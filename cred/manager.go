package cred

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap"
)

var (
	ErrEmptyUsername   = errors.New("empty username")
	ErrNonexistentUser = errors.New("nonexistent user")
)

// ManagedServer stores information about a server whose credentials are managed by the credential manager.
type ManagedServer struct {
	pskLength           int
	tcp                 *ss2022.CredStore
	udp                 *ss2022.CredStore
	path                string
	cachedContent       string
	cachedCredMap       map[string]*cachedUserCredential
	cachedUserLookupMap ss2022.UserLookupMap
	mu                  sync.RWMutex
	wg                  sync.WaitGroup
	saveQueue           chan struct{}
	logger              *zap.Logger
}

// UserCredential stores a user's credential.
type UserCredential struct {
	Name string `json:"username"`
	UPSK []byte `json:"uPSK"`
}

// Compare is useful for sorting user credentials by username.
func (uc UserCredential) Compare(other UserCredential) int {
	return cmp.Compare(uc.Name, other.Name)
}

type cachedUserCredential struct {
	uPSK     []byte
	uPSKHash [ss2022.IdentityHeaderLength]byte
}

// Credentials returns the server credentials.
func (s *ManagedServer) Credentials() []UserCredential {
	s.mu.RLock()
	ucs := make([]UserCredential, 0, len(s.cachedCredMap))
	for username, cachedCred := range s.cachedCredMap {
		ucs = append(ucs, UserCredential{
			Name: username,
			UPSK: cachedCred.uPSK,
		})
	}
	s.mu.RUnlock()
	slices.SortFunc(ucs, UserCredential.Compare)
	return ucs
}

// GetCredential returns the user credential.
func (s *ManagedServer) GetCredential(username string) (UserCredential, bool) {
	s.mu.RLock()
	cachedCred := s.cachedCredMap[username]
	s.mu.RUnlock()
	if cachedCred == nil {
		return UserCredential{}, false
	}
	return UserCredential{
		Name: username,
		UPSK: cachedCred.uPSK,
	}, true
}

func (s *ManagedServer) saveToFile() error {
	uPSKMap := make(map[string][]byte, len(s.cachedCredMap))
	for username, uc := range s.cachedCredMap {
		uPSKMap[username] = uc.uPSK
	}

	b, err := json.MarshalIndent(uPSKMap, "", "    ")
	if err != nil {
		return err
	}
	b = append(b, '\n') // b has plenty of unused capacity.

	if err = os.WriteFile(s.path, b, 0644); err != nil {
		return err
	}

	s.cachedContent = unsafe.String(unsafe.SliceData(b), len(b))
	return nil
}

func (s *ManagedServer) dequeueSave(ctx context.Context) {
	for {
		// Wait for incoming save job.
		select {
		case <-s.saveQueue:
		case <-ctx.Done():
			return
		}

		// Wait for cooldown.
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}

		// Clear save queue after cooldown.
		select {
		case <-s.saveQueue:
		default:
		}

		// The save operation only reads cachedCredMap and writes cachedContent.
		// It is without doubt that taking the read lock is enough for cachedCredMap.
		// As for cachedContent, the only other place that reads and writes it is LoadFromFile,
		// which takes the write lock. So it is safe to take just the read lock here.
		s.mu.RLock()
		if err := s.saveToFile(); err != nil {
			s.logger.Warn("Failed to save credentials", zap.Error(err))
		}
		s.mu.RUnlock()
	}
}

// Start starts the managed server.
func (s *ManagedServer) Start(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		s.dequeueSave(ctx)
		s.wg.Done()
	}()
}

// Stop stops the managed server.
func (s *ManagedServer) Stop() {
	s.wg.Wait()
}

func (s *ManagedServer) enqueueSave() {
	select {
	case s.saveQueue <- struct{}{}:
	default:
	}
}

func (s *ManagedServer) updateProdULM(f func(ss2022.UserLookupMap)) {
	if s.tcp != nil {
		s.tcp.UpdateUserLookupMap(f)
	}
	if s.udp != nil {
		s.udp.UpdateUserLookupMap(f)
	}
}

// AddCredential adds a user credential.
func (s *ManagedServer) AddCredential(username string, uPSK []byte) error {
	if username == "" {
		return ErrEmptyUsername
	}
	if len(uPSK) != s.pskLength {
		return &ss2022.PSKLengthError{PSK: uPSK, ExpectedLength: s.pskLength}
	}
	s.mu.Lock()
	if s.cachedCredMap[username] != nil {
		s.mu.Unlock()
		return fmt.Errorf("user %s already exists", username)
	}
	c, err := ss2022.NewServerUserCipherConfig(username, uPSK, s.udp != nil)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	uc := &cachedUserCredential{
		uPSK:     uPSK,
		uPSKHash: ss2022.PSKHash(uPSK),
	}
	s.cachedCredMap[username] = uc
	s.cachedUserLookupMap[uc.uPSKHash] = c
	s.mu.Unlock()
	s.enqueueSave()
	s.updateProdULM(func(ulm ss2022.UserLookupMap) {
		ulm[uc.uPSKHash] = c
	})
	return nil
}

// UpdateCredential updates a user credential.
func (s *ManagedServer) UpdateCredential(username string, uPSK []byte) error {
	if len(uPSK) != s.pskLength {
		return &ss2022.PSKLengthError{PSK: uPSK, ExpectedLength: s.pskLength}
	}
	s.mu.Lock()
	uc := s.cachedCredMap[username]
	if uc == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNonexistentUser, username)
	}
	if bytes.Equal(uc.uPSK, uPSK) {
		s.mu.Unlock()
		return fmt.Errorf("user %s already has the same uPSK", username)
	}
	c, err := ss2022.NewServerUserCipherConfig(username, uPSK, s.udp != nil)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	oldUPSKHash := uc.uPSKHash
	uc.uPSK = uPSK
	uc.uPSKHash = ss2022.PSKHash(uPSK)
	delete(s.cachedUserLookupMap, oldUPSKHash)
	s.cachedUserLookupMap[uc.uPSKHash] = c
	s.mu.Unlock()
	s.enqueueSave()
	s.updateProdULM(func(ulm ss2022.UserLookupMap) {
		delete(ulm, oldUPSKHash)
		ulm[uc.uPSKHash] = c
	})
	return nil
}

// DeleteCredential deletes a user credential.
func (s *ManagedServer) DeleteCredential(username string) error {
	s.mu.Lock()
	uc := s.cachedCredMap[username]
	if uc == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNonexistentUser, username)
	}
	delete(s.cachedCredMap, username)
	delete(s.cachedUserLookupMap, uc.uPSKHash)
	s.mu.Unlock()
	s.enqueueSave()
	s.updateProdULM(func(ulm ss2022.UserLookupMap) {
		delete(ulm, uc.uPSKHash)
	})
	return nil
}

// LoadFromFile loads credentials from the configured credential file
// and applies the changes to the associated credential stores.
func (s *ManagedServer) LoadFromFile() error {
	content, close, err := mmap.ReadFile[string](s.path)
	if err != nil {
		return err
	}
	defer close()

	s.mu.Lock()
	// Skip if the file content is unchanged.
	if content == s.cachedContent {
		s.mu.Unlock()
		return nil
	}

	r := strings.NewReader(content)
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	var uPSKMap map[string][]byte
	if err = d.Decode(&uPSKMap); err != nil {
		s.mu.Unlock()
		return err
	}

	userLookupMap := make(ss2022.UserLookupMap, len(uPSKMap))
	credMap := make(map[string]*cachedUserCredential, len(uPSKMap))
	for username, uPSK := range uPSKMap {
		if len(uPSK) != s.pskLength {
			s.mu.Unlock()
			return &ss2022.PSKLengthError{PSK: uPSK, ExpectedLength: s.pskLength}
		}

		uPSKHash := ss2022.PSKHash(uPSK)
		c, ok := userLookupMap[uPSKHash]
		if ok {
			s.mu.Unlock()
			return fmt.Errorf("duplicate uPSK for user %s and %s", c.Name, username)
		}
		c, err := ss2022.NewServerUserCipherConfig(username, uPSK, s.udp != nil)
		if err != nil {
			s.mu.Unlock()
			return err
		}

		userLookupMap[uPSKHash] = c
		credMap[username] = &cachedUserCredential{uPSK, uPSKHash}
	}

	s.cachedContent = strings.Clone(content)
	s.cachedUserLookupMap = userLookupMap
	s.cachedCredMap = credMap
	s.mu.Unlock()

	if s.tcp != nil {
		s.tcp.ReplaceUserLookupMap(maps.Clone(s.cachedUserLookupMap))
	}
	if s.udp != nil {
		s.udp.ReplaceUserLookupMap(maps.Clone(s.cachedUserLookupMap))
	}

	return nil
}

// Manager manages credentials for servers of supported protocols.
type Manager struct {
	logger  *zap.Logger
	servers map[string]*ManagedServer
}

// NewManager returns a new credential manager.
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		logger:  logger,
		servers: make(map[string]*ManagedServer),
	}
}

// ReloadAll asks all managed servers to reload credentials from files.
func (m *Manager) ReloadAll() {
	for name, s := range m.servers {
		if err := s.LoadFromFile(); err != nil {
			m.logger.Warn("Failed to reload credentials", zap.String("server", name), zap.Error(err))
			continue
		}
		m.logger.Info("Reloaded credentials", zap.String("server", name))
	}
}

// LoadAll loads credentials for all managed servers.
func (m *Manager) LoadAll() error {
	for name, s := range m.servers {
		if err := s.LoadFromFile(); err != nil {
			return fmt.Errorf("failed to load credentials for server %s: %w", name, err)
		}
		m.logger.Debug("Loaded credentials", zap.String("server", name))
	}
	return nil
}

var _ shadowsocks.Service = (*Manager)(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (*Manager) ZapField() zap.Field {
	return zap.String("service", "credential manager")
}

// Start starts all managed servers and registers to reload on SIGUSR1.
//
// Start implements [shadowsocks.Service.Start].
func (m *Manager) Start(ctx context.Context) error {
	for _, s := range m.servers {
		s.Start(ctx)
	}
	m.registerSIGUSR1()
	return nil
}

// Stop gracefully stops all managed servers.
//
// Stop implements [shadowsocks.Service.Stop].
func (m *Manager) Stop() error {
	for _, s := range m.servers {
		s.Stop()
	}
	return nil
}

// RegisterServer registers a server to the manager.
func (m *Manager) RegisterServer(name, path string, pskLength int, tcpCredStore, udpCredStore *ss2022.CredStore) (*ManagedServer, error) {
	s := m.servers[name]
	if s != nil {
		return nil, fmt.Errorf("server already registered: %s", name)
	}
	s = &ManagedServer{
		pskLength: pskLength,
		tcp:       tcpCredStore,
		udp:       udpCredStore,
		path:      path,
		saveQueue: make(chan struct{}, 1),
		logger:    m.logger,
	}
	if err := s.LoadFromFile(); err != nil {
		return nil, fmt.Errorf("failed to load credentials for server %s: %w", name, err)
	}
	m.servers[name] = s
	m.logger.Debug("Registered server", zap.String("server", name))
	return s, nil
}
