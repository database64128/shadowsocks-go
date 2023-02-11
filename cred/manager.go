package cred

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/database64128/shadowsocks-go/maps"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap"
)

// ManagedServer stores information about a server whose credentials are managed by the credential manager.
type ManagedServer struct {
	pskLength     int
	tcp           *ss2022.CredStore
	udp           *ss2022.CredStore
	path          string
	cachedContent string
	cachedReader  *strings.Reader
	cachedCreds   map[string][]byte
	mu            sync.RWMutex
}

// SetTCPCredStore sets the TCP credential store.
func (s *ManagedServer) SetTCPCredStore(tcp *ss2022.CredStore) {
	s.tcp = tcp
}

// SetUDPCredStore sets the UDP credential store.
func (s *ManagedServer) SetUDPCredStore(udp *ss2022.CredStore) {
	s.udp = udp
}

// UserCredential stores a user's credential.
type UserCredential struct {
	Name string `json:"username"`
	UPSK []byte `json:"uPSK"`
}

// Credentials returns the server credentials.
func (s *ManagedServer) Credentials() []UserCredential {
	s.mu.RLock()
	ucs := make([]UserCredential, 0, len(s.cachedCreds))
	for username, uPSK := range s.cachedCreds {
		ucs = append(ucs, UserCredential{
			Name: username,
			UPSK: uPSK,
		})
	}
	s.mu.RUnlock()
	return ucs
}

// LoadFromFile loads credentials from the configured credential file.
func (s *ManagedServer) LoadFromFile() error {
	content, err := mmap.ReadFile[string](s.path)
	if err != nil {
		return err
	}
	defer mmap.Unmap(content)

	// Skip if the file content is unchanged.
	if content == s.cachedContent {
		return nil
	}

	s.cachedContent = strings.Clone(content)
	s.cachedReader.Reset(s.cachedContent)
	d := json.NewDecoder(s.cachedReader)
	d.DisallowUnknownFields()
	s.mu.Lock()
	maps.Clear(s.cachedCreds)
	if err = d.Decode(&s.cachedCreds); err != nil {
		return err
	}

	uPSKMap, err := ss2022.NewUPSKMap(s.pskLength, s.cachedCreds, s.udp != nil)
	s.mu.Unlock()
	if err != nil {
		return err
	}

	if s.tcp != nil {
		s.tcp.ReplaceUPSKMap(uPSKMap)
	}
	if s.udp != nil {
		s.udp.ReplaceUPSKMap(uPSKMap)
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

// Start loads credentials for all managed servers and registers to reload on SIGUSR1.
func (m *Manager) Start() error {
	for name, s := range m.servers {
		if err := s.LoadFromFile(); err != nil {
			return err
		}
		m.logger.Debug("Loaded credentials", zap.String("server", name))
	}
	m.registerSIGUSR1()
	return nil
}

// RegisterServer registers a server to the manager.
func (m *Manager) RegisterServer(name string, pskLength int, path string) (*ManagedServer, error) {
	s := m.servers[name]
	if s != nil {
		return nil, fmt.Errorf("server already registered: %s", name)
	}
	s = &ManagedServer{
		pskLength:    pskLength,
		path:         path,
		cachedReader: strings.NewReader(""),
	}
	m.servers[name] = s
	m.logger.Debug("Registered server", zap.String("server", name))
	return s, nil
}
