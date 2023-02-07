package cred

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap"
)

type managedServer struct {
	pskLength     int
	tcp           *ss2022.CredStore
	udp           *ss2022.CredStore
	path          string
	cachedContent string
	cachedReader  *strings.Reader
	cachedCreds   map[string][]byte
}

func (s *managedServer) loadFromFile() error {
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
	if err = d.Decode(&s.cachedCreds); err != nil {
		return err
	}

	uPSKMap, err := ss2022.NewUPSKMap(s.pskLength, s.cachedCreds, s.udp != nil)
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
	servers map[string]*managedServer
}

// NewManager returns a new credential manager.
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		logger:  logger,
		servers: make(map[string]*managedServer),
	}
}

// ReloadAll asks all managed servers to reload credentials from files.
func (m *Manager) ReloadAll() {
	for name, s := range m.servers {
		if err := s.loadFromFile(); err != nil {
			m.logger.Warn("Failed to reload credentials", zap.String("server", name), zap.Error(err))
			continue
		}
		m.logger.Info("Reloaded credentials", zap.String("server", name))
	}
}

// Start loads credentials for all managed servers and registers to reload on SIGUSR1.
func (m *Manager) Start() error {
	for name, s := range m.servers {
		if err := s.loadFromFile(); err != nil {
			return err
		}
		m.logger.Debug("Loaded credentials", zap.String("server", name))
	}
	m.registerSIGUSR1()
	return nil
}

// RegisterServer registers a server to the manager.
func (m *Manager) RegisterServer(name string, pskLength int, path string) error {
	if s := m.servers[name]; s != nil {
		return fmt.Errorf("server already registered: %s", name)
	}
	m.servers[name] = &managedServer{
		pskLength:    pskLength,
		path:         path,
		cachedReader: strings.NewReader(""),
	}
	m.logger.Debug("Registered server", zap.String("server", name))
	return nil
}

// AddTCPCredStore adds a TCP credential store to the given server.
func (m *Manager) AddTCPCredStore(name string, store *ss2022.CredStore) error {
	s, ok := m.servers[name]
	if !ok {
		return fmt.Errorf("server not registered: %s", name)
	}
	s.tcp = store
	return nil
}

// AddUDPCredStore adds a UDP credential store to the given server.
func (m *Manager) AddUDPCredStore(name string, store *ss2022.CredStore) error {
	s, ok := m.servers[name]
	if !ok {
		return fmt.Errorf("server not registered: %s", name)
	}
	s.udp = store
	return nil
}
