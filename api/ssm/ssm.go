// Package ssm implements the Shadowsocks Server Management API v1.
package ssm

import (
	"errors"
	"net/http"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/api/internal/restapi"
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/stats"
)

// StandardError is the standard error response.
type StandardError struct {
	Message string `json:"error"`
}

// Server represents a server managed by the API.
type Server struct {
	// CredentialManager manages user credentials for the server.
	// It is nil if the server does not support user management.
	CredentialManager *cred.ManagedServer

	// StatsCollector provides access to server traffic statistics.
	// It MUST NOT be nil.
	StatsCollector stats.Collector
}

// ServerManager handles server management API requests.
type ServerManager struct {
	serverByName map[string]Server
	serverNames  []string
}

// NewServerManager returns a new server manager.
func NewServerManager(serverByName map[string]Server, serverNames []string) *ServerManager {
	return &ServerManager{
		serverByName: serverByName,
		serverNames:  serverNames,
	}
}

// RegisterHandlers sets up handlers for the /servers endpoint.
func (sm *ServerManager) RegisterHandlers(register func(method string, path string, handler restapi.HandlerFunc)) {
	register(http.MethodGet, "/servers", sm.handleListServers)

	register(http.MethodGet, "/servers/{server}", sm.requireServerStats(handleGetServerInfo))
	register(http.MethodGet, "/servers/{server}/stats", sm.requireServerStats(handleGetStats))

	register(http.MethodGet, "/servers/{server}/users", sm.requireServerUsers(handleListUsers))
	register(http.MethodPost, "/servers/{server}/users", sm.requireServerUsers(handleAddUser))
	register(http.MethodGet, "/servers/{server}/users/{username}", sm.requireServerUsers(handleGetUser))
	register(http.MethodPatch, "/servers/{server}/users/{username}", sm.requireServerUsers(handleUpdateUser))
	register(http.MethodDelete, "/servers/{server}/users/{username}", sm.requireServerUsers(handleDeleteUser))

	register(http.MethodPost, "/servers/{server}/reload-users", sm.requireServerUsers(handleReloadUsers))
}

func (sm *ServerManager) handleListServers(w http.ResponseWriter, _ *http.Request) (int, error) {
	return restapi.EncodeResponse(w, http.StatusOK, &sm.serverNames)
}

func (sm *ServerManager) requireServerStats(h func(http.ResponseWriter, *http.Request, stats.Collector) (int, error)) restapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) (int, error) {
		name := r.PathValue("server")
		server, ok := sm.serverByName[name]
		if !ok {
			return restapi.EncodeResponse(w, http.StatusNotFound, &serverNotFoundJSON)
		}
		return h(w, r, server.StatsCollector)
	}
}

var (
	serverInfoJSON                = []byte(`{"server":"shadowsocks-go ` + shadowsocks.Version + `","apiVersion":"v1"}`)
	serverNotFoundJSON            = []byte(`{"error":"server not found"}`)
	serverNoCredentialManagerJSON = []byte(`{"error":"The server does not support user management."}`)
	userNotFoundJSON              = []byte(`{"error":"user not found"}`)
)

func handleGetServerInfo(w http.ResponseWriter, _ *http.Request, _ stats.Collector) (int, error) {
	return restapi.EncodeResponse(w, http.StatusOK, &serverInfoJSON)
}

func handleGetStats(w http.ResponseWriter, r *http.Request, sc stats.Collector) (int, error) {
	var serverStats stats.Server
	if v := r.URL.Query()["clear"]; len(v) == 1 && (v[0] == "" || v[0] == "true") {
		serverStats = sc.SnapshotAndReset()
	} else {
		serverStats = sc.Snapshot()
	}
	return restapi.EncodeResponse(w, http.StatusOK, serverStats)
}

func (sm *ServerManager) requireServerUsers(h func(http.ResponseWriter, *http.Request, Server) (int, error)) func(http.ResponseWriter, *http.Request) (int, error) {
	return func(w http.ResponseWriter, r *http.Request) (int, error) {
		name := r.PathValue("server")
		server, ok := sm.serverByName[name]
		if !ok {
			return restapi.EncodeResponse(w, http.StatusNotFound, &serverNotFoundJSON)
		}
		if server.CredentialManager == nil {
			return restapi.EncodeResponse(w, http.StatusNotFound, &serverNoCredentialManagerJSON)
		}
		return h(w, r, server)
	}
}

func handleListUsers(w http.ResponseWriter, _ *http.Request, s Server) (int, error) {
	type response struct {
		Users []cred.UserCredential `json:"users"`
	}
	return restapi.EncodeResponse(w, http.StatusOK, response{Users: s.CredentialManager.Credentials()})
}

func handleAddUser(w http.ResponseWriter, r *http.Request, s Server) (int, error) {
	var uc cred.UserCredential
	if err := restapi.DecodeRequest(r, &uc); err != nil {
		return restapi.EncodeResponse(w, http.StatusBadRequest, StandardError{Message: err.Error()})
	}

	if err := s.CredentialManager.AddCredential(uc.Name, uc.UPSK); err != nil {
		return restapi.EncodeResponse(w, http.StatusBadRequest, StandardError{Message: err.Error()})
	}

	return restapi.EncodeResponse(w, http.StatusCreated, &uc)
}

func handleGetUser(w http.ResponseWriter, r *http.Request, s Server) (int, error) {
	type response struct {
		cred.UserCredential
		stats.Traffic
	}

	username := r.PathValue("username")
	userCred, ok := s.CredentialManager.GetCredential(username)
	if !ok {
		return restapi.EncodeResponse(w, http.StatusNotFound, &userNotFoundJSON)
	}

	return restapi.EncodeResponse(w, http.StatusOK, response{userCred, s.StatsCollector.Snapshot().Traffic})
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request, s Server) (int, error) {
	var update struct {
		UPSK []byte `json:"uPSK"`
	}
	if err := restapi.DecodeRequest(r, &update); err != nil {
		return restapi.EncodeResponse(w, http.StatusBadRequest, StandardError{Message: err.Error()})
	}

	username := r.PathValue("username")
	if err := s.CredentialManager.UpdateCredential(username, update.UPSK); err != nil {
		if errors.Is(err, cred.ErrNonexistentUser) {
			return restapi.EncodeResponse(w, http.StatusNotFound, StandardError{Message: err.Error()})
		}
		return restapi.EncodeResponse(w, http.StatusBadRequest, StandardError{Message: err.Error()})
	}

	return restapi.EncodeResponse(w, http.StatusNoContent, nil)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request, s Server) (int, error) {
	username := r.PathValue("username")
	if err := s.CredentialManager.DeleteCredential(username); err != nil {
		return restapi.EncodeResponse(w, http.StatusNotFound, StandardError{Message: err.Error()})
	}
	return restapi.EncodeResponse(w, http.StatusNoContent, nil)
}

func handleReloadUsers(w http.ResponseWriter, _ *http.Request, s Server) (int, error) {
	if err := s.CredentialManager.LoadFromFile(); err != nil {
		return restapi.EncodeResponse(w, http.StatusInternalServerError, StandardError{Message: err.Error()})
	}
	return restapi.EncodeResponse(w, http.StatusNoContent, nil)
}
