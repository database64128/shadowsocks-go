package v1

import (
	"errors"

	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/gofiber/fiber/v2"
)

// ServerInfo contains information about the API server.
type ServerInfo struct {
	Name       string `json:"server"`
	APIVersion string `json:"apiVersion"`
}

var serverInfo = ServerInfo{
	Name:       "shadowsocks-go",
	APIVersion: "v1",
}

// GetServerInfo returns information about the API server.
func GetServerInfo(c *fiber.Ctx) error {
	return c.JSON(&serverInfo)
}

type managedServer struct {
	cms *cred.ManagedServer
	sc  stats.Collector
}

// ServerManager handles server management API requests.
type ServerManager struct {
	managedServers     map[string]*managedServer
	managedServerNames []string
}

// NewServerManager returns a new server manager.
func NewServerManager() *ServerManager {
	return &ServerManager{
		managedServers: make(map[string]*managedServer),
	}
}

// AddServer adds a server to the server manager.
func (sm *ServerManager) AddServer(name string, cms *cred.ManagedServer, sc stats.Collector) {
	sm.managedServers[name] = &managedServer{
		cms: cms,
		sc:  sc,
	}
	sm.managedServerNames = append(sm.managedServerNames, name)
}

// Routes sets up routes for the /v1/servers endpoint.
func (sm *ServerManager) Routes(v1 fiber.Router) {
	v1.Get("/servers", sm.ListServers)

	server := v1.Group("/servers/:server", sm.ContextManagedServer)
	server.Get("", GetServerInfo)
	server.Get("/stats", sm.GetStats)

	users := server.Group("/users", sm.CheckMultiUserSupport)
	users.Get("", sm.ListUsers)
	users.Post("", sm.AddUser)
	users.Get("/:username", sm.GetUser)
	users.Patch("/:username", sm.UpdateUser)
	users.Delete("/:username", sm.DeleteUser)
}

// ListServers lists all managed servers.
func (sm *ServerManager) ListServers(c *fiber.Ctx) error {
	return c.JSON(&sm.managedServerNames)
}

// ContextManagedServer is a middleware for the servers group.
// It adds the server with the given name to the request context.
func (sm *ServerManager) ContextManagedServer(c *fiber.Ctx) error {
	name := c.Params("server")
	ms := sm.managedServers[name]
	if ms == nil {
		return c.Status(fiber.StatusNotFound).JSON(&StandardError{Message: "server not found"})
	}
	c.Locals(0, ms)
	return c.Next()
}

// managedServerFromContext returns the managed server from the request context.
func managedServerFromContext(c *fiber.Ctx) *managedServer {
	return c.Locals(0).(*managedServer)
}

// GetStats returns server traffic statistics.
func (sm *ServerManager) GetStats(c *fiber.Ctx) error {
	ms := managedServerFromContext(c)
	if c.QueryBool("clear", false) {
		return c.JSON(ms.sc.SnapshotAndReset())
	}
	return c.JSON(ms.sc.Snapshot())
}

// CheckMultiUserSupport is a middleware for the users group.
// It checks whether the selected server supports user management.
func (sm *ServerManager) CheckMultiUserSupport(c *fiber.Ctx) error {
	ms := managedServerFromContext(c)
	if ms.cms == nil {
		return c.Status(fiber.StatusNotFound).JSON(&StandardError{Message: "The server does not support user management."})
	}
	return c.Next()
}

// UserList contains a list of user credentials.
type UserList struct {
	Users []cred.UserCredential `json:"users"`
}

// ListUsers lists server users.
func (sm *ServerManager) ListUsers(c *fiber.Ctx) error {
	ms := managedServerFromContext(c)
	return c.JSON(&UserList{Users: ms.cms.Credentials()})
}

// AddUser adds a new user credential to the server.
func (sm *ServerManager) AddUser(c *fiber.Ctx) error {
	var uc cred.UserCredential
	if err := c.BodyParser(&uc); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&StandardError{Message: err.Error()})
	}

	ms := managedServerFromContext(c)
	if err := ms.cms.AddCredential(uc.Name, uc.UPSK); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&StandardError{Message: err.Error()})
	}
	return c.JSON(&uc)
}

// UserInfo contains information about a user.
type UserInfo struct {
	cred.UserCredential
	stats.Traffic
}

// GetUser returns information about a user.
func (sm *ServerManager) GetUser(c *fiber.Ctx) error {
	ms := managedServerFromContext(c)
	username := c.Params("username")
	uc, ok := ms.cms.GetCredential(username)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(&StandardError{Message: "user not found"})
	}
	return c.JSON(&UserInfo{uc, ms.sc.Snapshot().Traffic})
}

// UpdateUser updates a user's credential.
func (sm *ServerManager) UpdateUser(c *fiber.Ctx) error {
	var update struct {
		UPSK []byte `json:"uPSK"`
	}
	if err := c.BodyParser(&update); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&StandardError{Message: err.Error()})
	}

	ms := managedServerFromContext(c)
	username := c.Params("username")
	if err := ms.cms.UpdateCredential(username, update.UPSK); err != nil {
		if errors.Is(err, cred.ErrNonexistentUser) {
			return c.Status(fiber.StatusNotFound).JSON(&StandardError{Message: err.Error()})
		}
		return c.Status(fiber.StatusBadRequest).JSON(&StandardError{Message: err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteUser deletes a user's credential.
func (sm *ServerManager) DeleteUser(c *fiber.Ctx) error {
	ms := managedServerFromContext(c)
	username := c.Params("username")
	if err := ms.cms.DeleteCredential(username); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(&StandardError{Message: err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
