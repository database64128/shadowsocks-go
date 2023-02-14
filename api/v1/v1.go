package v1

import "github.com/gofiber/fiber/v2"

func Routes(router fiber.Router) *ServerManager {
	v1 := router.Group("/v1")
	sm := NewServerManager()
	sm.Routes(v1)
	return sm
}
