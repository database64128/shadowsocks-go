//go:build !unix

package cred

func (m *Manager) registerSIGUSR1() {}
