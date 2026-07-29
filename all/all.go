// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

// Package all provides a convenience function to register all built-in detectors.
package all

import (
	"github.com/bag/security-go"
	"github.com/bag/security-go/data"
	"github.com/bag/security-go/file"
	"github.com/bag/security-go/injection"
	"github.com/bag/security-go/protocol"
)

// RegisterAll registers all built-in detectors that do not require
// external configuration (injection, protocol, data, file).
// HTTP validation detectors (httpval) must be registered individually
// as they require application-specific settings.
func RegisterAll(e *security.Engine) {
	e.Register(&injection.XSS{})
	e.Register(&injection.SQL{})
	e.Register(&injection.Command{})
	e.Register(&injection.NoSQL{})
	e.Register(&injection.LDAP{})
	e.Register(&injection.XPath{})
	e.Register(&injection.JNDI{})
	e.Register(&injection.SSI{})
	e.Register(&injection.GraphQL{})
	e.Register(&injection.SSTI{})
	e.Register(&protocol.SSRF{})
	e.Register(&protocol.XXE{})
	e.Register(&protocol.HeaderInjection{})
	e.Register(&protocol.HostHeader{})
	e.Register(&protocol.RequestSmuggling{})
	e.Register(&protocol.OpenRedirect{})
	e.Register(&protocol.CORS{})
	e.Register(&protocol.WebSocket{})
	e.Register(&protocol.DNSRebinding{})
	e.Register(&data.Deserialization{})
	e.Register(&data.CSVInjection{})
	e.Register(&data.MailHeader{})
	e.Register(&data.JWTAttack{})
	e.Register(&data.PrototypePollution{})
	e.Register(&file.PathTraversal{})
	e.Register(&file.MaliciousFileUpload{})
	e.Register(&file.SensitiveDataLeak{})
}
