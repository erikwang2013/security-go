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
	e.Register(&protocol.SSRFDetector{})
	e.Register(&protocol.XXEDetector{})
	e.Register(&protocol.HeaderInjectionDetector{})
	e.Register(&protocol.HostHeaderDetector{})
	e.Register(&protocol.RequestSmugglingDetector{})
	e.Register(&protocol.OpenRedirectDetector{})
	e.Register(&protocol.CORSDetector{})
	e.Register(&protocol.WebSocketDetector{})
	e.Register(&protocol.DNSRebindingDetector{})
	e.Register(&data.DeserializationDetector{})
	e.Register(&data.CSVInjectionDetector{})
	e.Register(&data.MailHeaderDetector{})
	e.Register(&data.JWTAttackDetector{})
	e.Register(&data.PrototypePollutionDetector{})
	e.Register(&file.PathTraversal{})
	e.Register(&file.MaliciousFileUpload{})
	e.Register(&file.SensitiveDataLeak{})
}
