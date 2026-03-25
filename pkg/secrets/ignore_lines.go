package secrets

var aurelianIgnoreExtraLines = []string{
	// Node.js vendored dependencies in Lambda ZIPs
	"**/node_modules/**",

	// Python vendored test fixtures in Lambda ZIPs
	"**/Crypto/SelfTest/**",
	"**/Cryptodome/SelfTest/**",
	"**/__pycache__/**",
}
