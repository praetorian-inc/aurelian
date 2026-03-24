package secrets

var aurelianIgnoreExtraLines = []string{
	// Node.js vendored dependencies in Lambda ZIPs
	"**/node_modules/@aws-sdk/**",
	"**/node_modules/aws-sdk/dist/**",
	"**/node_modules/aws-sdk/apis/**",
	"**/node_modules/aws-sdk/clients/**",
	"**/node_modules/**/test/**",
	"**/node_modules/**/tests/**",
	"**/node_modules/**/__tests__/**",
	"**/node_modules/**/README.md",
	"**/node_modules/**/README.markdown",

	// Python vendored test fixtures in Lambda ZIPs
	"**/Crypto/SelfTest/**",
	"**/Cryptodome/SelfTest/**",
	"**/__pycache__/**",
}
