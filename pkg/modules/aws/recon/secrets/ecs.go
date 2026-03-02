package secrets

// ECS Task Definitions are handled by extractProperties() in extract.go.
// Cloud Control returns all container definitions, environment variables,
// and other configuration inline — no additional API calls needed.
//
// The dispatcher in extract.go routes "AWS::ECS::TaskDefinition" to:
//
//	extractProperties(r, out, "TaskDefinition")
