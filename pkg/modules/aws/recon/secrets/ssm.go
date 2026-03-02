package secrets

// SSM Documents are handled by extractProperties() in extract.go.
// Cloud Control returns the document content inline — no additional API calls needed.
//
// The dispatcher in extract.go routes "AWS::SSM::Document" to:
//
//	extractProperties(r, out, "Document")
