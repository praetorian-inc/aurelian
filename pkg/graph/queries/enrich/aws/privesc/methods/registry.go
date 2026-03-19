package methods

import "github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"

// AWSPrivesc defines the minimal contract for read-only privilege escalation queries.
type AWSPrivesc interface {
	ID() string
	Name() string
	Description() string
	Severity() string
	Query() dsl.Query
}

var AllPrivescQueries = []AWSPrivesc{
	NewMethod01IAMCreatePolicyVersion(),
	NewMethod02IAMSetDefaultPolicyVersion(),
	NewMethod03IAMCreateAccessKey(),
}
