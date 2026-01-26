package gcloudiam

import (
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

// PrivescPermissions contains all permissions relevant for privilege escalation analysis
var PrivescPermissions = map[gcptypes.Permission]bool{
	// resourcemanager - IAM policy modifications
	"resourcemanager.organizations.setIamPolicy": true,
	"resourcemanager.folders.setIamPolicy":       true,
	"resourcemanager.projects.setIamPolicy":      true,

	// iam - Service account impersonation and role manipulation
	"iam.serviceAccounts.setIamPolicy":       true,
	"iam.roles.update":                       true,
	"iam.serviceAccountKeys.create":          true,
	"iam.serviceAccounts.getAccessToken":     true,
	"iam.serviceAccounts.signBlob":           true,
	"iam.serviceAccounts.signJwt":            true,
	"iam.serviceAccounts.implicitDelegation": true,
	"iam.serviceAccounts.actAs":              true,

	// deploymentmanager - SA attachment to deployments
	"deploymentmanager.deployments.create":       true,
	"deploymentmanager.deployments.update":       true,
	"deploymentmanager.deployments.setIamPolicy": true,

	// cloudbuild - SA attachment to builds
	"cloudbuild.builds.create": true,
	"cloudbuild.builds.update": true,

	// cloudfunctions - Function manipulation and invocation
	"cloudfunctions.functions.create":        true,
	"cloudfunctions.functions.sourceCodeSet": true,
	"cloudfunctions.functions.update":        true,
	"cloudfunctions.functions.call":          true,
	"cloudfunctions.functions.setIamPolicy":  true,

	// compute - VM and metadata manipulation and SSH access
	"compute.projects.setCommonInstanceMetadata": true,
	"compute.instances.create":                   true,
	"compute.instances.setMetadata":              true,
	"compute.instances.setServiceAccount":        true,
	"compute.instances.setIamPolicy":             true,
	"compute.instances.osLogin":                  true,
	"compute.instances.osAdminLogin":             true,
	"compute.disks.create":                       true,
	"compute.subnetworks.use":                    true,
	"compute.subnetworks.useExternalIp":          true,

	// composer - Airflow environment SA attachment
	"composer.environments.create": true,

	// container (GKE) - Pod creation and execution
	"container.cronJobs.create":               true,
	"container.cronJobs.update":               true,
	"container.daemonSets.create":             true,
	"container.daemonSets.update":             true,
	"container.deployments.create":            true,
	"container.deployments.update":            true,
	"container.jobs.create":                   true,
	"container.jobs.update":                   true,
	"container.pods.create":                   true,
	"container.pods.update":                   true,
	"container.pods.exec":                     true,
	"container.replicaSets.create":            true,
	"container.replicaSets.update":            true,
	"container.replicationControllers.create": true,
	"container.replicationControllers.update": true,
	"container.scheduledJobs.create":          true,
	"container.scheduledJobs.update":          true,
	"container.statefulSets.create":           true,
	"container.statefulSets.update":           true,

	// container (GKE) - K8s privilege escalation
	"container.roles.escalate":              true,
	"container.roles.create":                true,
	"container.roles.update":                true,
	"container.roles.bind":                  true,
	"container.roleBindings.create":         true,
	"container.roleBindings.update":         true,
	"container.clusterRoles.escalate":       true,
	"container.clusterRoles.create":         true,
	"container.clusterRoles.update":         true,
	"container.clusterRoles.bind":           true,
	"container.clusterRoleBindings.create":  true,
	"container.clusterRoleBindings.update":  true,
	"container.secrets.get":                 true,
	"container.secrets.list":                true,
	"container.serviceAccounts.createToken": true,
	"container.pods.portForward":            true,

	// container (GKE) - Cluster access
	"container.clusters.get":                         true,
	"container.clusters.getCredentials":              true,
	"container.mutatingWebhookConfigurations.create": true,
	"container.mutatingWebhookConfigurations.update": true,

	// storage - Airflow DAG manipulation and image modification
	"storage.hmacKeys.create":      true,
	"storage.objects.create":       true,
	"storage.objects.setIamPolicy": true,
	"storage.objects.delete":       true,

	// secretmanager - Secret access
	"secretmanager.secrets.get":          true,
	"secretmanager.secrets.setIamPolicy": true,

	// orgpolicy - Protection disablement
	"orgpolicy.policy.set": true,

	// run - Cloud Run service manipulation
	"run.services.create":       true,
	"run.services.setIamPolicy": true,
	"run.routes.invoke":         true,

	// cloudscheduler - Scheduled jobs for HTTP requests
	"cloudscheduler.jobs.create":    true,
	"cloudscheduler.locations.list": true,

	// serviceusage - API key management
	"serviceusage.apiKeys.create": true,
	"serviceusage.apiKeys.list":   true,

	// apikeys - API key management
	"apikeys.keys.create":       true,
	"apikeys.keys.getKeyString": true,
	"apikeys.keys.list":         true,
	"apikeys.keys.regenerate":   true,
}

// IsPrivescPermission checks if a permission is relevant for privilege escalation
func IsPrivescPermission(perm gcptypes.Permission) bool {
	return PrivescPermissions[perm]
}
