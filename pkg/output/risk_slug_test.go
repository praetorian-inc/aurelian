package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResourceTypeSlug(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		want         string
	}{
		// AWS (CloudControl always uses PascalCase)
		{"aws lambda", "AWS::Lambda::Function", "lambda-function"},
		{"aws s3", "AWS::S3::Bucket", "s3-bucket"},
		{"aws ec2 instance", "AWS::EC2::Instance", "ec2-instance"},
		{"aws rds", "AWS::RDS::DBInstance", "rds-dbinstance"},
		{"aws redshift", "AWS::Redshift::Cluster", "redshift-cluster"},
		{"aws efs", "AWS::EFS::FileSystem", "efs-filesystem"},
		{"aws cognito", "AWS::Cognito::UserPool", "cognito-userpool"},
		{"aws sns", "AWS::SNS::Topic", "sns-topic"},
		{"aws sqs", "AWS::SQS::Queue", "sqs-queue"},
		{"aws ec2 image", "AWS::EC2::Image", "ec2-image"},

		// Azure — mixed case (unit test style)
		{"azure vm mixed case", "Microsoft.Compute/virtualMachines", "compute-virtualmachines"},
		{"azure storage mixed case", "Microsoft.Storage/storageAccounts", "storage-storageaccounts"},
		{"azure keyvault mixed case", "Microsoft.KeyVault/vaults", "keyvault-vaults"},
		{"azure cosmos mixed case", "Microsoft.DocumentDB/databaseAccounts", "documentdb-databaseaccounts"},
		{"azure aks mixed case", "Microsoft.ContainerService/managedClusters", "containerservice-managedclusters"},
		{"azure sql mixed case", "Microsoft.Sql/servers", "sql-servers"},
		{"azure acr mixed case", "Microsoft.ContainerRegistry/registries", "containerregistry-registries"},

		// Azure — lowercase (actual ARG output)
		{"azure vm lowercase", "microsoft.compute/virtualmachines", "compute-virtualmachines"},
		{"azure storage lowercase", "microsoft.storage/storageaccounts", "storage-storageaccounts"},
		{"azure keyvault lowercase", "microsoft.keyvault/vaults", "keyvault-vaults"},
		{"azure eventgrid lowercase", "microsoft.eventgrid/domains", "eventgrid-domains"},

		// GCP
		{"gcp compute instance", "compute.googleapis.com/Instance", "compute-instance"},
		{"gcp bucket", "storage.googleapis.com/Bucket", "storage-bucket"},
		{"gcp sql", "sqladmin.googleapis.com/Instance", "sqladmin-instance"},
		{"gcp function", "cloudfunctions.googleapis.com/Function", "cloudfunctions-function"},
		{"gcp cloud run", "run.googleapis.com/Service", "run-service"},
		{"gcp appengine", "appengine.googleapis.com/Service", "appengine-service"},
		{"gcp firebase", "firebasehosting.googleapis.com/Site", "firebasehosting-site"},
		{"gcp forwarding rule", "compute.googleapis.com/ForwardingRule", "compute-forwardingrule"},
		{"gcp global forwarding rule", "compute.googleapis.com/GlobalForwardingRule", "compute-globalforwardingrule"},
		{"gcp address", "compute.googleapis.com/Address", "compute-address"},

		// Edge cases
		{"empty string", "", ""},
		{"unrecognized format passthrough", "some-custom-type", "some-custom-type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ResourceTypeSlug(tt.resourceType))
		})
	}
}
