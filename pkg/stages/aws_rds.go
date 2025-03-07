package stages

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsRdsListDBSnapshots lists RDS DB snapshots
func AwsRdsListDBSnapshots(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListRDSDBSnapshots")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing RDS DB snapshots")
	profile := options.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logger.Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile, opts)

				rdsClient := rds.NewFromConfig(config)
				params := &rds.DescribeDBSnapshotsInput{
					IncludePublic: aws.Bool(true),
					SnapshotType:  aws.String("manual"),
				}

				for {
					res, err := rdsClient.DescribeDBSnapshots(ctx, params)
					if err != nil {
						logger.Error(err.Error())
						break
					}

					for _, snapshot := range res.DBSnapshots {
						properties, err := json.Marshal(snapshot)
						if err != nil {
							logger.Error("Could not marshal RDS DB snapshot description")
							continue
						}

						out <- types.EnrichedResourceDescription{
							Identifier: *snapshot.DBSnapshotIdentifier,
							TypeName:   rtype,
							Region:     region,
							Properties: string(properties),
							AccountId:  acctId,
						}
					}

					if res.Marker == nil {
						break
					}
					params.Marker = res.Marker
				}
			}(region, rtype)
		}
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// AwsRdsDbSnapshotDescribeAttributes checks the restore snapshot permissions of an RDS DB snapshot
func AwsRdsDbSnapshotDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "RDSDBSnapshotDescribeAttributes")
	logger.Info("Checking RDS DB snapshot restore snapshot permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			rdsClient := rds.NewFromConfig(config)

			loadPermissionInput := &rds.DescribeDBSnapshotAttributesInput{
				DBSnapshotIdentifier: aws.String(resource.Identifier),
			}
			permissionsOutput, err := rdsClient.DescribeDBSnapshotAttributes(ctx, loadPermissionInput)
			if err != nil {
				logger.Debug("Could not describe RDS DB snapshot restore snapshot permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				for _, attribute := range permissionsOutput.DBSnapshotAttributesResult.DBSnapshotAttributes {
					if *attribute.AttributeName == "restore" {
						restorePermissions, err := json.Marshal(attribute.AttributeValues)
						if err != nil {
							logger.Error("Could not marshal RDS DB snapshot restore snapshot permissions")
							continue
						}
						loadPermissionsString := "\"RestorePermissions\":[" + string(restorePermissions)

						lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
						newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "]}"

						out <- types.EnrichedResourceDescription{
							Identifier: resource.Identifier,
							TypeName:   resource.TypeName,
							Region:     resource.Region,
							Properties: newProperties,
							AccountId:  resource.AccountId,
						}
					}
				}
				out <- resource

			}
		}
		close(out)
	}()
	return out
}

// AwsRdsListDBClusterSnapshots lists RDS DB cluster snapshots
func AwsRdsListDbClusterSnapshots(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListRDSDBClusterSnapshots")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing RDS DB cluster snapshots")
	profile := options.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logger.Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile, opts)

				rdsClient := rds.NewFromConfig(config)
				params := &rds.DescribeDBClusterSnapshotsInput{
					IncludePublic: aws.Bool(true),
					SnapshotType:  aws.String("manual"),
				}

				for {
					res, err := rdsClient.DescribeDBClusterSnapshots(ctx, params)
					if err != nil {
						logger.Error(err.Error())
						break
					}

					for _, snapshot := range res.DBClusterSnapshots {
						properties, err := json.Marshal(snapshot)
						if err != nil {
							logger.Error("Could not marshal RDS DB snapshot description")
							continue
						}

						out <- types.EnrichedResourceDescription{
							Identifier: *snapshot.DBClusterIdentifier,
							TypeName:   rtype,
							Region:     region,
							Properties: string(properties),
							AccountId:  acctId,
						}
					}

					if res.Marker == nil {
						break
					}
					params.Marker = res.Marker
				}
			}(region, rtype)
		}
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// AwsRdsDbClusterSnapshotDescribeAttributes checks the restore snapshot permissions of an RDS DB cluster snapshot
func AwsRdsDbClusterSnapshotDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "RDSDBClusterSnapshotDescribeAttributes")
	logger.Info("Checking RDS DB cluster snapshot restore snapshot permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			rdsClient := rds.NewFromConfig(config)

			loadPermissionInput := &rds.DescribeDBClusterSnapshotAttributesInput{
				DBClusterSnapshotIdentifier: aws.String(resource.Identifier),
			}
			permissionsOutput, err := rdsClient.DescribeDBClusterSnapshotAttributes(ctx, loadPermissionInput)
			if err != nil {
				logger.Debug("Could not describe RDS DB cluster snapshot restore snapshot permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				for _, attribute := range permissionsOutput.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes {
					if *attribute.AttributeName == "restore" {
						restorePermissions, err := json.Marshal(attribute.AttributeValues)
						if err != nil {
							logger.Error("Could not marshal RDS DB cluster snapshot restore snapshot permissions")
							continue
						}
						loadPermissionsString := "\"RestorePermissions\":[" + string(restorePermissions)

						lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
						newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "]}"

						out <- types.EnrichedResourceDescription{
							Identifier: resource.Identifier,
							TypeName:   resource.TypeName,
							Region:     resource.Region,
							Properties: newProperties,
							AccountId:  resource.AccountId,
						}
					}
				}
				out <- resource

			}
		}
		close(out)
	}()
	return out
}
