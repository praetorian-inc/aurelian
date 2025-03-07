package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsEc2ListImages lists EC2 images in a given region.
func AwsEc2ListImages(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListEC2Images")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing EC2 AMIs")
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

				ec2Client := ec2.NewFromConfig(config)
				params := &ec2.DescribeImagesInput{
					Owners: []string{acctId},
				}

				for {
					res, err := ec2Client.DescribeImages(ctx, params)
					if err != nil {
						logger.Error(err.Error())
						break
					}

					for _, image := range res.Images {
						properties, err := json.Marshal(image)
						if err != nil {
							logger.Error("Could not marshal EC2 image description")
							continue
						}

						out <- types.EnrichedResourceDescription{
							Identifier: *image.ImageId,
							TypeName:   rtype,
							Region:     region,
							Properties: string(properties),
							AccountId:  acctId,
						}
					}

					if res.NextToken == nil {
						break
					}
					params.NextToken = res.NextToken
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

// AwsEc2ImageDescribeAttributes retrieves EC2 image launch permissions
func AwsEc2ImageDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "EC2ImageDescribeAttributes")
	logger.Info("Checking EC2 AMI launch permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ec2Client := ec2.NewFromConfig(config)

			launchPermissionInput := &ec2.DescribeImageAttributeInput{
				Attribute: ec2types.ImageAttributeNameLaunchPermission,
				ImageId:   aws.String(resource.Identifier),
			}
			permissionsOutput, err := ec2Client.DescribeImageAttribute(ctx, launchPermissionInput)
			if err != nil {
				logger.Debug("Could not get EC2 image launch permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				launchPermissions, err := json.Marshal(permissionsOutput.LaunchPermissions)
				if err != nil {
					logger.Error("Could not marshal EC2 image launch permissions")
					continue
				}
				launchPermissionsString := "\"LaunchPermissions\":" + string(launchPermissions)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + launchPermissionsString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}

// AwsEc2GetUserDataStage retrieves user data from EC2 instances
func AwsEc2GetUserDataStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "EC2GetUserDataStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for resource := range in {
			// Skip if not an EC2 instance
			if resource.TypeName != "AWS::EC2::Instance" {
				continue
			}

			// Set up EC2 client
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %v", resource.Region, err))
				continue
			}

			ec2Client := ec2.NewFromConfig(config)

			// Get user data
			input := &ec2.DescribeInstanceAttributeInput{
				Attribute:  ec2types.InstanceAttributeNameUserData,
				InstanceId: aws.String(resource.Identifier),
			}

			output, err := ec2Client.DescribeInstanceAttribute(ctx, input)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to get user data for instance %s: %v", resource.Identifier, err))
				continue
			}

			// Skip if no user data
			if output.UserData == nil || output.UserData.Value == nil {
				continue
			}

			// Send decoded user data

			out <- types.NpInput{
				ContentBase64: *output.UserData.Value,
				Provenance: types.NpProvenance{
					Platform:     string(modules.AWS),
					ResourceType: fmt.Sprintf("%s::UserData", resource.TypeName),
					ResourceID:   resource.Arn.String(),
					Region:       resource.Region,
					AccountID:    resource.AccountId,
				},
			}
		}
	}()

	return out
}

// AwsEc2ListFPGAImages lists EC2 FPGA images in a given region.
func AwsEc2ListFPGAImages(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListEC2FPGAImages")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing EC2 FPGA images")
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

				ec2Client := ec2.NewFromConfig(config)
				params := &ec2.DescribeFpgaImagesInput{
					Owners: []string{acctId},
				}

				for {
					res, err := ec2Client.DescribeFpgaImages(ctx, params)
					if err != nil {
						if strings.Contains(err.Error(), "The functionality you requested is not available in this region") {
							logger.Debug(err.Error())
							break
						} else {

							logger.Error(err.Error())
						}
						continue
					}

					for _, image := range res.FpgaImages {
						properties, err := json.Marshal(image)
						if err != nil {
							logger.Error("Could not marshal EC2 FPGA image description")
							continue
						}

						out <- types.EnrichedResourceDescription{
							Identifier: *image.FpgaImageId,
							TypeName:   rtype,
							Region:     region,
							Properties: string(properties),
							AccountId:  acctId,
						}
					}

					if res.NextToken == nil {
						break
					}
					params.NextToken = res.NextToken
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

// AwsEc2FPGAImageDescribeAttributes retrieves EC2 FPGA image load permissions
func AwsEc2FPGAImageDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "EC2FPGAImageDescribeAttributes")
	logger.Info("Checking EC2 FPGA image load permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ec2Client := ec2.NewFromConfig(config)

			loadPermissionInput := &ec2.DescribeFpgaImageAttributeInput{
				Attribute:   ec2types.FpgaImageAttributeNameLoadPermission,
				FpgaImageId: aws.String(resource.Identifier),
			}
			permissionsOutput, err := ec2Client.DescribeFpgaImageAttribute(ctx, loadPermissionInput)
			if err != nil {
				logger.Debug("Could not describe EC2 FPGA image load permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				loadPermissions, err := json.Marshal(permissionsOutput.FpgaImageAttribute.LoadPermissions)
				if err != nil {
					logger.Error("Could not marshal EC2 FPGA image load permissions")
					continue
				}
				loadPermissionsString := "\"LoadPermissions\":" + string(loadPermissions)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}

// AwsEBSListSnapshots lists EBS snapshots in a given region.
func AwsEBSListSnapshots(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListEBSSnapshots")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing EBS snapshots")
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

				ec2Client := ec2.NewFromConfig(config)
				params := &ec2.DescribeSnapshotsInput{
					OwnerIds: []string{acctId},
				}

				for {
					res, err := ec2Client.DescribeSnapshots(ctx, params)
					if err != nil {
						logger.Error(err.Error())
						continue
					}

					for _, snapshot := range res.Snapshots {
						properties, err := json.Marshal(snapshot)
						if err != nil {
							logger.Error("Could not marshal EBS snapshot description")
							continue
						}

						out <- types.EnrichedResourceDescription{
							Identifier: *snapshot.SnapshotId,
							TypeName:   rtype,
							Region:     region,
							Properties: string(properties),
							AccountId:  acctId,
						}
					}

					if res.NextToken == nil {
						break
					}
					params.NextToken = res.NextToken
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

// AwsEbsSnapshotDescribeAttributes gets the create volume permissions for an EBS snapshot.
func AwsEbsSnapshotDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "EBSSnapshotDescribeAttributes")
	logger.Info("Checking EBS snapshot create volume permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			logger.Debug("Checking EBS snapshot create volume permissions for " + resource.Identifier)
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ec2Client := ec2.NewFromConfig(config)

			loadPermissionInput := &ec2.DescribeSnapshotAttributeInput{
				Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
				SnapshotId: aws.String(resource.Identifier),
			}
			permissionsOutput, err := ec2Client.DescribeSnapshotAttribute(ctx, loadPermissionInput)
			if err != nil {
				logger.Debug("Could not describe EBS snapshot create volume permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				loadPermissions, err := json.Marshal(permissionsOutput.CreateVolumePermissions)
				if err != nil {
					logger.Error("Could not marshal EBS snapshot create volume permissions")
					continue
				}
				loadPermissionsString := "\"CreateVolumePermissions\":" + string(loadPermissions)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}
