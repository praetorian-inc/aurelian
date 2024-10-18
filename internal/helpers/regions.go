package helpers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

var Regions = []string{
	"us-east-2",
	"us-east-1",
	"us-west-1",
	"us-west-2",
	"af-south-1",
	"ap-east-1",
	"ap-south-2",
	"ap-southeast-3",
	"ap-southeast-4",
	"ap-south-1",
	"ap-northeast-3",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"ca-central-1",
	"ca-west-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-south-1",
	"eu-west-3",
	"eu-south-2",
	"eu-north-1",
	"eu-central-2",
	"il-central-1",
	"me-south-1",
	"me-central-1",
	"sa-east-1",
	"us-gov-east-1",
	"us-gov-west-1",
}

func EnabledRegions(profile string) ([]string, error) {
	var regions []string

	// Use cache if it exists for profile
	if utils.IsCacheValid(CreateFileName(fmt.Sprintf("%s_enabled_regions", profile))) {
		data, err := utils.ReadCache(CreateFileName(fmt.Sprintf("%s_enabled_regions", profile)))
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(data, &regions)
		if err != nil {
			return nil, err
		}
		logs.ConsoleLogger().Debug("Using cached enabled regions")
		return regions, nil
	}

	cfg, err := GetAWSCfg("", profile)

	if err != nil {
		return nil, err
	}

	client := ec2.NewFromConfig(cfg)
	input := &ec2.DescribeRegionsInput{}

	result, err := client.DescribeRegions(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	for _, region := range result.Regions {
		regions = append(regions, *region.RegionName)
	}

	data, err := json.Marshal(regions)
	if err != nil {
		return nil, err
	}

	utils.WriteCache(CreateFileName(fmt.Sprintf("%s_enabled_regions", profile)), data)
	return regions, nil
}
