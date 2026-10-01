package enumeration

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// ec2InstanceLastModified stamps instances with LaunchTime. User data can only
// change while an instance is stopped, and starting it resets LaunchTime, so
// every user-data change is followed by a newer LaunchTime.
type ec2InstanceLastModified struct {
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

func NewEC2InstanceTimestampEnumerator(cc *CloudControlEnumerator, provider *AWSConfigProvider, skipReport *SkipReport) *CloudControlTimestampEnumerator {
	return newCloudControlTimestampEnumerator(cc, "AWS::EC2::Instance", &ec2InstanceLastModified{provider: provider, skipReport: skipReport})
}

// regionStamper describes the region's instances once, on the first resource,
// instead of once per instance. A nil map value marks an instance AWS returned
// without LaunchTime.
func (s *ec2InstanceLastModified) regionStamper(region string) stampFunc {
	var launchTimes map[string]*time.Time
	loaded := false
	return func(r *output.AWSResource) error {
		if !loaded {
			loaded = true
			launchTimes = s.describeLaunchTimes(region, nil)
		}
		return stampLaunchTime(r, launchTimes)
	}
}

func (s *ec2InstanceLastModified) resourceStamper(region string) stampFunc {
	return func(r *output.AWSResource) error {
		return stampLaunchTime(r, s.describeLaunchTimes(region, []string{ec2InstanceID(r)}))
	}
}

// describeLaunchTimes returns nil when DescribeInstances fails, which leaves
// every instance in the region unstamped.
func (s *ec2InstanceLastModified) describeLaunchTimes(region string, instanceIDs []string) map[string]*time.Time {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		warnTimestampFailure(err, "ec2", "DescribeInstances", region, "")
		return nil
	}

	launchTimes := make(map[string]*time.Time)
	paginator := ec2.NewDescribeInstancesPaginator(ec2.NewFromConfig(*cfg), &ec2.DescribeInstancesInput{InstanceIds: instanceIDs})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ec2", "DescribeInstances", region); op != nil {
				s.skipReport.Record(*op)
				return nil
			}
			warnTimestampFailure(err, "ec2", "DescribeInstances", region, "")
			return nil
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				launchTimes[aws.ToString(instance.InstanceId)] = instance.LaunchTime
			}
		}
	}
	return launchTimes
}

func stampLaunchTime(r *output.AWSResource, launchTimes map[string]*time.Time) error {
	if launchTimes == nil {
		return nil
	}
	id := ec2InstanceID(r)
	launchTime, found := launchTimes[id]
	if !found {
		slog.Debug("instance listed by CloudControl not returned by DescribeInstances; leaving LastModified unset",
			"instance", id, "region", r.Region)
		return nil
	}
	if launchTime == nil {
		return fmt.Errorf("DescribeInstances returned instance %s in %s without LaunchTime", id, r.Region)
	}
	r.LastModified = launchTime
	return nil
}

func ec2InstanceID(r *output.AWSResource) string {
	if id, ok := r.Properties["InstanceId"].(string); ok && id != "" {
		return id
	}
	return r.ResourceID
}
