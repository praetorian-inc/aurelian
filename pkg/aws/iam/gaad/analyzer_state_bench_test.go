package gaad

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func BenchmarkGetResourcesByAction(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("resources=%d", size), func(b *testing.B) {
			resources := store.NewMap[output.AWSResource]()
			for i := 0; i < size; i++ {
				var arnStr string
				switch i % 5 {
				case 0:
					arnStr = fmt.Sprintf("arn:aws:iam::%012d:role/role-%d", 100000000000+i, i)
				case 1:
					arnStr = fmt.Sprintf("arn:aws:iam::%012d:user/user-%d", 100000000000+i, i)
				case 2:
					arnStr = fmt.Sprintf("arn:aws:s3:::bucket-%d", i)
				case 3:
					arnStr = fmt.Sprintf("arn:aws:lambda:us-east-1:%012d:function:func-%d", 100000000000+i, i)
				default:
					arnStr = fmt.Sprintf("arn:aws:ec2:us-east-1:%012d:instance/i-%d", 100000000000+i, i)
				}
				resources.Set(arnStr, output.AWSResource{
					ResourceType: "test",
					ResourceID:   arnStr,
					ARN:          arnStr,
					Region:       "us-east-1",
					AccountRef:   fmt.Sprintf("%012d", 100000000000+i),
				})
			}

			gaad := &types.AuthorizationAccountDetails{
				Users:    store.NewMap[types.UserDetail](),
				Roles:    store.NewMap[types.RoleDetail](),
				Groups:   store.NewMap[types.GroupDetail](),
				Policies: store.NewMap[types.ManagedPolicyDetail](),
			}

			state := NewAnalyzerState(gaad, nil, resources)
			action := iam.Action("iam:PassRole")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				state.GetResourcesByAction(action)
			}
		})
	}
}
