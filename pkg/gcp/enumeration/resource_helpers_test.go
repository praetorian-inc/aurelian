package enumeration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRelativeGCPResourceID(t *testing.T) {
	cases := []struct {
		name     string
		selfLink string
		want     string
	}{
		{
			name:     "compute api self link",
			selfLink: "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1/addresses/test-address",
			want:     "projects/test-project/regions/us-central1/addresses/test-address",
		},
		{
			name:     "relative resource path",
			selfLink: "projects/test-project/global/forwardingRules/test-rule",
			want:     "projects/test-project/global/forwardingRules/test-rule",
		},
		{
			name:     "leading slash and query",
			selfLink: "/compute/v1/projects/test-project/global/addresses/test-address?alt=json",
			want:     "projects/test-project/global/addresses/test-address",
		},
		{
			name:     "empty",
			selfLink: "",
			want:     "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, relativeGCPResourceID(tc.selfLink))
		})
	}
}
