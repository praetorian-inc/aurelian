package recon

import "testing"

func TestAppServiceExposure_IsDirectlyReachable(t *testing.T) {
	cases := []struct {
		name string
		e    appServiceExposure
		want bool
	}{
		{
			name: "public access enabled, no IP restrictions",
			e:    appServiceExposure{PublicNetworkAccess: "Enabled", IPRestrictionRules: 0},
			want: true,
		},
		{
			name: "public access enabled, only default deny-all rule",
			e:    appServiceExposure{PublicNetworkAccess: "Enabled", IPRestrictionRules: 1},
			want: true,
		},
		{
			name: "public access enabled, meaningful IP restrictions configured",
			e:    appServiceExposure{PublicNetworkAccess: "Enabled", IPRestrictionRules: 3},
			want: false,
		},
		{
			name: "public access disabled",
			e:    appServiceExposure{PublicNetworkAccess: "Disabled", IPRestrictionRules: 0},
			want: false,
		},
		{
			name: "empty publicNetworkAccess string is treated as not enabled",
			e:    appServiceExposure{PublicNetworkAccess: "", IPRestrictionRules: 0},
			want: false,
		},
		{
			name: "case-insensitive match on Enabled",
			e:    appServiceExposure{PublicNetworkAccess: "enabled", IPRestrictionRules: 0},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.IsDirectlyReachable(); got != tc.want {
				t.Fatalf("IsDirectlyReachable() = %v, want %v", got, tc.want)
			}
		})
	}
}
