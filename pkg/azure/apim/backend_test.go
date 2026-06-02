package apim

import "testing"

func TestCategorizeBackendURL(t *testing.T) {
	cases := []struct {
		name    string
		rawURL  string
		wantCat BackendCategory
		wantFQDN string
	}{
		{
			name:    "azure app service default hostname",
			rawURL:  "https://my-app.azurewebsites.net/api",
			wantCat: BackendAppService,
			wantFQDN: "my-app.azurewebsites.net",
		},
		{
			name:    "app service environment",
			rawURL:  "https://servicenowmcp.iase-corpit-prod-wu2.appserviceenvironment.net/mcp",
			wantCat: BackendAppServiceEnvironment,
			wantFQDN: "servicenowmcp.iase-corpit-prod-wu2.appserviceenvironment.net",
		},
		{
			name:    "chained apim instance",
			rawURL:  "https://inner-apim.azure-api.net/path",
			wantCat: BackendAPIM,
			wantFQDN: "inner-apim.azure-api.net",
		},
		{
			name:    "gcp cloud run",
			rawURL:  "https://mcp-log-analyzer-4jrv2alh2q-uw.a.run.app/mcp",
			wantCat: BackendGCPCloudRun,
			wantFQDN: "mcp-log-analyzer-4jrv2alh2q-uw.a.run.app",
		},
		{
			// OpenShift/ARO routes have shape <app>.apps.<cluster>.<base>.
			// The earlier .apps.-substring heuristic matched too aggressively
			// (e.g., web.apps.contoso.com), so they now fall through to
			// BackendOther. Manual triage covers the actual classification.
			name:     "openshift route falls through to other",
			rawURL:   "https://f5-mcp.apps.arocorpitdev.az.micron.com/mcp",
			wantCat:  BackendOther,
			wantFQDN: "f5-mcp.apps.arocorpitdev.az.micron.com",
		},
		{
			// The reason we removed the OpenShift heuristic: legitimate
			// non-OpenShift hostnames containing `.apps.` were being mislabeled.
			name:     "non-openshift hostname containing .apps. falls through to other",
			rawURL:   "https://web.apps.contoso.com",
			wantCat:  BackendOther,
			wantFQDN: "web.apps.contoso.com",
		},
		{
			name:    "internal dns",
			rawURL:  "https://bitbucket.micron.com",
			wantCat: BackendOther,
			wantFQDN: "bitbucket.micron.com",
		},
		{
			name:    "hostname with port is preserved without port",
			rawURL:  "https://bowscordev2.micron.com:8034/mcp",
			wantCat: BackendOther,
			wantFQDN: "bowscordev2.micron.com",
		},
		{
			name:    "bare host without scheme",
			rawURL:  "my-app.azurewebsites.net",
			wantCat: BackendAppService,
			wantFQDN: "my-app.azurewebsites.net",
		},
		{
			name:    "empty input",
			rawURL:  "",
			wantCat: BackendOther,
			wantFQDN: "",
		},
		{
			name:    "case-insensitive host matching",
			rawURL:  "https://MY-APP.AZUREWEBSITES.NET/",
			wantCat: BackendAppService,
			wantFQDN: "my-app.azurewebsites.net",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCat, gotFQDN := CategorizeBackendURL(tc.rawURL)
			if gotCat != tc.wantCat {
				t.Errorf("category = %q, want %q", gotCat, tc.wantCat)
			}
			if gotFQDN != tc.wantFQDN {
				t.Errorf("fqdn = %q, want %q", gotFQDN, tc.wantFQDN)
			}
		})
	}
}
