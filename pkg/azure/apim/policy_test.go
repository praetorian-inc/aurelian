package apim

import "testing"

func TestParseInboundAuth(t *testing.T) {
	cases := []struct {
		name     string
		policy   string
		fragAuth map[string]bool // fragment-id → contains auth element
		want     AuthPosture
	}{
		{
			name: "empty policy, no inbound children",
			policy: `<policies>
  <inbound />
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>`,
			want: AuthPosture{},
		},
		{
			name: "validate-jwt present",
			policy: `<policies>
  <inbound>
    <validate-jwt header-name="Authorization" />
  </inbound>
</policies>`,
			want: AuthPosture{ValidateJWT: true},
		},
		{
			name: "validate-azure-ad-token present",
			policy: `<policies>
  <inbound>
    <validate-azure-ad-token tenant-id="abc" />
  </inbound>
</policies>`,
			want: AuthPosture{ValidateAzureADToken: true},
		},
		{
			name: "ip-filter present",
			policy: `<policies>
  <inbound>
    <ip-filter action="allow"><address>10.0.0.0/8</address></ip-filter>
  </inbound>
</policies>`,
			want: AuthPosture{IPFilter: true},
		},
		{
			name: "check-header for Authorization counts as auth",
			policy: `<policies>
  <inbound>
    <check-header name="Authorization" failed-check-httpcode="401" failed-check-error-message="Unauthorized" ignore-case="true">
      <value>Bearer</value>
    </check-header>
  </inbound>
</policies>`,
			want: AuthPosture{CheckHeader: true},
		},
		{
			name: "check-header for X-Request-Id does NOT count as auth",
			policy: `<policies>
  <inbound>
    <check-header name="X-Request-Id" failed-check-httpcode="400" failed-check-error-message="missing" ignore-case="true" />
  </inbound>
</policies>`,
			want: AuthPosture{},
		},
		{
			name: "check-header for Ocp-Apim-Subscription-Key does NOT count as auth",
			policy: `<policies>
  <inbound>
    <check-header name="Ocp-Apim-Subscription-Key" failed-check-httpcode="401" failed-check-error-message="missing" ignore-case="true" />
  </inbound>
</policies>`,
			want: AuthPosture{},
		},
		{
			name: "auth nested in choose/when counts",
			policy: `<policies>
  <inbound>
    <choose>
      <when condition="@(context.Request.Method == &quot;GET&quot;)">
        <validate-jwt header-name="Authorization" />
      </when>
      <otherwise />
    </choose>
  </inbound>
</policies>`,
			want: AuthPosture{ValidateJWT: true},
		},
		{
			name: "only <base /> — nothing authenticates here",
			policy: `<policies>
  <inbound>
    <base />
  </inbound>
</policies>`,
			want: AuthPosture{},
		},
		{
			name: "include-fragment referencing auth fragment",
			policy: `<policies>
  <inbound>
    <include-fragment fragment-id="corp-jwt" />
  </inbound>
</policies>`,
			fragAuth: map[string]bool{"corp-jwt": true},
			want:     AuthPosture{IncludeFragment: true},
		},
		{
			name: "include-fragment referencing non-auth fragment",
			policy: `<policies>
  <inbound>
    <include-fragment fragment-id="logging" />
  </inbound>
</policies>`,
			fragAuth: map[string]bool{"logging": false, "corp-jwt": true},
			want:     AuthPosture{},
		},
		{
			name: "include-fragment with unknown id is conservatively treated as auth",
			policy: `<policies>
  <inbound>
    <include-fragment fragment-id="unknown-fragment" />
  </inbound>
</policies>`,
			fragAuth: map[string]bool{},
			want:     AuthPosture{IncludeFragment: true},
		},
		{
			name: "combined auth + base counts each present element",
			policy: `<policies>
  <inbound>
    <base />
    <validate-jwt header-name="Authorization" />
    <ip-filter action="allow"><address>10.0.0.0/8</address></ip-filter>
  </inbound>
</policies>`,
			want: AuthPosture{ValidateJWT: true, IPFilter: true},
		},
		{
			name:   "malformed XML is treated as empty (defensive)",
			policy: `<policies><inbound`,
			want:   AuthPosture{},
		},
		{
			name:   "empty policy string",
			policy: "",
			want:   AuthPosture{},
		},
		{
			name: "auth elements outside inbound are ignored",
			policy: `<policies>
  <inbound><base /></inbound>
  <backend>
    <validate-jwt header-name="Authorization" />
  </backend>
  <outbound><base /></outbound>
</policies>`,
			want: AuthPosture{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseInboundAuth(tc.policy, tc.fragAuth)
			if got != tc.want {
				t.Fatalf("ParseInboundAuth() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAuthPostureHasAuth(t *testing.T) {
	cases := []struct {
		name string
		p    AuthPosture
		want bool
	}{
		{"empty", AuthPosture{}, false},
		{"validate-jwt", AuthPosture{ValidateJWT: true}, true},
		{"validate-azure-ad-token", AuthPosture{ValidateAzureADToken: true}, true},
		{"ip-filter", AuthPosture{IPFilter: true}, true},
		{"check-header", AuthPosture{CheckHeader: true}, true},
		{"include-fragment", AuthPosture{IncludeFragment: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.HasAuth(); got != tc.want {
				t.Fatalf("HasAuth() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseFragmentHasAuth(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		want   bool
	}{
		{
			name: "fragment with validate-jwt",
			policy: `<fragment>
  <validate-jwt header-name="Authorization" />
</fragment>`,
			want: true,
		},
		{
			name: "fragment with check-header Authorization",
			policy: `<fragment>
  <check-header name="Authorization" failed-check-httpcode="401" failed-check-error-message="no" ignore-case="true" />
</fragment>`,
			want: true,
		},
		{
			name: "fragment with logging only",
			policy: `<fragment>
  <log-to-eventhub logger-id="logger1">@(context.RequestId)</log-to-eventhub>
</fragment>`,
			want: false,
		},
		{
			name:   "empty fragment",
			policy: `<fragment />`,
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FragmentHasAuth(tc.policy); got != tc.want {
				t.Fatalf("FragmentHasAuth() = %v, want %v", got, tc.want)
			}
		})
	}
}
