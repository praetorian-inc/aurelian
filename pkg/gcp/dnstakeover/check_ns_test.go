package dnstakeover

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

const googleNS = "ns-cloud-a1.googledomains.com."

// apiFailure describes a managedZones.list failure to serve for one project.
type apiFailure struct {
	status  int
	message string
}

// fakeDNS is an in-memory Cloud DNS managedZones.list backend. It serves real
// dns.ManagedZonesListResponse JSON with nextPageToken set, so the production
// google-api-go-client pagination path executes against it rather than a
// hand-rolled fake.
type fakeDNS struct {
	// zonesByProject maps project ID -> the zone DnsNames that project owns.
	zonesByProject map[string][]string
	// failures maps project ID -> a failure to serve instead of a listing.
	failures map[string]apiFailure
	// pageSize is the number of zones served per page.
	pageSize int

	// mu guards listedProjects. The handler appends from net/http's
	// per-connection goroutine while the test goroutine reads. Today every
	// lookup is sequential, so the appends never overlap; the mutex keeps
	// that an invariant of the fake rather than of its only caller, so a
	// future test that drives concurrent lookups cannot introduce a race.
	mu sync.Mutex
	// listedProjects records every project ID whose zones were listed, in
	// request order, so a test can assert which projects were consulted.
	listedProjects []string
}

// listed returns a snapshot of the projects consulted, in request order.
func (f *fakeDNS) listed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.listedProjects)
}

func (f *fakeDNS) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		project := projectFromPath(r.URL.Path)
		if project == "" {
			t.Errorf("could not extract project from request path %q", r.URL.Path)
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.listedProjects = append(f.listedProjects, project)
		f.mu.Unlock()

		if fail, ok := f.failures[project]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(fail.status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    fail.status,
					"message": fail.message,
					"status":  http.StatusText(fail.status),
				},
			})
			return
		}

		zones := f.zonesByProject[project]
		offset := 0
		if tok := r.URL.Query().Get("pageToken"); tok != "" {
			var err error
			offset, err = strconv.Atoi(tok)
			if err != nil {
				t.Errorf("unexpected pageToken %q", tok)
				http.Error(w, "bad token", http.StatusBadRequest)
				return
			}
		}

		end := min(offset+f.pageSize, len(zones))
		resp := dns.ManagedZonesListResponse{}
		for i := offset; i < end; i++ {
			resp.ManagedZones = append(resp.ManagedZones, &dns.ManagedZone{
				Name:    fmt.Sprintf("zone-%d", i),
				DnsName: zones[i],
			})
		}
		if end < len(zones) {
			resp.NextPageToken = strconv.Itoa(end)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func projectFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if p == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// newTestChecker wires a Checker to an httptest-backed Cloud DNS service.
func newTestChecker(t *testing.T, f *fakeDNS, projectIDs []string) (*Checker, *fakeDNS) {
	t.Helper()
	if f.pageSize == 0 {
		f.pageSize = 100
	}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)

	svc, err := dns.NewService(t.Context(),
		option.WithEndpoint(srv.URL+"/"),
		option.WithoutAuthentication(),
	)
	require.NoError(t, err)

	return &Checker{dnsSvc: svc, projectIDs: projectIDs}, f
}

// runCheckNS drives checkNS and collects everything it emitted.
func runCheckNS(t *testing.T, c *Checker, rec DNSRecord) []output.AurelianRisk {
	t.Helper()
	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		c.checkNS(rec, out)
	}()
	items, err := out.Collect()
	require.NoError(t, err)

	risks := make([]output.AurelianRisk, 0, len(items))
	for _, item := range items {
		risk, ok := item.(output.AurelianRisk)
		require.Truef(t, ok, "emitted item %T is not an output.AurelianRisk", item)
		risks = append(risks, risk)
	}
	return risks
}

func nsRecord(projectID, zoneDNS, recordName string) DNSRecord {
	return DNSRecord{
		ProjectID:  projectID,
		ZoneName:   "parent-zone",
		DNSName:    zoneDNS,
		RecordName: recordName,
		Type:       "NS",
		Values:     []string{googleNS},
	}
}

// --- checkNS ---------------------------------------------------------------

// AC1: the delegated zone lives in a different project of the scanned
// organization, so the delegation is owned and no risk may be reported.
func TestCheckNS_ZoneInDifferentProject_NoRisk(t *testing.T) {
	c, f := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"hub-dns-project":   {"preprod.gcp.ent.af1platform.com."},
			"child-app-project": {"apigw.preprod.gcp.ent.af1platform.com."},
		},
	}, []string{"hub-dns-project", "child-app-project"})

	risks := runCheckNS(t, c, nsRecord(
		"hub-dns-project",
		"preprod.gcp.ent.af1platform.com.",
		"apigw.preprod.gcp.ent.af1platform.com",
	))

	assert.Empty(t, risks, "delegated zone exists in a sibling project; no risk expected")
	assert.Contains(t, f.listed(), "child-app-project",
		"the sibling project that owns the zone must be consulted")
}

// AC2: the delegated zone exists in the parent project but only after page 1,
// so the real .Pages() path must follow nextPageToken.
func TestCheckNS_ZoneOnSecondPage_NoRisk(t *testing.T) {
	const target = "apigw.preprod.gcp.ent.af1platform.com."
	zones := make([]string, 0, 150)
	for i := range 150 {
		zones = append(zones, fmt.Sprintf("filler-%d.example.com.", i))
	}
	zones[140] = target // page 2 at a page size of 100

	c, f := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{"hub-dns-project": zones},
		pageSize:       100,
	}, []string{"hub-dns-project"})

	risks := runCheckNS(t, c, nsRecord(
		"hub-dns-project",
		"preprod.gcp.ent.af1platform.com.",
		strings.TrimSuffix(target, "."),
	))

	assert.Empty(t, risks, "delegated zone is on page 2; pagination must find it")
	assert.Equal(t, []string{"hub-dns-project", "hub-dns-project"}, f.listed(),
		"both pages must be requested; a single request means .Do() not .Pages()")
}

// AC3: only a zone BELOW the delegated name exists. That deeper zone must not
// satisfy the existence test, so a genuinely dangling delegation is reported.
func TestCheckNS_OnlyDeeperZoneExists_RiskEmitted(t *testing.T) {
	c, _ := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"hub-dns-project": {
				"preprod.gcp.ent.af1platform.com.",
				"internal.apigw.preprod.gcp.ent.af1platform.com.",
			},
		},
	}, []string{"hub-dns-project"})

	risks := runCheckNS(t, c, nsRecord(
		"hub-dns-project",
		"preprod.gcp.ent.af1platform.com.",
		"apigw.preprod.gcp.ent.af1platform.com",
	))

	require.Len(t, risks, 1, "a zone below the delegated name must not clear the delegation")
	assert.Equal(t, "GCP Subdomain Takeover: Dangling NS Delegation", risks[0].Name)
	assert.Equal(t, output.RiskSeverityCritical, risks[0].Severity)
}

// AC4: an NS record set at the apex of its own zone is the zone's own
// delegation, never a dangling one — for any zone count in the project.
func TestCheckNS_ApexRecordSet_NoRisk(t *testing.T) {
	c, f := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{"hub-dns-project": {}},
	}, []string{"hub-dns-project"})

	risks := runCheckNS(t, c, nsRecord(
		"hub-dns-project",
		"preprod.gcp.ent.af1platform.com.",
		"preprod.gcp.ent.af1platform.com",
	))

	assert.Empty(t, risks, "apex NS record set must never be reported as dangling")
	assert.Empty(t, f.listed(),
		"the apex guard must return before any managedZones.list call, which is "+
			"what makes the outcome independent of the project's zone count")
}

// Ownership of the delegated zone is the sole input to the decision: the
// parent zone is owned, the delegated name is not, and the risk is reported.
//
// AC5's DNS clause ("a DNS answer may suppress a risk, it may never clear
// one") is NOT covered here, or anywhere in this package. checkNS performs no
// name resolution at all, so there is no seam into which a DNS answer could be
// injected and no behaviour that a test could discriminate. AC5 is an
// architectural constraint on a future change, not a property of the code as
// it stands; whoever adds a resolver owns writing the test that enforces it.
// The fixture deliberately uses RFC 2606 names so that if a resolver is ever
// wired in by default, this test fails loudly rather than silently resolving
// a real domain over the network.
func TestCheckNS_NoProjectOwnsDelegatedZone_RiskEmitted(t *testing.T) {
	c, _ := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"hub-dns-project": {"example.com."},
		},
	}, []string{"hub-dns-project"})

	risks := runCheckNS(t, c, nsRecord(
		"hub-dns-project",
		"example.com.",
		"api.example.com",
	))

	require.Len(t, risks, 1, "no project owns the delegated zone, so the delegation is dangling")
	assert.Equal(t, output.RiskSeverityCritical, risks[0].Severity)
}

func TestCheckNS_NonGoogleNameserver_NoRisk(t *testing.T) {
	c, f := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{"hub-dns-project": {}},
	}, []string{"hub-dns-project"})

	rec := nsRecord("hub-dns-project", "example.com.", "sub.example.com")
	rec.Values = []string{"ns1.cloudflare.com."}

	risks := runCheckNS(t, c, rec)

	assert.Empty(t, risks, "non-Cloud-DNS nameservers are out of scope for this check")
	assert.Empty(t, f.listed(), "a non-Cloud-DNS delegation must not trigger an API call")
}

// --- delegatedZoneExists ----------------------------------------------------

func TestDelegatedZoneExists_ExactMatchInAnotherProject(t *testing.T) {
	c, _ := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"parent-project": {"preprod.example.com."},
			"other-project":  {"apigw.preprod.example.com."},
		},
	}, []string{"parent-project", "other-project"})

	assert.True(t, c.delegatedZoneExists("parent-project", "apigw.preprod.example.com"))
}

func TestDelegatedZoneExists_DeeperZoneIsNotAMatch(t *testing.T) {
	c, _ := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"parent-project": {"internal.apigw.preprod.example.com."},
		},
	}, []string{"parent-project"})

	assert.False(t, c.delegatedZoneExists("parent-project", "apigw.preprod.example.com"),
		"a zone below the delegated name is not the delegated zone")
}

func TestDelegatedZoneExists_HigherZoneIsNotAMatch(t *testing.T) {
	c, _ := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"parent-project": {"preprod.example.com."},
		},
	}, []string{"parent-project"})

	assert.False(t, c.delegatedZoneExists("parent-project", "apigw.preprod.example.com"),
		"the parent zone is not the delegated zone")
}

// C1: a skippable per-project error (disabled API / permission denied) means
// that project is simply not an owner. The scan continues to the next project.
func TestDelegatedZoneExists_SkippableErrorContinuesToNextProject(t *testing.T) {
	c, f := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"owner-project": {"apigw.preprod.example.com."},
		},
		failures: map[string]apiFailure{
			"denied-project": {status: http.StatusForbidden, message: "Permission denied on resource project denied-project."},
		},
	}, []string{"denied-project", "owner-project"})

	assert.True(t, c.delegatedZoneExists("denied-project", "apigw.preprod.example.com"),
		"a permission-denied project is not an owner; the next project must still be checked")
	assert.Contains(t, f.listed(), "owner-project")
}

// C1: a skippable error on every project must not be read as ownership.
func TestDelegatedZoneExists_AllProjectsSkippable_NotAnOwner(t *testing.T) {
	c, _ := newTestChecker(t, &fakeDNS{
		failures: map[string]apiFailure{
			"denied-project": {status: http.StatusForbidden, message: "Permission denied on resource project denied-project."},
		},
	}, []string{"denied-project"})

	assert.False(t, c.delegatedZoneExists("denied-project", "apigw.preprod.example.com"),
		"permission denied everywhere means no evidence of ownership, not ownership")
}

// C1: any other error preserves today's conservative behavior — suppress.
func TestDelegatedZoneExists_NonSkippableErrorSuppressesRisk(t *testing.T) {
	c, _ := newTestChecker(t, &fakeDNS{
		failures: map[string]apiFailure{
			"parent-project": {status: http.StatusInternalServerError, message: "backend error"},
		},
	}, []string{"parent-project"})

	assert.True(t, c.delegatedZoneExists("parent-project", "apigw.preprod.example.com"),
		"an unexpected API error must suppress the risk, not assert a dangling delegation")
}

// The record's own project is always consulted, even when hierarchy resolution
// produced nothing, so the check never regresses below today's coverage.
func TestDelegatedZoneExists_RecordProjectConsultedWhenScopeEmpty(t *testing.T) {
	c, f := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"parent-project": {"apigw.preprod.example.com."},
		},
	}, nil)

	assert.True(t, c.delegatedZoneExists("parent-project", "apigw.preprod.example.com"))
	assert.Equal(t, []string{"parent-project"}, f.listed())
}

// The record's project must not be listed twice when it is also in scope.
func TestDelegatedZoneExists_RecordProjectNotListedTwice(t *testing.T) {
	c, f := newTestChecker(t, &fakeDNS{
		zonesByProject: map[string][]string{
			"parent-project": {"other.example.com."},
		},
	}, []string{"parent-project"})

	assert.False(t, c.delegatedZoneExists("parent-project", "apigw.preprod.example.com"))
	assert.Equal(t, []string{"parent-project"}, f.listed())
}
