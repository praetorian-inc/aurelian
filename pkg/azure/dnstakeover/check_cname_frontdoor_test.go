package dnstakeover

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrontDoorEndpointName(t *testing.T) {
	n, ok := frontDoorEndpointName("myfd.azurefd.net")
	require.True(t, ok)
	assert.Equal(t, "myfd", n)

	_, ok = frontDoorEndpointName("myfd-abc.z01.azurefd.net")
	assert.False(t, ok, "hashed Standard/Premium hostnames are a documented FN")

	_, ok = frontDoorEndpointName("x.azureedge.net")
	assert.False(t, ok)
}

func TestFrontDoorEndpointName_TrailingDotAndCase(t *testing.T) {
	n, ok := frontDoorEndpointName("MyFD.AzureFD.net.")
	require.True(t, ok)
	assert.Equal(t, "myfd", n)
}

func TestFrontDoorEndpointName_EmptyLabel(t *testing.T) {
	_, ok := frontDoorEndpointName(".azurefd.net")
	assert.False(t, ok)
}

type mockFrontDoorClient struct {
	available bool
	inputs    []armfrontdoor.CheckNameAvailabilityInput
}

func (m *mockFrontDoorClient) Check(_ context.Context, input armfrontdoor.CheckNameAvailabilityInput, _ *armfrontdoor.NameAvailabilityWithSubscriptionClientCheckOptions) (armfrontdoor.NameAvailabilityWithSubscriptionClientCheckResponse, error) {
	m.inputs = append(m.inputs, input)
	avail := armfrontdoor.AvailabilityUnavailable
	if m.available {
		avail = armfrontdoor.AvailabilityAvailable
	}
	return armfrontdoor.NameAvailabilityWithSubscriptionClientCheckResponse{
		CheckNameAvailabilityOutput: armfrontdoor.CheckNameAvailabilityOutput{
			NameAvailability: &avail,
		},
	}, nil
}

func classicFrontDoorRecord() AzureDNSRecord {
	return AzureDNSRecord{
		SubscriptionID: "sub",
		ResourceGroup:  "rg",
		ZoneName:       "example.com",
		RecordName:     "www",
		FQDN:           "www.example.com",
		Type:           "CNAME",
		Values:         []string{"foo.azurefd.net"},
	}
}

func TestCheckFrontDoor_ClassicAvailableEmitsRisk(t *testing.T) {
	client := &mockFrontDoorClient{available: true}
	risks := collectFrontDoorRisks(t, client, classicFrontDoorRecord())
	require.Len(t, risks, 1)
	assert.Equal(t, "frontdoor-subdomain-takeover", risks[0].Name)

	require.Len(t, client.inputs, 1)
	require.NotNil(t, client.inputs[0].Type)
	assert.Equal(t, armfrontdoor.ResourceTypeMicrosoftNetworkFrontDoors, *client.inputs[0].Type)
}

func TestCheckFrontDoor_ClassicUnavailableNoRisk(t *testing.T) {
	client := &mockFrontDoorClient{available: false}
	assert.Empty(t, collectFrontDoorRisks(t, client, classicFrontDoorRecord()))

	require.Len(t, client.inputs, 1)
	require.NotNil(t, client.inputs[0].Type)
	assert.Equal(t, armfrontdoor.ResourceTypeMicrosoftNetworkFrontDoors, *client.inputs[0].Type)
}

func TestCheckFrontDoor_HashedZ01SkipsCheck(t *testing.T) {
	client := &mockFrontDoorClient{available: true}
	rec := AzureDNSRecord{
		SubscriptionID: "sub",
		ResourceGroup:  "rg",
		ZoneName:       "example.com",
		RecordName:     "www",
		FQDN:           "www.example.com",
		Type:           "CNAME",
		Values:         []string{"myfd-abc.z01.azurefd.net"},
	}
	assert.Empty(t, collectFrontDoorRisks(t, client, rec))
	assert.Empty(t, client.inputs)
}

func collectFrontDoorRisks(t *testing.T, client *mockFrontDoorClient, rec AzureDNSRecord) []output.AurelianRisk {
	t.Helper()
	out := pipeline.New[model.AurelianModel]()
	errCh := make(chan error, 1)
	go func() {
		defer out.Close()
		errCh <- checkFrontDoorWithClient(context.Background(), client, rec, out)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	require.NoError(t, <-errCh)

	risks := make([]output.AurelianRisk, 0, len(items))
	for _, item := range items {
		risk, ok := item.(output.AurelianRisk)
		require.True(t, ok, "expected AurelianRisk, got %T", item)
		risks = append(risks, risk)
	}
	return risks
}
