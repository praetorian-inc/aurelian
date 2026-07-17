package recon

import (
	"encoding/json"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

// Check evaluates one enriched AWSResource and optionally emits a risk.
// Checks live inside the configuration-scan module so they share a single
// enumeration; adding a check does not add a Guard capability or a new scan job.
type Check interface {
	ResourceType() string
	Evaluate(r output.AWSResource) *output.AurelianRisk
}

func defaultChecks() []Check {
	return []Check{imdsCheck{}}
}

// imdsCheck flags EC2 instances that allow IMDSv1 (SSRF credential-theft risk).
// Logic mirrors pkg/modules/aws/rules/ec2/ec2-imdsv1-enabled.yaml, which remains
// the declarative statement of the rule; this Go check is authoritative.
type imdsCheck struct{}

func (imdsCheck) ResourceType() string { return "AWS::EC2::Instance" }

type imdsProof struct {
	InstanceID         string `json:"instance_id"`
	Region             string `json:"region"`
	HttpTokens         string `json:"http_tokens"`
	HttpEndpoint       string `json:"http_endpoint"`
	HttpPutHopLimit    int    `json:"http_put_hop_limit,omitempty"`
	InstanceState      string `json:"instance_state"`
	IamInstanceProfile string `json:"iam_instance_profile,omitempty"`
}

func propString(props map[string]any, key string) string {
	s, _ := props[key].(string)
	return s
}

func (imdsCheck) Evaluate(r output.AWSResource) *output.AurelianRisk {
	tokens, ok := r.Properties["MetadataHttpTokens"].(string)
	if !ok {
		// Enricher did not run (e.g. DescribeInstances denied). Treat as
		// "undetermined", not "compliant". Surfacing this is LAB-5015.
		return nil
	}
	if propString(r.Properties, "InstanceStateName") == "terminated" {
		return nil
	}
	if tokens != "optional" || propString(r.Properties, "MetadataHttpEndpoint") != "enabled" {
		return nil
	}

	hop, _ := r.Properties["MetadataHttpPutResponseHopLimit"].(int)
	proof := imdsProof{
		InstanceID:         r.ResourceID,
		Region:             r.Region,
		HttpTokens:         tokens,
		HttpEndpoint:       propString(r.Properties, "MetadataHttpEndpoint"),
		HttpPutHopLimit:    hop,
		InstanceState:      propString(r.Properties, "InstanceStateName"),
		IamInstanceProfile: propString(r.Properties, "IamInstanceProfile"),
	}
	ctx, err := json.Marshal(proof)
	if err != nil {
		slog.Warn("failed to marshal imds proof", "resource", r.ResourceID, "error", err)
		return nil
	}

	return &output.AurelianRisk{
		Name:               "ec2-imdsv1-enabled",
		Severity:           output.RiskSeverityMedium,
		ImpactedResourceID: r.ARN,
		Context:            ctx,
	}
}
