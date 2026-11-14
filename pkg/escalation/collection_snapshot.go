package escalation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

const CollectionSnapshotVersion = "collection-snapshot-v1"

// CollectionUnknown records a value that a plan-to-snapshot adapter could not
// resolve. Security-critical unknowns prevent model assembly; emitting an ARN,
// policy, trust relationship, or role association by guessing would make the
// benchmark report paths that the authored environment does not establish.
type CollectionUnknown struct {
	Address          string `json:"address"`
	Field            string `json:"field"`
	Reason           string `json:"reason"`
	SecurityCritical bool   `json:"security_critical"`
}

// CollectionSnapshot is Aurelian's stable, apply-free collector replay format.
// It deliberately contains collector-shaped data rather than model-v1 facts so
// replay exercises the same model assembly used by a live scan.
type CollectionSnapshot struct {
	Version            string                             `json:"version"`
	GAAD               *types.AuthorizationAccountDetails `json:"gaad"`
	OrgPolicies        *orgpolicies.OrgPolicies           `json:"org_policies,omitempty"`
	Resources          []output.AWSResource               `json:"resources,omitempty"`
	Relationships      []output.AWSIAMRelationship        `json:"relationships,omitempty"`
	PermissionFormat   string                             `json:"permission_format,omitempty"`
	Attacker           string                             `json:"attacker,omitempty"`
	CollectionCoverage map[string]*CollectionCoverage     `json:"collection_coverage,omitempty"`
	CollectionErrors   []CollectionError                  `json:"collection_errors,omitempty"`
	Unknowns           []CollectionUnknown                `json:"unknowns,omitempty"`
}

// LoadCollectionSnapshot decodes and validates an offline collector replay.
func LoadCollectionSnapshot(data []byte) (*CollectionSnapshot, error) {
	var snapshot CollectionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode collection snapshot: %w", err)
	}
	if err := snapshot.validate(); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// Assemble runs the snapshot through the production model assembly boundary.
func (s *CollectionSnapshot) Assemble() (*Model, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	resources := store.NewMap[output.AWSResource]()
	for _, resource := range s.Resources {
		resources.Set(resourceIdentity(resource), resource)
	}
	relationships := store.NewMap[output.AWSIAMRelationship]()
	for i, relationship := range s.Relationships {
		relationships.Set(fmt.Sprintf("snapshot-relationship-%d", i), relationship)
	}

	return Assemble(AssembleInput{
		GAAD:               s.GAAD,
		OrgPolicies:        s.OrgPolicies,
		Resources:          resources,
		Relationships:      relationships,
		PermissionFormat:   s.PermissionFormat,
		Attacker:           s.Attacker,
		CollectionCoverage: s.CollectionCoverage,
		CollectionErrors:   s.CollectionErrors,
	})
}

func (s *CollectionSnapshot) validate() error {
	if s == nil {
		return fmt.Errorf("collection snapshot is nil")
	}
	if s.Version != CollectionSnapshotVersion {
		return fmt.Errorf("unsupported collection snapshot version %q (want %q)", s.Version, CollectionSnapshotVersion)
	}
	if s.GAAD == nil {
		return fmt.Errorf("collection snapshot requires gaad")
	}
	for _, unknown := range s.Unknowns {
		if unknown.SecurityCritical {
			return fmt.Errorf("security-critical collection value is unknown: %s.%s: %s", unknown.Address, unknown.Field, unknown.Reason)
		}
	}

	seen := make(map[string]struct{}, len(s.Resources))
	for i, resource := range s.Resources {
		identity := resourceIdentity(resource)
		if identity == "" {
			return fmt.Errorf("resource %d requires arn or resource_id", i)
		}
		if _, ok := seen[identity]; ok {
			return fmt.Errorf("duplicate resource identity %q", identity)
		}
		seen[identity] = struct{}{}
		if strings.TrimSpace(resource.ResourceType) == "" {
			return fmt.Errorf("resource %q requires resource_type", identity)
		}
		if _, modeled := awsResourceTypeToSolver[resource.ResourceType]; modeled && strings.TrimSpace(resource.ARN) == "" {
			return fmt.Errorf("modeled resource %q requires arn", identity)
		}
		if strings.TrimSpace(resource.AccountRef) == "" {
			return fmt.Errorf("resource %q requires account_ref", identity)
		}
	}
	return nil
}

func resourceIdentity(resource output.AWSResource) string {
	if resource.ARN != "" {
		return resource.ARN
	}
	return resource.ResourceID
}
