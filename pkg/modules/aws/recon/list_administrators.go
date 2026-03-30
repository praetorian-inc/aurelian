package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/aws/iamadmin"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSListAdministratorsModule{})
}

type ListAdministratorsConfig struct {
	plugin.AWSCommonRecon
}

// AWSListAdministratorsModule emits IAM principals with admin-level permissions.
type AWSListAdministratorsModule struct {
	ListAdministratorsConfig
}

func (m *AWSListAdministratorsModule) ID() string   { return "list-administrators" }
func (m *AWSListAdministratorsModule) Name() string { return "AWS List Administrators" }
func (m *AWSListAdministratorsModule) Description() string {
	return "Discover IAM principals with administrator-level permissions."
}
func (m *AWSListAdministratorsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSListAdministratorsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSListAdministratorsModule) OpsecLevel() string        { return "passive" }
func (m *AWSListAdministratorsModule) Authors() []string         { return []string{"Praetorian"} }
func (m *AWSListAdministratorsModule) References() []string      { return []string{} }
func (m *AWSListAdministratorsModule) Parameters() any           { return &m.ListAdministratorsConfig }
func (m *AWSListAdministratorsModule) Global() bool              { return true }

func (m *AWSListAdministratorsModule) SupportedResourceTypes() []string {
	return []string{"AWS::Organizations::Account"}
}

func (m *AWSListAdministratorsModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ListAdministratorsConfig
	lister := enumeration.NewEnumerator(c.AWSCommonRecon)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(pipeline.From("AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group"), lister.List, listed)

	evaluator := iamadmin.New(m.AWSCommonRecon)

	adminCandidates := pipeline.New[output.AWSResource]()
	pipeline.Pipe(listed, evaluator.EvaluatePrincipal, adminCandidates)

	enricher := enrichment.NewAWSEnricher(c.AWSCommonRecon)
	enriched := pipeline.New[output.AWSResource]()
	pipeline.Pipe(adminCandidates, enricher.Enrich, enriched, nil)

	pipeline.Pipe(enriched, sendAdminFinding, out)
	return out.Wait()
}

func sendAdminFinding(resource output.AWSResource, out *pipeline.P[model.AurelianModel]) error {
	out.Send(resource)
	return nil
}
