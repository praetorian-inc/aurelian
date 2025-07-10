package recon

// import (
// 	"github.com/praetorian-inc/janus/pkg/chain"
// 	"github.com/praetorian-inc/janus/pkg/chain/cfg"
// 	"github.com/praetorian-inc/janus/pkg/output"
// 	"github.com/praetorian-inc/nebula/internal/registry"
// 	"github.com/praetorian-inc/nebula/pkg/links/gcp/compute"
// 	"github.com/praetorian-inc/nebula/pkg/links/general"
// 	"github.com/praetorian-inc/nebula/pkg/outputters"
// 	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
// )

// func init() {
// 	registry.Register("gcp", "recon", GCPComputePublicResources.Metadata().Properties()["id"].(string), *GCPComputePublicResources)
// }

// var GCPComputePublicResources = chain.NewModule(
// 	cfg.NewMetadata(
// 		"GCP Compute Public Resources",
// 		"Scan GCP compute instances for public IP access across projects and regions",
// 	).WithProperties(map[string]any{
// 		"id":          "compute-public-resources",
// 		"platform":    "gcp",
// 		"opsec_level": "moderate",
// 		"authors":     []string{"Praetorian"},
// 		"references":  []string{},
// 	}).WithChainInputParam("resource-types"),
// ).WithLinks(
// 	general.NewResourceTypePreprocessor(&ComputeResourceTypeHandler{}),
// 	compute.NewGcpComputeRegionParallelProcessor,
// ).WithOutputters(
// 	output.NewJSONOutputter,
// 	outputters.NewERDConsoleOutputter,
// ).WithInputParam(
// 	cfg.NewParam[[]string]("resource-types", "GCP resource types to scan for public access").WithDefault([]string{string(tab.GCPResourceInstance)}),
// )

// type ComputeResourceTypeHandler struct{}

// func (c *ComputeResourceTypeHandler) SupportedResourceTypes() []string {
// 	return []string{
// 		string(tab.GCPResourceInstance),
// 	}
// }
