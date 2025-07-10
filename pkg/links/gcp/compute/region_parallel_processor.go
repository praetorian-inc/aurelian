package compute

// import (
// 	"sync"

// 	"github.com/praetorian-inc/janus/pkg/chain"
// 	"github.com/praetorian-inc/janus/pkg/chain/cfg"
// 	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
// 	"github.com/praetorian-inc/nebula/pkg/types"
// 	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
// )

// type GcpComputeRegionParallelProcessor struct {
// 	*base.GcpReconLink
// 	wg sync.WaitGroup
// }

// func NewGcpComputeRegionParallelProcessor(configs ...cfg.Config) chain.Link {
// 	g := &GcpComputeRegionParallelProcessor{}
// 	g.GcpReconLink = base.NewGcpReconLink(g, configs...)
// 	return g
// }

// func (g *GcpComputeRegionParallelProcessor) Process(resourceType string) error {
// 	if resourceType != string(tab.GCPResourceInstance) {
// 		return nil
// 	}

// 	for _, project := range g.Projects {
// 		g.wg.Add(1)
// 		go g.processProject(project)
// 	}

// 	g.wg.Wait()
// 	return nil
// }

// func (g *GcpComputeRegionParallelProcessor) processProject(project string) {
// 	defer g.wg.Done()

// 	projectChain := chain.NewChain(
// 		NewGcpComputeInstanceLister(),
// 		NewGcpComputePublicHostChecker(),
// 	).WithConfigs(cfg.WithArgs(g.Args()))

// 	projectChain.Send(project)
// 	projectChain.Close()

// 	for result, ok := chain.RecvAs[*types.EnrichedResourceDescription](projectChain); ok; result, ok = chain.RecvAs[*types.EnrichedResourceDescription](projectChain) {
// 		g.Send(result)
// 	}

// 	if err := projectChain.Error(); err != nil {
// 		g.Logger.Error("Error processing project", "project", project, "error", err)
// 	}
// }

// func (g *GcpComputeRegionParallelProcessor) Complete() error {
// 	g.wg.Wait()
// 	return nil
// }
