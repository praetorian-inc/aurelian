package base

// import (
// 	"fmt"

// 	"github.com/praetorian-inc/janus/pkg/chain"
// 	"github.com/praetorian-inc/janus/pkg/chain/cfg"
// 	"github.com/praetorian-inc/nebula/pkg/links/options"
// 	"golang.org/x/oauth2/google"
// 	"google.golang.org/api/option"
// )

// // TODO: is a separate reconbase needed?

// type GcpReconBaseLink struct {
// 	*chain.Base
// 	CredentialsFile string
// 	ClientOptions   []option.ClientOption
// }

// func NewGcpReconBaseLink(link chain.Link, configs ...cfg.Config) *GcpReconBaseLink {
// 	g := &GcpReconBaseLink{}
// 	g.Base = chain.NewBase(link, configs...)
// 	return g
// }

// func (g *GcpReconBaseLink) Params() []cfg.Param {
// 	return options.GcpBaseOptions()
// }

// func (g *GcpReconBaseLink) Initialize() error {
// 	// g.ContextHolder = cfg.NewContextHolder()
// 	g.CredentialsFile, _ = cfg.As[string](g.Arg("creds-file"))
// 	if g.CredentialsFile != "" {
// 		g.ClientOptions = append(g.ClientOptions, option.WithCredentialsFile(g.CredentialsFile))
// 	} else {
// 		// attempt to use application default credentials or default auth that SDK can find
// 		_, err := google.FindDefaultCredentials(g.Context())
// 		if err != nil {
// 			return fmt.Errorf("cannot find default credentials: %w", err)
// 		}
// 	}
// 	return nil
// }

// type GcpReconLink struct {
// 	*GcpReconBaseLink
// 	Project string
// }

// func NewGcpReconLink(link chain.Link, configs ...cfg.Config) *GcpReconLink {
// 	g := &GcpReconLink{}
// 	g.GcpReconBaseLink = NewGcpReconBaseLink(link, configs...)
// 	return g
// }

// func (g *GcpReconLink) Params() []cfg.Param {
// 	return options.GcpCommonReconOptions()
// }

// func (g *GcpReconLink) Initialize() error {
// 	if err := g.GcpReconBaseLink.Initialize(); err != nil {
// 		return fmt.Errorf("failed to initialize base link: %w", err)
// 	}
// 	// g.ContextHolder = cfg.NewContextHolder()
// 	g.Project, _ = cfg.As[string](g.Arg("project"))
// 	return nil
// }
