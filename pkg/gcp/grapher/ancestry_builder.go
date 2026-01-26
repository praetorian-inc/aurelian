package gcloudiam

import gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"

type AncestryBuilder struct {
	nodeByURI map[string]any
	ancestors map[string][]string
}

func NewAncestryBuilder() *AncestryBuilder {
	return &AncestryBuilder{
		nodeByURI: make(map[string]any),
		ancestors: make(map[string][]string),
	}
}

func (ab *AncestryBuilder) AddOrganization(org *gcptypes.Organization) {
	ab.nodeByURI[org.URI] = org
	ab.ancestors[org.URI] = []string{}
}

func (ab *AncestryBuilder) AddFolder(folder *gcptypes.Folder) {
	ab.nodeByURI[folder.URI] = folder
	ab.ancestors[folder.URI] = ab.buildAncestorChain(folder.ParentURI)
}

func (ab *AncestryBuilder) AddProject(project *gcptypes.Project) {
	ab.nodeByURI[project.URI] = project
	ab.ancestors[project.URI] = ab.buildAncestorChain(project.ParentURI)
}

func (ab *AncestryBuilder) buildAncestorChain(parent string) []string {
	if parent == "" {
		return []string{}
	}
	chain := []string{parent}
	if parentAncestors, ok := ab.ancestors[parent]; ok {
		chain = append(chain, parentAncestors...)
	}
	return chain
}

func (ab *AncestryBuilder) GetAncestors(uri string) []string {
	return ab.ancestors[uri]
}

func (ab *AncestryBuilder) GetNode(uri string) any {
	return ab.nodeByURI[uri]
}
