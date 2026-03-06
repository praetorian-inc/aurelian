package plugin

import (
	"fmt"
	"strings"

	"google.golang.org/api/option"
)

type GCPCommonRecon struct {
	ProjectID          []string              `param:"project-id"           desc:"GCP project IDs" shortcode:"p"`
	OrgID              []string              `param:"org-id"               desc:"GCP organization IDs" shortcode:"o"`
	FolderID           []string              `param:"folder-id"            desc:"GCP folder IDs"`
	ResourceType       []string              `param:"resource-type"        desc:"Resource types to enumerate" default:"all" shortcode:"t"`
	Concurrency        int                   `param:"concurrency"          desc:"Max concurrent API requests" default:"5"`
	CredentialsFile    string                `param:"creds-file"           desc:"Path to GCP credentials JSON" shortcode:"c"`
	IncludeSysProjects bool                  `param:"include-sys-projects" desc:"Include system projects" default:"false"`
	ClientOptions      []option.ClientOption `param:"-"`
	ResolvedProjects   []string              `param:"-"`
}

var systemProjectPrefixes = []string{"sys-", "script-editor-", "apps-script-"}

func (c *GCPCommonRecon) PostBind(_ Config, _ Module) error {
	if len(c.ProjectID) == 0 && len(c.OrgID) == 0 && len(c.FolderID) == 0 {
		return fmt.Errorf("at least one of --project-id, --org-id, or --folder-id is required")
	}
	if c.CredentialsFile != "" {
		c.ClientOptions = append(c.ClientOptions, option.WithCredentialsFile(c.CredentialsFile))
	}
	c.Concurrency = max(1, c.Concurrency)
	return nil
}

func IsSystemProject(projectID string) bool {
	for _, prefix := range systemProjectPrefixes {
		if strings.HasPrefix(projectID, prefix) {
			return true
		}
	}
	return false
}
