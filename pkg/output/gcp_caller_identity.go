package output

import "github.com/praetorian-inc/aurelian/pkg/model"

type GCPCallerIdentity struct {
	model.BaseAurelianModel
	Status    string `json:"status"`
	Email     string `json:"email,omitempty"`
	Subject   string `json:"subject,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	Scopes    string `json:"scopes,omitempty"`
	ExpiresIn string `json:"expires_in,omitempty"`
}
