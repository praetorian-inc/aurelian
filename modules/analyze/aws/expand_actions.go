package analyze

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
)

type AwsExpandActions struct {
	modules.BaseModule
}

var AwsExpandActionsRequiredOptions = []*options.Option{
	&options.AwsActionOpt,
}

var AwsExpandActionOutputProvders = []func(options []*options.Option) modules.OutputProvider{
	op.NewConsoleProvider,
}

var AwsExpandActionsMetadata = modules.Metadata{
	Id:          "expand-actions",
	Name:        "AWS Expand Actions",
	Description: "This module takes a wildcard action and returns a list of all possible actions that match the wildcard.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAwsExpandActions(options []*options.Option, run modules.Run) (modules.Module, error) {
	var m AwsExpandActions
	m.SetMetdata(AwsExpandActionsMetadata)
	m.Run = run
	m.Options = options
	m.ConfigureOutputProviders(AwsExpandActionOutputProvders)

	return &m, nil
}

func (m *AwsExpandActions) Invoke() error {
	resp, err := http.Get("https://awspolicygen.s3.amazonaws.com/js/policies.js")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	jstring := strings.Replace(string(body), "app.PolicyEditorConfig=", "", 1)

	var j map[string]interface{}
	err = json.Unmarshal([]byte(jstring), &j)
	if err != nil {
		return err
	}

	allActions := []string{}
	for serviceName := range j["serviceMap"].(map[string]interface{}) {
		prefix := j["serviceMap"].(map[string]interface{})[serviceName].(map[string]interface{})["StringPrefix"].(string)
		actions := j["serviceMap"].(map[string]interface{})[serviceName].(map[string]interface{})["Actions"].([]interface{})
		for _, a := range actions {
			action := a.(string)
			allActions = append(allActions, prefix+":"+action)
		}
	}

	action := m.GetOptionByName(options.AwsActionOpt.Name).Value
	pattern := strings.ReplaceAll(action, "*", ".*")

	matchedActions := []string{}
	for _, a := range allActions {
		match, _ := regexp.MatchString(pattern, a)
		if match {
			matchedActions = append(matchedActions, a)
			//fmt.Println(a)
			m.Run.Data <- m.MakeResult(a)
		}
	}

	//m.Run.Data <- m.MakeResult(matchedActions)
	close(m.Run.Data)
	return nil
}
