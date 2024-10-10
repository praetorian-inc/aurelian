package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/nebula/utils"
)

func AwsExpandActionsStage[In, Out string](ctx context.Context, opts []*options.Option, in <-chan In) <-chan Out {
	out := make(chan Out)
	body, err := utils.Cached_httpGet("https://awspolicygen.s3.amazonaws.com/js/policies.js")

	jstring := strings.Replace(string(body), "app.PolicyEditorConfig=", "", 1)

	var j map[string]interface{}
	err = json.Unmarshal([]byte(jstring), &j)
	if err != nil {
		fmt.Println(fmt.Errorf("error unmarshalling JSON: %v", err))
		return nil
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
	go func() {
		defer close(out)
		for action := range in {
			pattern := strings.ReplaceAll(string(action), "*", ".*")
			pattern = "^" + pattern + "$"

			for _, a := range allActions {
				match, _ := regexp.MatchString(pattern, a)
				if match {
					out <- Out(a)
				}
			}

		}
	}()
	return out
}

func AwsKnownAccountIdStage(ctx context.Context, opts []*options.Option, in <-chan string) <-chan AwsKnownAccount {
	out := make(chan AwsKnownAccount)

	go func() {
		defer close(out)
		logs.ConsoleLogger().Info("Getting known AWS account IDs")
		for id := range in {

			body, err := utils.Cached_httpGet("https://raw.githubusercontent.com/rupertbg/aws-public-account-ids/master/accounts.json")
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error getting known AWS account IDs: %v", err))
				continue
			}

			var accounts []AwsKnownAccount
			err = json.Unmarshal(body, &accounts)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error unmarshalling known AWS account IDs: %v", err))
				continue
			}

			for _, account := range accounts {
				if account.ID == string(id) {
					out <- account
					break
				}
			}
		}
	}()

	return out
}

type AwsKnownAccount struct {
	ID          string      `json:"id"`
	Owner       string      `json:"owner"`
	Source      interface{} `json:"source"`
	Description string      `json:"description"`
}
