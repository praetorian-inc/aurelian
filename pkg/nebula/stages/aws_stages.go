package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nebula/modules/options"
)

func AwsExpandActionsStage[In, Out string](ctx context.Context, opts []*options.Option, in <-chan In) <-chan Out {
	out := make(chan Out)
	resp, err := http.Get("https://awspolicygen.s3.amazonaws.com/js/policies.js")
	if err != nil {
		fmt.Println(fmt.Errorf("error getting AWS policy data: %v", err))
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

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
