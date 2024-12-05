package stages

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
	a "github.com/seancfoley/ipaddress-go/ipaddr"
	"gopkg.in/yaml.v3"
)

// AwsExpandActionsStage is a generic function that takes an input channel of strings and returns an output channel of strings.
// It fetches AWS policy actions from a remote URL, processes the JSON response to extract all possible actions, and then
// matches each input action pattern against the list of all actions. If a match is found, it sends the matched action to the output channel.
//
// Type Parameters:
//   - In: The type of the input channel elements (string).
//   - Out: The type of the output channel elements (string).
//
// Parameters:
//   - ctx: The context for controlling cancellation and deadlines.
//   - opts: A slice of options for additional configurations (not used in the current implementation).
//   - in: An input channel of type In (string) containing action patterns to be matched.
//
// Returns:
//   - An output channel of type Out (string) containing matched actions.
func AwsExpandActionsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	out := make(chan string)
	body, err := utils.Cached_httpGet("https://awspolicygen.s3.amazonaws.com/js/policies.js")
	if err != nil {
		fmt.Println(fmt.Errorf("error getting AWS policy actions: %v", err))
		return nil
	}

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
					out <- a
				}
			}

		}
	}()
	return out
}

// AwsKnownAccountIdStage retrieves known AWS account IDs from a remote JSON file and matches them against input IDs.
// It reads input IDs from the provided channel, fetches the JSON file containing known AWS account IDs, and sends
// matching accounts to the output channel.
//
// Parameters:
//   - ctx: The context for controlling cancellation and deadlines.
//   - opts: A slice of options for configuring the stage (currently unused).
//   - in: A channel of input strings representing AWS account IDs to be checked.
//
// Returns:
//   - A channel of AwsKnownAccount structs that match the input IDs.
func AwsKnownAccountIdStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan AwsKnownAccount {
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

			body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml")
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error getting known AWS account IDs: %v", err))
				continue
			}

			fcsAccounts := []fwdcloudsecAccount{}
			yaml.Unmarshal(body, &fcsAccounts)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error unmarshalling fwdcloudsec known AWS account IDs: %v", err))
				continue
			}

			body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/duo-labs/cloudmapper/refs/heads/main/vendor_accounts.yaml")
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error getting known AWS account IDs: %v", err))
				continue
			}

			cmAccounts := []cloudmapperAccount{}
			yaml.Unmarshal(body, &cmAccounts)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error unmarshalling fwdcloudsec known AWS account IDs: %v", err))
				continue
			}
			for _, account := range cmAccounts {
				for _, id := range account.Accounts {
					accounts = append(accounts, AwsKnownAccount{ID: id, Owner: account.Name, Source: account.Source})
				}
			}

			// https://github.com/trufflesecurity/trufflehog/blob/4cd055fe3f13b5e17fcb19553c623f1f2720e9f3/pkg/detectors/aws/access_keys/canary.go#L16
			canaryTokens := []string{"052310077262", "171436882533", "534261010715", "595918472158", "717712589309", "819147034852", "992382622183", "730335385048", "266735846894"}

			for _, id := range canaryTokens {
				accounts = append(accounts, AwsKnownAccount{ID: id, Owner: "Thinkst", Description: "Canary Tokens AWS account"})
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

type cloudmapperAccount struct {
	Name     string   `json:"name"`
	Source   string   `json:"source"`
	Accounts []string `json:"accounts"`
}

type fwdcloudsecAccount struct {
	Name     string   `yaml:"name"`
	Source   []string `yaml:"source"`
	Accounts []string `yaml:"accounts"`
}

type AwsKnownAccount struct {
	ID          string      `json:"id"`
	Owner       string      `json:"owner"`
	Source      interface{} `json:"source"`
	Description string      `json:"description"`
}

func AwsAccessKeyIdtoAccountIdStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan int {
	out := make(chan int)
	go func() {
		defer close(out)
		for AWSKeyID := range in {
			trimmedAWSKeyID := AWSKeyID[4:]                          // remove KeyID prefix
			x, _ := base32.StdEncoding.DecodeString(trimmedAWSKeyID) // base32 decode
			y := make([]byte, 8)
			copy(y[2:], x[0:6])

			z := binary.BigEndian.Uint64(y)
			//z := int(binary.BigEndian.Uint64(y))
			m1, err := hex.DecodeString("7fffffffff80")
			if err != nil {
				fmt.Println(err)
			}
			mask := make([]byte, 8)
			copy(mask[2:], m1)

			e := (z & binary.BigEndian.Uint64(mask)) >> 7
			out <- int(e)
		}
	}()
	return out
}

func AwsIpLookupStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for ip := range in {

			helpers.PrintMessage("Downloading AWS IP ranges...")
			body, err := utils.Cached_httpGet("https://ip-ranges.amazonaws.com/ip-ranges.json")
			if err != nil {
				logs.ConsoleLogger().Error("Error getting AWS IP ranges: " + err.Error())
				continue
			}

			var ipRanges IPRanges
			err = json.Unmarshal(body, &ipRanges)
			if err != nil {
				logs.ConsoleLogger().Error("Error unmarshalling AWS IP ranges: " + err.Error())
				continue
			}

			logs.ConsoleLogger().Info("Searching for " + ip + " in AWS IP ranges")
			var found int32
			prefixesChan := make(chan Prefix, 100) // Buffered channel to reduce blocking on send

			var wg sync.WaitGroup

			// TODO move this to a config option
			numWorkers := 10
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go processPrefix(prefixesChan, &found, ip, &wg)
			}

			// Send prefixes to the channel
			for _, prefix := range ipRanges.Prefixes {
				if atomic.LoadInt32(&found) == 1 {
					break
				}
				prefixesChan <- prefix
			}

			// Close the channel and wait for all workers to finish
			close(prefixesChan)
			wg.Wait()
		}
	}()

	return out
}

func processPrefix(prefixesChan <-chan Prefix, found *int32, target string, wg *sync.WaitGroup) {
	defer wg.Done()
	for prefix := range prefixesChan {
		if atomic.LoadInt32(found) == 1 {
			return
		}
		ips := Cidr2IPs(prefix.IPPrefix)

		for _, ip := range ips {
			if ip == target {
				helpers.PrintMessage("Found:\n" + prefix.String())
				atomic.StoreInt32(found, 1)
				return
			}
		}
	}
}

type IPRanges struct {
	SyncToken    string   `json:"syncToken"`
	CreateDate   string   `json:"createDate"`
	Prefixes     []Prefix `json:"prefixes"`
	IPv6Prefixes []Prefix `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

func (p *Prefix) String() string {
	return fmt.Sprintf("prefix: %s\nregion: %s\nservice: %s\nnetwork border group: %s", p.IPPrefix, p.Region, p.Service, p.NetworkBorderGroup)
}

func Cidr2IPs(cidr string) []string {
	var addrs []string
	block := a.NewIPAddressString(cidr).GetAddress()
	for i := block.Iterator(); i.HasNext(); {
		addrs = append(addrs, i.Next().GetNetNetIPAddr().String())
	}
	return addrs
}
