package recon

import (
	"fmt"
	"sync"
	"testing"

	"github.com/praetorian-inc/nebula/modules"
	. "github.com/praetorian-inc/nebula/modules/options"
)

func TestCloudControlListResources_Invoke(t *testing.T) {

	run := modules.Run{Output: make(chan modules.Result)}

	// Default to all regions
	regions := AwsRegionsOpt
	regions.Value = "ALL"
	//regions.Value = "us-east-1"
	rtype := AwsResourceTypeOpt
	//rtype.Value = "AWS::Lambda::Function"
	rtype.Value = "AWS::Lambda::Function"

	opts := []*Option{&regions, &rtype}

	m, err := NewAwsCloudControlListResources(opts, run)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for res := range run.Output {
			fmt.Println(res.String())
			t.Log(res.String())
		}
		wg.Done()
	}()

	err = m.Invoke()
	wg.Wait()
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}
