package analyze

import (
	"strconv"
	"sync"
	"testing"

	"github.com/praetorian-inc/nebula/modules"
	. "github.com/praetorian-inc/nebula/modules/options"
)

func TestAccessKeyIdToAccountId_Invoke(t *testing.T) {

	// Test case 2: access_key_id option is not empty and m.Data channel value is 411435703965
	keys := []map[string]string{
		{
			"access_key_id": "AKIAV7S32T2OSBFJQOIY",
			"account_id":    "411435703965",
		},
		{
			"access_key_id": "ASIAY34FZKBOKMUTVV7A",
			"account_id":    "609629065308",
		},
	}
	for _, key := range keys {
		opt2 := AwsAccessKeyIdOpt
		opt2.Value = key["access_key_id"]
		options := []*Option{&opt2}
		run := modules.Run{Data: make(chan modules.Result)}
		m, _ := NewAccessKeyIdToAccountId(options, run)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			for res := range run.Data {
				id, _ := strconv.Atoi(key["account_id"])
				if res.Data != id {
					t.Errorf("Expected value %s on m.Data channel, got %v", key["account_id"], res.Data)
				}
				t.Log(id)
				wg.Done()
			}
		}()
		err := m.Invoke()
		wg.Wait()
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
	}
}
