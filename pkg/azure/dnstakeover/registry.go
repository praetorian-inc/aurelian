package dnstakeover

import (
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

type checkerFunc func(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error

type registeredChecker struct {
	Name       string
	RecordType string
	Fn         checkerFunc
}

var checkersByRecordType = map[string][]registeredChecker{}

func mustRegister(recordType, name string, fn checkerFunc) {
	if recordType == "" {
		panic("checker record type cannot be empty")
	}
	if name == "" {
		panic("checker name cannot be empty")
	}
	if fn == nil {
		panic("checker function cannot be nil")
	}

	existing := checkersByRecordType[recordType]
	for _, item := range existing {
		if item.Name == name {
			panic("checker already registered: " + recordType + "/" + name)
		}
	}
	checkersByRecordType[recordType] = append(existing, registeredChecker{
		Name:       name,
		RecordType: recordType,
		Fn:         fn,
	})
}

func getCheckers(recordType string) []registeredChecker {
	return checkersByRecordType[recordType]
}
