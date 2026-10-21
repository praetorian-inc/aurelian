package dnstakeover

import (
	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

type checkerFunc func(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error

type registeredChecker struct {
	Name       string
	RecordType string
	Fn         checkerFunc
	Clouds     []string // nil = every cloud
}

var checkersByRecordType = map[string][]registeredChecker{}

func mustRegister(recordType, name string, fn checkerFunc, clouds ...string) {
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
		Clouds:     clouds,
	})
}

func getCheckers(recordType string) []registeredChecker {
	return checkersByRecordType[recordType]
}

func unsupportedCheckers(env azurecloud.Environment) []string {
	var names []string
	for _, checkers := range checkersByRecordType {
		for _, chk := range checkers {
			if !env.Supports(chk.Clouds) {
				names = append(names, chk.Name)
			}
		}
	}
	return names
}
