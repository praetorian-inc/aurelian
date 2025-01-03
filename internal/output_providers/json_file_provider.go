package outputproviders

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/nebula/internal/logs"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type JsonFileProvider struct {
	types.OutputProvider
	OutputPath string
	FileName   string
}

func NewJsonFileProvider(options []*types.Option) types.OutputProvider {
	return &JsonFileProvider{
		OutputPath: types.GetOptionByName(o.OutputOpt.Value, options).Value,
		FileName:   "",
	}
}

func (fp *JsonFileProvider) Write(result types.Result) error {
	var filename string


	_, ok := result.Data.([]types.EnrichedResourceDescription)
	if !ok {
		// Skip if not the correct type
		logs.ConsoleLogger().Info("Result is not of JSON type")
		return nil
	}

	if result.Filename == "" {
		filename = fp.DefaultFileName(result.Module)
	} else {
		filename = result.Filename
	}
	fullpath := GetFullPath(filename, fp.OutputPath)
	dir := filepath.Dir(fullpath)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	file, err := os.Create(fullpath)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(result)
	if err != nil {
		return err
	}

	logs.ConsoleLogger().Info("Output written", "path", fullpath)

	return nil
}

func (fp *JsonFileProvider) DefaultFileName(prefix string) string {
	return DefaultFileName(prefix, "json")
}
