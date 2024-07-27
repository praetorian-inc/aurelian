package outputproviders

import (
	"os"

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type FileProvider struct {
	modules.OutputProvider
	OutputPath string
	FileName   string
}

func NewFileProvider(options []*o.Option) modules.OutputProvider {
	return &FileProvider{
		OutputPath: o.GetOptionByName(o.OutputOpt.Name, options).Value,
		FileName:   o.GetOptionByName(o.FileNameOpt.Name, options).Value,
	}
}

func (lp *FileProvider) Write(result modules.Result) error {
	file, err := os.Create(lp.GetFullPath())
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(result.String())
	if err != nil {
		return err
	}

	logs.ConsoleLogger().Info("Output written", "path", lp.GetFullPath())

	return nil
}

func (lp *FileProvider) GetFullPath() string {
	return lp.OutputPath + string(os.PathSeparator) + lp.FileName
}
