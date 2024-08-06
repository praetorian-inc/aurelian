package outputproviders

import (
	"os"
	"strconv"
	"time"

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

func (fp *FileProvider) Write(result modules.Result) error {
	if _, err := os.Stat(fp.OutputPath); os.IsNotExist(err) {
		err := os.MkdirAll(fp.OutputPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	file, err := os.Create(fp.GetFulfpath())
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(result.String())
	if err != nil {
		return err
	}

	logs.ConsoleLogger().Info("Output written", "path", fp.GetFulfpath())

	return nil
}

func (fp *FileProvider) GetFulfpath() string {
	return fp.OutputPath + string(os.PathSeparator) + fp.FileName
}

func DefaultFileName(prefix string) string {
	return prefix + "-" + strconv.FormatInt(time.Now().Unix(), 10) + ".json"
}
