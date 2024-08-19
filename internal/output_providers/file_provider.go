package outputproviders

import (
	"os"
	"path/filepath"
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
		OutputPath: o.GetOptionByName(o.OutputOpt.Value, options).Value,
		FileName:   "",
	}
}

func (fp *FileProvider) Write(result modules.Result) error {
	var filename string

	if result.Filename == "" {
		filename = DefaultFileName(result.Module)
	} else {
		filename = result.Filename
	}
	fullpath := fp.GetFulfpath(filename)
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

	_, err = file.WriteString(result.String())
	if err != nil {
		return err
	}

	logs.ConsoleLogger().Info("Output written", "path", fullpath)

	return nil
}

func (fp *FileProvider) GetFulfpath(filename string) string {
	return fp.OutputPath + string(os.PathSeparator) + filename
}

func DefaultFileName(prefix string) string {
	return prefix + "-" + strconv.FormatInt(time.Now().Unix(), 10) + ".json"
}
