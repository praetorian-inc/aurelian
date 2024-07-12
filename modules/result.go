package modules

import (
	"encoding/json"
)

type Result struct {
	Platform Platform    `json:"platform"`
	Module   string      `json:"module"`
	Data     interface{} `json:"data"`
}

func (r *Result) String() string {
	d, _ := json.Marshal(r)
	return string(d)
}

func (r *Result) Json() []byte {
	d, _ := json.Marshal(r)
	return d
}
