package aws

import "strings"

type Action string

func (a *Action) Service() string {
	split := strings.Split(string(*a), ":")
	if len(split) != 2 {
		return ""
	}
	return split[0]
}
