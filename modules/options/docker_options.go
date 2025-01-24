package options

import "github.com/praetorian-inc/nebula/pkg/types"

var DockerUserOpt = types.Option{
	Name:        "docker-user",
	Description: "Docker registry username",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var DockerPasswordOpt = types.Option{
	Name:        "docker-password",
	Description: "Docker registry password",
	Required:    false,
	Type:        types.String,
	Value:       "",
}
