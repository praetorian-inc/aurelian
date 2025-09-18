package docker

import (
	"testing"

	"github.com/docker/docker/api/types/registry"
	dockerTypes "github.com/praetorian-inc/janus-framework/pkg/types/docker"
)

func TestDockerImageLoader_createImageContext(t *testing.T) {
	tests := []struct {
		name      string
		imageName string
		expected  dockerTypes.DockerImage
	}{
		{
			name:      "simple image no tag",
			imageName: "nginx",
			expected: dockerTypes.DockerImage{
				Image: "nginx",
			},
		},
		{
			name:      "simple image with tag",
			imageName: "nginx:1.20",
			expected: dockerTypes.DockerImage{
				Image: "nginx:1.20",
			},
		},
		{
			name:      "dockerhub org image no tag",
			imageName: "library/nginx",
			expected: dockerTypes.DockerImage{
				Image: "library/nginx",
			},
		},
		{
			name:      "dockerhub org image with tag",
			imageName: "library/nginx:alpine",
			expected: dockerTypes.DockerImage{
				Image: "library/nginx:alpine",
			},
		},
		{
			name:      "private registry domain no tag",
			imageName: "registry.company.com/myapp",
			expected: dockerTypes.DockerImage{
				Image:      "myapp",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://registry.company.com",
				},
			},
		},
		{
			name:      "private registry with org and tag",
			imageName: "registry.company.com/backend/api:v2.1.0",
			expected: dockerTypes.DockerImage{
				Image:      "backend/api:v2.1.0",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://registry.company.com",
				},
			},
		},
		{
			name:      "with digest",
			imageName: "nginx@sha256:abc123def456789012345678901234567890123456789012345678901234567890",
			expected: dockerTypes.DockerImage{
				Image: "nginx@sha256:abc123def456789012345678901234567890123456789012345678901234567890",
			},
		},
		{
			name:      "registry with digest",
			imageName: "registry.company.com/nginx@sha256:abc123def456789012345678901234567890123456789012345678901234567890",
			expected: dockerTypes.DockerImage{
				Image:      "nginx@sha256:abc123def456789012345678901234567890123456789012345678901234567890",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://registry.company.com",
				},
			},
		},
		{
			name:      "ECR private registry",
			imageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-web-app",
			expected: dockerTypes.DockerImage{
				Image:      "my-web-app",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://123456789012.dkr.ecr.us-east-1.amazonaws.com",
				},
			},
		},
		{
			name:      "ECR private registry with tag",
			imageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-web-app:production",
			expected: dockerTypes.DockerImage{
				Image:      "my-web-app:production",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://123456789012.dkr.ecr.us-east-1.amazonaws.com",
				},
			},
		},
		{
			name:      "ECR public registry",
			imageName: "public.ecr.aws/nginx/nginx-unprivileged",
			expected: dockerTypes.DockerImage{
				Image:      "nginx/nginx-unprivileged",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://public.ecr.aws",
				},
			},
		},
		{
			name:      "Google Container Registry",
			imageName: "gcr.io/my-project/web-service",
			expected: dockerTypes.DockerImage{
				Image:      "my-project/web-service",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://gcr.io",
				},
			},
		},
		{
			name:      "Azure Container Registry",
			imageName: "company.azurecr.io/backend/api",
			expected: dockerTypes.DockerImage{
				Image:      "backend/api",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://company.azurecr.io",
				},
			},
		},
		{
			name:      "Quay registry",
			imageName: "quay.io/prometheus/prometheus:v2.30.0",
			expected: dockerTypes.DockerImage{
				Image:      "prometheus/prometheus:v2.30.0",
				AuthConfig: registry.AuthConfig{
					ServerAddress: "https://quay.io",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dl := NewDockerImageLoader().(*DockerImageLoader)

			result := dl.createImageContext(tt.imageName)

			if result.Image != tt.expected.Image {
				t.Errorf("createImageContext(%q).Image = %q, want %q", 
					tt.imageName, result.Image, tt.expected.Image)
			}

			if result.AuthConfig.ServerAddress != tt.expected.AuthConfig.ServerAddress {
				t.Errorf("createImageContext(%q).AuthConfig.ServerAddress = %q, want %q", 
					tt.imageName, result.AuthConfig.ServerAddress, tt.expected.AuthConfig.ServerAddress)
			}
		})
	}
}
