package docker

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	dockerTypes "github.com/praetorian-inc/janus-framework/pkg/types/docker"
)

func DockerExtractDomain(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %v", err)
	}
	return parsedURL.Host, nil
}

var dockerClientIsTooNew = regexp.MustCompile(`client version (\d[\d\.]+) is too new\. Maximum supported API version is (\d[\d\.]+)`)

func NewUnauthenticatedClient(ctx context.Context, opts ...client.Opt) (*client.Client, error) {
	return unauthenciated(ctx, true, opts...)
}

func unauthenciated(ctx context.Context, retry bool, opts ...client.Opt) (*client.Client, error) {
	dockerClient, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	_, err = dockerClient.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		dockerClient.Close()

		matches := dockerClientIsTooNew.FindStringSubmatch(err.Error())
		if len(matches) == 3 && retry {
			slog.Debug("retrying with Docker API version", "version", matches[2])
			return unauthenciated(ctx, false, client.WithVersion(matches[2]))
		}
		return nil, err
	}

	return dockerClient, nil
}

func NewAuthenticatedClient(ctx context.Context, imageContext dockerTypes.DockerImage, opts ...client.Opt) (*client.Client, error) {
	return authenticate(ctx, imageContext, true, opts...)
}

func authenticate(ctx context.Context, imageContext dockerTypes.DockerImage, retry bool, opts ...client.Opt) (*client.Client, error) {
	dockerClient, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	_, err = dockerClient.RegistryLogin(ctx, imageContext.AuthConfig)

	errString := ""
	if err != nil {
		errString = err.Error()
	}

	matches := dockerClientIsTooNew.FindStringSubmatch(errString)
	if len(matches) == 3 && retry {
		dockerClient.Close()

		maximumSupportedVersion := matches[2]
		slog.Debug("retrying with Docker API version", "version", maximumSupportedVersion)
		return authenticate(ctx, imageContext, false, client.WithVersion(maximumSupportedVersion))
	}

	if err != nil {
		return nil, err
	}

	return dockerClient, nil
}

func removeImage(ctx context.Context, dockerClient *client.Client, imageID string) {
	_, err := dockerClient.ImageRemove(ctx, imageID, image.RemoveOptions{Force: true})
	if err != nil {
		slog.Error("failed to remove image", slog.String("containerId", imageID), slog.String("error", err.Error()))
	}
}