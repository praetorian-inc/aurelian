package enrichers

import (
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("redis_cache_public_access", enrichRedisCache)
}

func enrichRedisCache(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	resourceName := result.ResourceName
	if resourceName == "" {
		return nil, nil
	}

	var hostname string
	if h, ok := result.Properties["hostname"].(string); ok {
		hostname = h
	} else {
		hostname = resourceName + ".redis.cache.windows.net"
	}

	var cmds []plugin.AzureEnrichmentCommand

	// Test SSL port 6380
	sslCmd := TCPProbe(hostname, 6380, 10*time.Second)
	sslCmd.Description = "Test TCP connectivity to Redis SSL port 6380"
	sslCmd.ExpectedOutputDescription = "Connection succeeded = accessible | Connection failed/timeout = blocked/unreachable"
	cmds = append(cmds, sslCmd)

	// Test non-SSL port 6379 if enabled
	enableNonSslPort, _ := result.Properties["enableNonSslPort"].(bool)
	if enableNonSslPort {
		nonSslCmd := TCPProbe(hostname, 6379, 10*time.Second)
		nonSslCmd.Description = "Test TCP connectivity to Redis non-SSL port 6379"
		nonSslCmd.ExpectedOutputDescription = "Connection succeeded = accessible | Connection failed/timeout = blocked/unreachable"
		cmds = append(cmds, nonSslCmd)
	}

	return cmds, nil
}
