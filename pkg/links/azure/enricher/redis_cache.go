package enricher

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// RedisCacheEnricher implements enrichment for Redis Cache instances
type RedisCacheEnricher struct{}

func (r *RedisCacheEnricher) CanEnrich(templateID string) bool {
	return templateID == "redis_cache_public_access"
}

func (r *RedisCacheEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Redis hostname
	var hostname string
	if hostnameProp, exists := resource.Properties["hostname"].(string); exists {
		hostname = hostnameProp
	} else {
		hostname = resource.Name + ".redis.cache.windows.net"
	}

	// Check if non-SSL port is enabled
	enableNonSslPort, _ := resource.Properties["enableNonSslPort"].(bool)

	if hostname == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Redis Cache hostname",
			ActualOutput: "Error: Redis hostname is empty",
		})
		return commands
	}

	// Test 1: TCP connection to SSL port (6380)
	sslPort := "6380"
	conn, err := net.DialTimeout("tcp", hostname+":"+sslPort, 10*time.Second)

	sslConnCommand := Command{
		Command:                   fmt.Sprintf("nc -zv %s %s", hostname, sslPort),
		Description:               "Test TCP connectivity to Redis SSL port 6380",
		ExpectedOutputDescription: "Connection succeeded = accessible | Connection failed/timeout = blocked/unreachable",
	}

	if err != nil {
		sslConnCommand.Error = err.Error()
		sslConnCommand.ActualOutput = fmt.Sprintf("Connection failed: %s", err.Error())
		sslConnCommand.ExitCode = 1
	} else {
		conn.Close()
		sslConnCommand.ActualOutput = "Connection successful"
		sslConnCommand.ExitCode = 0
	}

	commands = append(commands, sslConnCommand)

	// Test 2: TCP connection to non-SSL port (6379) if enabled
	if enableNonSslPort {
		nonSslPort := "6379"
		conn2, err2 := net.DialTimeout("tcp", hostname+":"+nonSslPort, 10*time.Second)

		nonSslConnCommand := Command{
			Command:                   fmt.Sprintf("nc -zv %s %s", hostname, nonSslPort),
			Description:               "Test TCP connectivity to Redis non-SSL port 6379",
			ExpectedOutputDescription: "Connection succeeded = accessible | Connection failed/timeout = blocked/unreachable",
		}

		if err2 != nil {
			nonSslConnCommand.Error = err2.Error()
			nonSslConnCommand.ActualOutput = fmt.Sprintf("Connection failed: %s", err2.Error())
			nonSslConnCommand.ExitCode = 1
		} else {
			conn2.Close()
			nonSslConnCommand.ActualOutput = "Connection successful"
			nonSslConnCommand.ExitCode = 0
		}

		commands = append(commands, nonSslConnCommand)
	}

	redisCommand := fmt.Sprintf("redis-cli -h %s -p %s --tls -a '%s' ping", hostname, sslPort, "AZURE_REDIS_CACHE_ACCESS_KEY")
	description := "Test Redis PING command with access key"

	redisTestCommand := Command{
		Command:                   redisCommand,
		Description:               description,
		ExpectedOutputDescription: "PONG = authentication successful | WRONGPASS/NOAUTH = authentication required | Connection error = network/access issue",
		ActualOutput:              "Manual execution required - requires redis-cli tool",
	}

	commands = append(commands, redisTestCommand)

	return commands
}
