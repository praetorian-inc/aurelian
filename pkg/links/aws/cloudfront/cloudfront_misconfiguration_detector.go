package cloudfront

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type CloudFrontMisconfigurationDetector struct {
	*base.AwsReconLink
	httpClient *http.Client
}

type SecurityFinding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Domain      string `json:"domain,omitempty"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

func NewCloudFrontMisconfigurationDetector(configs ...cfg.Config) chain.Link {
	detector := &CloudFrontMisconfigurationDetector{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
	detector.AwsReconLink = base.NewAwsReconLink(detector, configs...)
	return detector
}

func (c *CloudFrontMisconfigurationDetector) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::CloudFront::Distribution" {
		slog.Debug("Skipping non-CloudFront distribution", "resource", resource.TypeName)
		return nil
	}

	// CloudFront is a global service, always use us-east-1
	region := "us-east-1"
	if resource.Region != "" {
		region = resource.Region
	}

	config, err := c.GetConfigWithRuntimeArgs(region)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", region, err)
	}

	client := cloudfront.NewFromConfig(config)

	distributionID := resource.Identifier
	slog.Info("Analyzing CloudFront distribution for misconfigurations", "distribution_id", distributionID)

	distribution, err := c.getDistributionConfig(client, distributionID)
	if err != nil {
		slog.Error("Failed to get distribution config", "distribution_id", distributionID, "error", err)
		return nil
	}

	findings := c.detectMisconfigurations(distribution)

	// Add findings to the resource properties
	if len(findings) > 0 {
		if resource.Properties == nil {
			resource.Properties = make(map[string]any)
		}

		// Convert properties to map if it's not already
		props, ok := resource.Properties.(map[string]any)
		if !ok {
			props = make(map[string]any)
			resource.Properties = props
		}

		// Add findings to properties
		props["SecurityFindings"] = findings
		props["HasSecurityFindings"] = true
		props["FindingsCount"] = len(findings)

		// Log the findings
		for _, finding := range findings {
			slog.Info("CloudFront security finding detected",
				"distribution_id", distributionID,
				"type", finding.Type,
				"severity", finding.Severity,
				"domain", finding.Domain,
				"description", finding.Description)
		}
	}

	// Send the enriched resource with findings
	return c.Send(resource)
}

func (c *CloudFrontMisconfigurationDetector) getDistributionConfig(client *cloudfront.Client, distributionID string) (*cloudfronttypes.Distribution, error) {
	input := &cloudfront.GetDistributionInput{
		Id: &distributionID,
	}

	result, err := client.GetDistribution(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution: %w", err)
	}

	return result.Distribution, nil
}

func (c *CloudFrontMisconfigurationDetector) detectMisconfigurations(distribution *cloudfronttypes.Distribution) []SecurityFinding {
	var findings []SecurityFinding

	if distribution.DistributionConfig == nil {
		return findings
	}

	config := distribution.DistributionConfig

	findings = append(findings, c.checkDomainMisconfigurations(config)...)
	findings = append(findings, c.checkSSLConfiguration(config)...)
	findings = append(findings, c.checkOriginSecurity(config)...)
	findings = append(findings, c.checkAccessControlConfiguration(config)...)
	findings = append(findings, c.checkProtocolSecurity(config)...)

	return findings
}

func (c *CloudFrontMisconfigurationDetector) checkDomainMisconfigurations(config *cloudfronttypes.DistributionConfig) []SecurityFinding {
	var findings []SecurityFinding

	if config.Aliases == nil || config.Aliases.Items == nil {
		return findings
	}

	for _, alias := range config.Aliases.Items {
		domain := alias

		httpResp, httpErr := c.testHTTPEndpoint("http://" + domain)
		_, httpsErr := c.testHTTPEndpoint("https://" + domain)

		if httpErr != nil && strings.Contains(httpErr.Error(), "403") && strings.Contains(httpErr.Error(), "Bad request") {
			if httpsErr != nil && (strings.Contains(httpsErr.Error(), "handshake") || strings.Contains(httpsErr.Error(), "certificate")) {
				findings = append(findings, SecurityFinding{
					Type:        "dangling_cname",
					Severity:    "high",
					Domain:      domain,
					Description: fmt.Sprintf("Domain %s appears to have a dangling CNAME record pointing to CloudFront", domain),
					Evidence:    fmt.Sprintf("HTTP: %v, HTTPS: %v", httpErr, httpsErr),
				})
			}
		}

		if httpResp != nil && httpResp.StatusCode == 403 {
			body := make([]byte, 1024)
			httpResp.Body.Read(body)
			httpResp.Body.Close()
			if strings.Contains(string(body), "Bad request") {
				findings = append(findings, SecurityFinding{
					Type:        "potential_takeover",
					Severity:    "high",
					Domain:      domain,
					Description: fmt.Sprintf("Domain %s returns CloudFront 403 Bad Request error, indicating potential subdomain takeover vulnerability", domain),
					Evidence:    "HTTP 403 response with 'Bad request' message from CloudFront",
				})
			}
		}
	}

	return findings
}

func (c *CloudFrontMisconfigurationDetector) testHTTPEndpoint(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	return resp, err
}

func (c *CloudFrontMisconfigurationDetector) checkSSLConfiguration(config *cloudfronttypes.DistributionConfig) []SecurityFinding {
	var findings []SecurityFinding

	if config.ViewerCertificate == nil {
		return findings
	}

	cert := config.ViewerCertificate

	if cert.CloudFrontDefaultCertificate != nil && *cert.CloudFrontDefaultCertificate {
		findings = append(findings, SecurityFinding{
			Type:        "default_ssl_certificate",
			Severity:    "medium",
			Description: "Distribution is using CloudFront default SSL certificate instead of custom certificate",
			Evidence:    "ViewerCertificate.CloudFrontDefaultCertificate is true",
		})
	}

	if cert.MinimumProtocolVersion != "" {
		protocol := string(cert.MinimumProtocolVersion)
		if strings.Contains(protocol, "TLSv1_") || strings.Contains(protocol, "SSLv3") {
			findings = append(findings, SecurityFinding{
				Type:        "weak_ssl_protocol",
				Severity:    "high",
				Description: fmt.Sprintf("Distribution allows weak SSL/TLS protocol: %s", protocol),
				Evidence:    fmt.Sprintf("MinimumProtocolVersion: %s", protocol),
			})
		}
	}

	return findings
}

func (c *CloudFrontMisconfigurationDetector) checkOriginSecurity(config *cloudfronttypes.DistributionConfig) []SecurityFinding {
	var findings []SecurityFinding

	if config.Origins == nil || config.Origins.Items == nil {
		return findings
	}

	for _, origin := range config.Origins.Items {
		if origin.CustomOriginConfig != nil {
			customConfig := origin.CustomOriginConfig

			if customConfig.OriginProtocolPolicy == cloudfronttypes.OriginProtocolPolicyHttpOnly {
				findings = append(findings, SecurityFinding{
					Type:        "insecure_origin_protocol",
					Severity:    "medium",
					Description: fmt.Sprintf("Origin %s uses HTTP-only protocol, data transmitted in plain text", *origin.DomainName),
					Evidence:    "OriginProtocolPolicy is http-only",
				})
			}

			if customConfig.OriginSslProtocols != nil && customConfig.OriginSslProtocols.Items != nil {
				for _, protocol := range customConfig.OriginSslProtocols.Items {
					if protocol == cloudfronttypes.SslProtocolTLSv1 || protocol == cloudfronttypes.SslProtocolSSLv3 {
						findings = append(findings, SecurityFinding{
							Type:        "weak_origin_ssl",
							Severity:    "high",
							Description: fmt.Sprintf("Origin %s allows weak SSL protocol: %s", *origin.DomainName, string(protocol)),
							Evidence:    fmt.Sprintf("OriginSslProtocols contains %s", string(protocol)),
						})
					}
				}
			}
		}
	}

	return findings
}

func (c *CloudFrontMisconfigurationDetector) checkAccessControlConfiguration(config *cloudfronttypes.DistributionConfig) []SecurityFinding {
	var findings []SecurityFinding

	if config.Logging != nil && config.Logging.Enabled != nil && !*config.Logging.Enabled {
		findings = append(findings, SecurityFinding{
			Type:        "logging_disabled",
			Severity:    "medium",
			Description: "Access logging is disabled for CloudFront distribution",
			Evidence:    "Logging.Enabled is false",
		})
	}

	if config.WebACLId == nil || (config.WebACLId != nil && *config.WebACLId == "") {
		findings = append(findings, SecurityFinding{
			Type:        "no_waf_integration",
			Severity:    "medium",
			Description: "No AWS WAF integration configured for additional protection",
			Evidence:    "WebACLId is empty",
		})
	}

	return findings
}

func (c *CloudFrontMisconfigurationDetector) checkProtocolSecurity(config *cloudfronttypes.DistributionConfig) []SecurityFinding {
	var findings []SecurityFinding

	if config.DefaultCacheBehavior != nil {
		behavior := config.DefaultCacheBehavior

		if behavior.ViewerProtocolPolicy == cloudfronttypes.ViewerProtocolPolicyAllowAll {
			findings = append(findings, SecurityFinding{
				Type:        "insecure_viewer_protocol",
				Severity:    "medium",
				Description: "Distribution allows both HTTP and HTTPS traffic, potentially exposing sensitive data",
				Evidence:    "ViewerProtocolPolicy is allow-all",
			})
		}
	}

	if config.CacheBehaviors != nil && config.CacheBehaviors.Items != nil {
		for _, behavior := range config.CacheBehaviors.Items {
			if behavior.ViewerProtocolPolicy == cloudfronttypes.ViewerProtocolPolicyAllowAll {
				findings = append(findings, SecurityFinding{
					Type:        "insecure_cache_behavior",
					Severity:    "medium",
					Description: fmt.Sprintf("Cache behavior for path %s allows HTTP traffic", *behavior.PathPattern),
					Evidence:    "ViewerProtocolPolicy is allow-all for cache behavior",
				})
			}
		}
	}

	return findings
}