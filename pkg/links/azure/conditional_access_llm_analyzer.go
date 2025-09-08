package azure

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type PolicyDescriptionXML struct {
	ID          string `xml:"id"`
	Name        string `xml:"name"`
	Description string `xml:"description"`
}

type ObservationXML struct {
	Type             string `xml:"type"`
	Confidence       string `xml:"confidence"`
	Title            string `xml:"title"`
	Description      string `xml:"description"`
	TechnicalDetails string `xml:"technical_details"`
	PotentialImpact  string `xml:"potential_impact"`
	ExploitScenario  string `xml:"exploit_scenario"`
}

type AnalysisXML struct {
	PolicyDescriptions []PolicyDescriptionXML `xml:"policy_descriptions>policy"`
	Observations       []ObservationXML       `xml:"security_analysis>observations_detected>observation"`
}

type ConditionalAccessAnalysisResult struct {
	PolicySetID          string                 `json:"policy_set_id"`
	AnalysisTimestamp    string                 `json:"analysis_timestamp"`
	LLMProvider          string                 `json:"llm_provider"`
	PoliciesAnalyzed     int                    `json:"policies_analyzed"`
	PolicyDescriptions   []PolicyDescriptionXML `json:"policy_descriptions"`
	ObservationsDetected []ObservationXML       `json:"observations_detected"`
	OverallRiskLevel     string                 `json:"overall_risk_level"`
	Recommendations      []string               `json:"recommendations"`
}

type AzureConditionalAccessLLMAnalyzer struct {
	*chain.Base
}

type LLMRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLMResponse struct {
	Content []Content `json:"content"`
}

type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func NewAzureConditionalAccessLLMAnalyzer(configs ...cfg.Config) chain.Link {
	l := &AzureConditionalAccessLLMAnalyzer{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureConditionalAccessLLMAnalyzer) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureLLMAPIKey(),
		options.AzureLLMProvider(),
		options.AzureLLMModel(),
	}
}

func (l *AzureConditionalAccessLLMAnalyzer) Process(input any) error {
	var policies []EnrichedConditionalAccessPolicy

	// Handle both single policy and array of policies
	switch v := input.(type) {
	case EnrichedConditionalAccessPolicy:
		policies = []EnrichedConditionalAccessPolicy{v}
	case []EnrichedConditionalAccessPolicy:
		policies = v
	default:
		return fmt.Errorf("expected EnrichedConditionalAccessPolicy or []EnrichedConditionalAccessPolicy, got %T", input)
	}

	if len(policies) == 0 {
		return fmt.Errorf("no policies to analyze")
	}

	apiKey, err := cfg.As[string](l.Arg("llm-api-key"))
	if err != nil || apiKey == "" {
		return fmt.Errorf("LLM API key is required")
	}

	provider, err := cfg.As[string](l.Arg("llm-provider"))
	if err != nil {
		provider = "anthropic"
	}

	model, err := cfg.As[string](l.Arg("llm-model"))
	if err != nil {
		model = "claude-opus-4-20250514"
	}

	analysisResult, err := l.analyzePolicySet(policies, apiKey, provider, model)
	if err != nil {
		return fmt.Errorf("failed to analyze policy set: %w", err)
	}

	return l.Send(analysisResult)
}

func (l *AzureConditionalAccessLLMAnalyzer) analyzePolicySet(policies []EnrichedConditionalAccessPolicy, apiKey, provider, model string) (ConditionalAccessAnalysisResult, error) {
	if provider != "anthropic" {
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("unsupported LLM provider: %s (only 'anthropic' is supported)", provider)
	}
	policySetJSON, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("failed to marshal policy set: %w", err)
	}

	prompt := l.buildAnalysisPrompt(string(policySetJSON), len(policies))

	llmReq := LLMRequest{
		Model:     model,
		MaxTokens: 16000,
		Messages: []Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	// Debug logging for request (sanitized)
	sanitizedReq := LLMRequest{
		Model:     llmReq.Model,
		MaxTokens: llmReq.MaxTokens,
		Messages: []Message{
			{
				Role:    llmReq.Messages[0].Role,
				Content: fmt.Sprintf("[CONTENT_LENGTH: %d characters]", len(llmReq.Messages[0].Content)),
			},
		},
	}
	l.Logger.Debug("Sending request to LLM provider", "provider", provider, "model", model, "request_structure", sanitizedReq)

	reqBody, err := json.Marshal(llmReq)
	if err != nil {
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	llmURL := "https://api.anthropic.com/v1/messages"
	req, err := http.NewRequestWithContext(l.Context(), http.MethodPost, llmURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("failed to call LLM API (%s): %w", provider, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes := make([]byte, 4096)
		n, _ := resp.Body.Read(bodyBytes)
		bodySnippet := string(bodyBytes[:n])
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("LLM API (%s) status %d: %s", provider, resp.StatusCode, bodySnippet)
	}

	var llmResp LLMResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(llmResp.Content) == 0 {
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("empty response from LLM API (%s)", provider)
	}

	analysisText := llmResp.Content[0].Text

	// Debug logging for response
	l.Logger.Debug("Raw LLM response received", "provider", provider, "model", model, "response_length", len(analysisText), "raw_response", analysisText)

	// Parse XML response
	var xmlResponse AnalysisXML
	if err := xml.Unmarshal([]byte(analysisText), &xmlResponse); err != nil {
		previewLen := 200
		if len(analysisText) < previewLen {
			previewLen = len(analysisText)
		}
		l.Logger.Debug("XML parsing failed", "provider", provider, "error", err.Error(), "response_preview", analysisText[:previewLen])
		return ConditionalAccessAnalysisResult{}, fmt.Errorf("failed to parse XML response from LLM provider %s: %w", provider, err)
	}

	// Convert XML to result structure
	analysisResult := ConditionalAccessAnalysisResult{
		PolicySetID:          fmt.Sprintf("policy-set-%d", time.Now().Unix()),
		AnalysisTimestamp:    time.Now().Format(time.RFC3339),
		LLMProvider:          provider,
		PoliciesAnalyzed:     len(policies),
		PolicyDescriptions:   xmlResponse.PolicyDescriptions,
		ObservationsDetected: xmlResponse.Observations,
		OverallRiskLevel:     "Unknown",  // TODO: Parse from XML if added to prompt
		Recommendations:      []string{}, // TODO: Parse from XML if added to prompt
	}

	return analysisResult, nil
}

func (l *AzureConditionalAccessLLMAnalyzer) buildAnalysisPrompt(policySetJSON string, policyCount int) string {
	return fmt.Sprintf(`
<main_role>
You are a cybersecurity expert analyzing a complete set of Azure Conditional Access policies for security vulnerabilities and configuration gaps.
You are analyzing Conditional Access policies as a cohesive security system. Focus on how these policies work together, identify gaps between policies, and look for security vulnerabilities that emerge from policy interactions.

1. Read the web articles linked for ideas on potential abuse cases
2. Read each policy one at a time and understand what each policy does 
3. Analyze all policies as an interconnected security control due to the conditional access policy evaluation logic highlighted in the conditional_access_policy_evaluation_logic section

CRITICAL RESTRICTIONS:
- NEVER hallucinate vulnerabilities or discoveries
- NEVER hallucinate if a tool returned no results, report actual findings
- ALWAYS check for false positives as other conditional access policies may prevent the gap you have identified in an earlier conditional access policy
</main_role>

<related_web_articles>
* https://trustedsec.com/blog/common-conditional-access-misconfigurations-and-bypasses-in-azure
* https://practical365.com/five-most-common-conditional-access-misconfigurations/
* https://cloudsecurityalliance.org/blog/2023/11/30/microsoft-365-and-azure-ad-addressing-misconfigurations-and-access-risks/
* https://www.mantra.ms/blog/how-hackers-bypass-microsoft-azure-ad-conditional-access
* https://cloudbrothers.info/en/protect-users-device-code-flow-abuse/
* https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/
* https://jeffreyappel.nl/how-to-protect-against-device-code-flow-abuse-storm-2372-attacks-and-block-the-authentication-flow/
* https://www.obsidiansecurity.com/blog/behind-the-breach-mfa
* https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
* https://blog.nviso.eu/2024/02/27/top-things-that-you-might-not-be-doing-yet-in-entra-conditional-access/
* https://msrc.microsoft.com/blog/2023/03/guidance-on-potential-misconfiguration-of-authorization-of-multi-tenant-applications-that-use-azure-ad/
</related_web_articles>

<conditional_access_policies_json>
%s
</conditional_access_policies_json>

<conditional_access_policy_evaluation_logic>
* Multiple Conditional Access policies can apply to an individual user at any time.
* In this case, all applicable policies must be satisfied. For example, if one policy requires multifactor authentication and another requires a compliant device, you must complete MFA, and use a compliant device. All assignments are logically combined using AND.
* If you have more than one assignment configured, all assignments must be satisfied to trigger a policy.
* Administrators choose to require one of the previous controls or all selected controls using the following options. By default, multiple controls require all.
	* Require all the selected controls (control and control)
	* Require one of the selected controls (control or control
</conditional_access_policy_evaluation_logic>

<policy_analysis_logic>
CRITICAL: Analyze these policies as an interdependent system, not individually.

Key areas of coverage include but are not limited to:
1. **Policy Interactions & Conflicts**: Look for policies that contradict each other or create unintended access paths
2. **Coverage Gaps**: Identify user groups, applications, or conditions not adequately covered by the policy set
3. **Legacy Authentication Bypass**: Find ways legacy protocols could bypass the overall policy framework
4. **MFA & Device Compliance Gaps**: Identify scenarios where MFA or device compliance isn't enforced
5. **Privilege Escalation Paths**: Look for policy combinations that allow escalation of access
6. **Exclusion Analysis**: Analyze if excluded users/groups/applications create security risks
7. **Conditional Logic Flaws**: Find logical inconsistencies in policy conditions and controls
</policy_analysis_logic>

<false_positive>
ALWAYS triple check your analysis and ensure there are no false positives. Use the conditional_access_policy_evaluation_logic to validate your findings.
</false_positive>

<output_format>
Provide your summary and analysis in the following XML format. DO NOT return anything except the XML structure (no markdown, no code blocks).

 <analysis>
    <policy_descriptions>
      <policy>
        <id>policy-id-here</id>
        <name>Display Name</name>
        <description>Clear natural language explanation of what this policy does, who it affects, and what controls it enforces</description>
      </policy>
      <!-- Repeat for each policy -->
    </policy_descriptions>

    <security_analysis>
      <observations_detected>
        <observation>
          <type>coverage-gap</type>
          <confidence>percentage representing confidence that this issue is valid</confidence>
          <title>Brief title of the gap</title>
          <description>Detailed description of the security gap</description>
          <technical_details>Technical explanation of the observation</technical_details>
		  <potential_impact>Impact assessment if an attacker carries out the exploit scenario</potential_impact>
          <exploit_scenario>Step-by-step exploitation scenario</exploit_scenario>
        </observation>
		<!-- Repeat for each observations -->
      </observations_detected>
    </security_analysis>
  </analysis>
</output_format>
`, policyCount, policySetJSON)
}
