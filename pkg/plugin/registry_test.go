package plugin

import (
	"fmt"
	"testing"
)

// mockModule is a test implementation of the Module interface
type mockModule struct {
	id          string
	name        string
	description string
	platform    Platform
	category    Category
	opsecLevel  string
	authors     []string
	references  []string
	parameters  []Parameter
}

func (m *mockModule) ID() string                { return m.id }
func (m *mockModule) Name() string              { return m.name }
func (m *mockModule) Description() string       { return m.description }
func (m *mockModule) Platform() Platform        { return m.platform }
func (m *mockModule) Category() Category        { return m.category }
func (m *mockModule) OpsecLevel() string        { return m.opsecLevel }
func (m *mockModule) Authors() []string         { return m.authors }
func (m *mockModule) References() []string      { return m.references }
func (m *mockModule) Parameters() []Parameter   { return m.parameters }
func (m *mockModule) Run(cfg Config) ([]Result, error) {
	return []Result{{Data: "test"}}, nil
}

func TestRegister(t *testing.T) {
	// Create a fresh registry for testing
	Registry = &registry{
		modules:   make(map[string]RegistryEntry),
		hierarchy: make(map[Platform]map[Category][]string),
	}

	module := &mockModule{
		id:          "test-module",
		name:        "Test Module",
		description: "A test module",
		platform:    PlatformAWS,
		category:    CategoryRecon,
		opsecLevel:  "stealth",
		authors:     []string{"Test Author"},
		references:  []string{"https://example.com"},
		parameters:  []Parameter{},
	}

	Register(module)

	// Verify registration
	if Count() != 1 {
		t.Errorf("Expected 1 registered module, got %d", Count())
	}

	// Verify retrieval
	retrieved, ok := Get(PlatformAWS, CategoryRecon, "test-module")
	if !ok {
		t.Fatal("Failed to retrieve registered module")
	}

	if retrieved.ID() != "test-module" {
		t.Errorf("Expected module ID 'test-module', got '%s'", retrieved.ID())
	}
}

func TestRegisterDuplicate(t *testing.T) {
	// Create a fresh registry for testing
	Registry = &registry{
		modules:   make(map[string]RegistryEntry),
		hierarchy: make(map[Platform]map[Category][]string),
	}

	module := &mockModule{
		id:       "duplicate",
		platform: PlatformAWS,
		category: CategoryRecon,
	}

	Register(module)

	// Attempt to register duplicate should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when registering duplicate module")
		}
	}()

	Register(module)
}

func TestGetNonExistent(t *testing.T) {
	// Create a fresh registry for testing
	Registry = &registry{
		modules:   make(map[string]RegistryEntry),
		hierarchy: make(map[Platform]map[Category][]string),
	}

	_, ok := Get(PlatformAWS, CategoryRecon, "nonexistent")
	if ok {
		t.Error("Expected false when retrieving nonexistent module")
	}
}

func TestGetHierarchy(t *testing.T) {
	// Create a fresh registry for testing
	Registry = &registry{
		modules:   make(map[string]RegistryEntry),
		hierarchy: make(map[Platform]map[Category][]string),
	}

	// Register multiple modules
	modules := []*mockModule{
		{id: "aws-recon-1", platform: PlatformAWS, category: CategoryRecon},
		{id: "aws-recon-2", platform: PlatformAWS, category: CategoryRecon},
		{id: "aws-analyze-1", platform: PlatformAWS, category: CategoryAnalyze},
		{id: "azure-recon-1", platform: PlatformAzure, category: CategoryRecon},
	}

	for _, m := range modules {
		Register(m)
	}

	hierarchy := GetHierarchy()

	// Verify AWS recon has 2 modules
	awsRecon := hierarchy[PlatformAWS][CategoryRecon]
	if len(awsRecon) != 2 {
		t.Errorf("Expected 2 AWS recon modules, got %d", len(awsRecon))
	}

	// Verify AWS analyze has 1 module
	awsAnalyze := hierarchy[PlatformAWS][CategoryAnalyze]
	if len(awsAnalyze) != 1 {
		t.Errorf("Expected 1 AWS analyze module, got %d", len(awsAnalyze))
	}

	// Verify Azure recon has 1 module
	azureRecon := hierarchy[PlatformAzure][CategoryRecon]
	if len(azureRecon) != 1 {
		t.Errorf("Expected 1 Azure recon module, got %d", len(azureRecon))
	}

	// Verify total count
	if Count() != 4 {
		t.Errorf("Expected 4 total modules, got %d", Count())
	}
}

func TestCount(t *testing.T) {
	// Create a fresh registry for testing
	Registry = &registry{
		modules:   make(map[string]RegistryEntry),
		hierarchy: make(map[Platform]map[Category][]string),
	}

	if Count() != 0 {
		t.Errorf("Expected 0 modules in empty registry, got %d", Count())
	}

	Register(&mockModule{id: "test1", platform: PlatformAWS, category: CategoryRecon})
	if Count() != 1 {
		t.Errorf("Expected 1 module after first registration, got %d", Count())
	}

	Register(&mockModule{id: "test2", platform: PlatformAWS, category: CategoryRecon})
	if Count() != 2 {
		t.Errorf("Expected 2 modules after second registration, got %d", Count())
	}
}

func TestThreadSafety(t *testing.T) {
	// Create a fresh registry for testing
	Registry = &registry{
		modules:   make(map[string]RegistryEntry),
		hierarchy: make(map[Platform]map[Category][]string),
	}

	// Test concurrent registration
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			module := &mockModule{
				id:       fmt.Sprintf("concurrent-%d", id),
				platform: PlatformAWS,
				category: CategoryRecon,
			}
			Register(module)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	if Count() != 10 {
		t.Errorf("Expected 10 modules after concurrent registration, got %d", Count())
	}
}
