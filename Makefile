.PHONY: all clean aws azure all_modules build_all

# Default build directory
BIN_DIR := bin

# All available build tags
TAGS := aws aws_recon aws_recon_find_secrets aws_public_resources azure azure_recon azure_public_resources all

# Ensure the bin directory exists
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Build all modules
all: all_modules

# Build all modules with the 'all' tag
all_modules: $(BIN_DIR)
	go build -tags all -o $(BIN_DIR)/nebula main.go

# Build all sub-builds with each individual tag
build_all: $(BIN_DIR) $(TAGS)
	@echo "All builds completed successfully."

# Build AWS modules
aws: $(BIN_DIR)
	go build -tags aws -o $(BIN_DIR)/nebula-aws main.go

# Build AWS recon modules
aws_recon: $(BIN_DIR)
	go build -tags aws_recon -o $(BIN_DIR)/nebula-aws-recon main.go

# Build AWS recon find secrets module
aws_recon_find_secrets: $(BIN_DIR)
	go build -tags aws_recon_find_secrets -o $(BIN_DIR)/nebula-aws-find-secrets main.go

# Build AWS public resources module
aws_public_resources: $(BIN_DIR)
	go build -tags aws_public_resources -o $(BIN_DIR)/nebula-aws-public-resources main.go

# Build Azure modules
azure: $(BIN_DIR)
	go build -tags azure -o $(BIN_DIR)/nebula-azure main.go

# Build Azure recon modules
azure_recon: $(BIN_DIR)
	go build -tags azure_recon -o $(BIN_DIR)/nebula-azure-recon main.go

# Build Azure public resources module
azure_public_resources: $(BIN_DIR)
	go build -tags azure_public_resources -o $(BIN_DIR)/nebula-azure-public-resources main.go

# Clean the build directory
clean:
	rm -rf $(BIN_DIR)