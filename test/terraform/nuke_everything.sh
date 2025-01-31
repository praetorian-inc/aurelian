
#!/bin/bash

# Function to delete a resource group
delete_resource_group() {
    local rg_name="$1"
    echo "Deleting resource group: $rg_name"
    az group delete --name "$rg_name" --yes --no-wait
}

# Confirm before proceeding
read -p "WARNING: This will delete ALL resource groups in the current subscription. Are you absolutely sure? (yes/no): " confirm

# Validate confirmation
if [[ "$confirm" != "yes" ]]; then
    echo "Operation cancelled."
    exit 1
fi

# Get current subscription details
echo "Current Subscription:"
az account show

# Confirm again with subscription details
read -p "Do you want to proceed with deleting all resource groups in this subscription? (yes/no): " final_confirm

if [[ "$final_confirm" != "yes" ]]; then
    echo "Operation cancelled."
    exit 1
fi

# List and delete all resource groups
echo "Fetching list of resource groups..."
resource_groups=$(az group list --query "[].name" -o tsv)

if [[ -z "$resource_groups" ]]; then
    echo "No resource groups found in the subscription."
    exit 0
fi

echo "Found the following resource groups:"
echo "$resource_groups"

# Pause to allow visual confirmation
read -p "Press Enter to continue deletion or Ctrl+C to cancel..."

# Delete each resource group
for rg in $resource_groups; do
    delete_resource_group "$rg"
done

echo "Deletion process initiated for all resource groups."
echo "Use 'az group list' to monitor progress."
