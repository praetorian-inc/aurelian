# apim-missing-auth fixture

Test bed for the `apim-missing-auth` Aurelian recon module.

## Deploy

```sh
cd test/terraform/azure/recon/apim-missing-auth
terraform init
terraform apply -var subscription_id=<YOUR_SUB_ID>
```

Provisions (~5 min on Consumption-tier APIM, free):

- Resource group `aur-apim-<suffix>-rg`
- 2 APIM services (`Consumption_0`, free tier)
- 6 APIs across the 2 services:
  - `apim1/unauth-api` — no auth (positive case)
  - `apim1/jwt-api` — API-scope `<validate-jwt>`
  - `apim1/ipfilter-api` — API-scope `<ip-filter>`
  - `apim1/checkheader-api` — API-scope auth-header `<check-header>`
  - `apim1/product-auth-api` — member of JWT-enforcing product (`SubscriptionRequired=true`)
  - `apim2/inherits-auth-api` — inherits service-scope `<validate-jwt>`

## Run the module

```sh
SUB_ID=$(terraform output -raw subscription_id)

go run ../../../../../ azure recon apim-missing-auth \
  --subscription-ids "$SUB_ID" -f /tmp/missing-auth.json
```

## Expected results

Exactly one risk, severity `critical`, `deduplication_id` ending in
`unauth-api`. None of the jwt / ipfilter / checkheader / product-auth /
inherits-auth APIs should appear.

## Teardown

```sh
terraform destroy -var subscription_id=<YOUR_SUB_ID>
```

Consumption APIMs cost nothing; the fixture has no ongoing costs.
