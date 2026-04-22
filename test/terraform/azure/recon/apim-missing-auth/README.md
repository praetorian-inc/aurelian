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
- 7 APIs across the 2 services:
  - `apim1/unauth-api` — no auth (positive case)
  - `apim1/jwt-api` — API-scope `<validate-jwt>`
  - `apim1/ipfilter-api` — API-scope `<ip-filter>`
  - `apim1/checkheader-api` — API-scope auth-header `<check-header>`
  - `apim1/product-auth-api` — member of JWT-enforcing product (`SubscriptionRequired=true`)
  - `apim1/fake-mcp-api` — MCP-shaped operations (`/mcp`, `/sse`, `/messages`),
    no auth (positive case + exercises MCP labelling)
  - `apim2/inherits-auth-api` — inherits service-scope `<validate-jwt>`
- A catch-all `GET /` operation on each REST API with a `<mock-response>`
  op-policy so the APIs respond to direct HTTP requests for manual
  verification. Consumption tier doesn't support native MCP-type APIs, so
  the fake MCP server is a regular API shaped like one.

## Manual HTTP verification

After deploy, you can curl each path and confirm the policies fire:

| Path                              | Expect | Why                                          |
| --------------------------------- | ------ | -------------------------------------------- |
| `GET  /unauth` on apim1           | `200`  | no policy, mock responds                     |
| `GET  /jwt` on apim1              | `401`  | `<validate-jwt>` rejects                     |
| `GET  /ipf` on apim1              | `403`  | `<ip-filter>` blocks non-10.x callers        |
| `GET  /chk` on apim1              | `401`  | `<check-header name=Authorization>` rejects  |
| `GET  /prod` on apim1             | `401`  | APIM subscription-key gate                   |
| `POST /fake-mcp/mcp` on apim1     | `200`  | no policy, mock responds                     |
| `GET  /inh` on apim2              | `401`  | service-scope `<validate-jwt>` rejects       |

## Run the module

```sh
SUB_ID=$(terraform output -raw subscription_id)

go run ../../../../../ azure recon apim-missing-auth \
  --subscription-ids "$SUB_ID" -f /tmp/missing-auth.json
```

## Expected results

Exactly two risks, both `critical`:

- `name: azure-apim-missing-auth`, deduplication ending in `unauth-api`
- `name: azure-apim-mcp-missing-auth`, deduplication ending in `fake-mcp-api`
  (with `context.is_mcp_server == true`)

None of the jwt / ipfilter / checkheader / product-auth / inherits-auth
APIs should appear.

## Teardown

```sh
terraform destroy -var subscription_id=<YOUR_SUB_ID>
```

Consumption APIMs cost nothing; the fixture has no ongoing costs.
