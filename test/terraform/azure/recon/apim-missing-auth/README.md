# apim-missing-auth fixture

Test bed for the `apim-missing-auth` and `apim-backend-direct-access`
Aurelian recon modules.

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
  - `apim1/unauth-api` — no auth (positive case for module 1)
  - `apim1/jwt-api` — API-scope `<validate-jwt>`
  - `apim1/ipfilter-api` — API-scope `<ip-filter>`
  - `apim1/checkheader-api` — API-scope auth-header `<check-header>`
  - `apim1/product-auth-api` — member of JWT-enforcing product (`SubscriptionRequired=true`)
  - `apim1/fake-mcp-api` — MCP-shaped operations (`/mcp`, `/sse`, `/messages`),
    no auth (positive case for module 1 + exercises MCP labelling)
  - `apim2/inherits-auth-api` — inherits service-scope `<validate-jwt>`
- Catch-all `GET /` operation on each REST API with a `<mock-response>`
  op-policy so callers can curl the APIs and see 200/401/403 directly
- 1 Linux App Service (B1, `public_network_access_enabled = true`) wired
  as an APIM backend (positive case for module 2)

Consumption tier doesn't support native MCP-type APIs, so the fake MCP
server is a regular API shaped like one.

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

## Run detections

```sh
SUB_ID=$(terraform output -raw subscription_id)

go run ../../../../../ azure recon apim-missing-auth \
  --subscription-ids "$SUB_ID" -f /tmp/missing-auth.json

go run ../../../../../ azure recon apim-backend-direct-access \
  --subscription-ids "$SUB_ID" -f /tmp/backend-direct.json
```

## Expected results

**apim-missing-auth** — exactly two `critical` risks:

- `name: azure-apim-missing-auth`, deduplication ending in `unauth-api`
- `name: azure-apim-mcp-missing-auth`, deduplication ending in
  `fake-mcp-api` (with `context.is_mcp_server == true`)

None of the jwt / ipfilter / checkheader / product-auth / inherits-auth
APIs should appear.

**apim-backend-direct-access** — one `high` risk, name
`azure-apim-backend-direct-access`, for the `public-appservice-backend`
on apim1. Reason field should mention `publicNetworkAccess Enabled and
no IP restrictions`.

## Teardown

```sh
terraform destroy -var subscription_id=<YOUR_SUB_ID>
```

Consumption APIMs cost nothing; the B1 App Service plan is ~$0.018/hr
while the fixture is up.
