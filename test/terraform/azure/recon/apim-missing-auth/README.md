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
    no auth (positive case + exercises MCP labelling via URL-template fallback)
  - `apim2/inherits-auth-api` — inherits service-scope `<validate-jwt>`
- A catch-all `GET /` operation on each REST API with a `<mock-response>`
  op-policy so the APIs respond to direct HTTP requests for manual
  verification.

## What this fixture does and does NOT cover

The module labels an API as an MCP server via two signals, in precedence
order:

1. **Primary**: `properties.type == "mcp"` on the API contract, returned
   by ARM's `/apis` endpoint at `api-version=2024-06-01-preview`. This
   is how APIM natively exposes MCP-type APIs introduced in 2024.
2. **Fallback**: any operation URL template is `/mcp`, `/sse`,
   `/messages`, or `/message`. This catches REST-API-shaped MCP proxies
   that aren't typed natively.

**This Terraform fixture exercises only the fallback (2).** The
`fake-mcp-api` is a plain `azurerm_api_management_api` with
MCP-conventional operation paths — its `properties.type` is `null`,
not `"mcp"`. Consumption tier does not support native MCP-type APIs,
so a true `type=mcp` API cannot be provisioned here.

The primary signal (1) is covered by:

- `pkg/azure/apim/list_test.go` — unit tests for `parseAPIListPage`
  including `TestParseAPIListPage_NativeMCPFixture`, which reads
  `pkg/azure/apim/testdata/apis-2024-06-01-preview-sample.json` — a
  captured ARM list response containing both `type=mcp` and non-MCP
  entries (with the type field in both lowercase and uppercase to
  assert case-insensitive matching).

### Adding a live native-MCP test

If you need the Terraform fixture itself to exercise the primary
signal (e.g., for a CI run that wants to hit real ARM list semantics
for MCP-type APIs), you must:

1. Upgrade one of the APIMs in `main.tf` from `Consumption_0` to
   `Developer_1` (or higher). Cost: **~$50/month pro-rated (~$0.07/hr,
   ~$1.70/day)** while deployed. Provisioning time jumps from ~5 min to
   ~30-45 min.
2. Add a native MCP API. At time of writing, neither the `azurerm`
   provider nor the `azapi` provider directly expose the new MCP-type
   API resource; you would declare it via `azapi_resource` against
   `Microsoft.ApiManagement/service/apis@2024-06-01-preview` with
   `body.properties.type = "mcp"`. See
   <https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview>.

The fallback path coverage plus the unit-test-level primary-path
coverage is generally sufficient — the overhead of keeping a
Developer-tier APIM warm is not worth the marginal CI assurance.

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
  (with `context.is_mcp_server == true` — set by the URL-template
  fallback because the fixture is Consumption tier)

None of the jwt / ipfilter / checkheader / product-auth / inherits-auth
APIs should appear.

## Teardown

```sh
terraform destroy -var subscription_id=<YOUR_SUB_ID>
```

Consumption APIMs cost nothing; the fixture has no ongoing costs.
