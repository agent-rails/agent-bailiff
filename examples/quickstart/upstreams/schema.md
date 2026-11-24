# Upstream config, version 1

Bootstrap reads one upstream config, `BAILIFF_UPSTREAM` (default `upstreams/gitea.json`), in the `decide`, `custodian` and `bootstrap` steps. It sets the routes, the cost table, and the credential bindings for one Streamable HTTP MCP server.

```json
{
  "version": 1,
  "service": "gitea",
  "url": "http://gitea-mcp:8080/mcp",
  "credential_id": "gitea-token",
  "credential_header": "Authorization",
  "target": "gitea",
  "binding_resource": "gitea/repos/quickstart/*",
  "routes_file": "gitea-routes.json"
}
```

| Field | Rule |
| --- | --- |
| `version` | `1` |
| `service` | Route service name: ASCII printable, no whitespace or `*`. `k8s` is reserved for catalogs. |
| `url` | `http://<compose-service>:<port>[/path]` for a server in the stack, or `https://<host>[:port][/path]`. No credentials, query or fragment. |
| `credential_id`, `target` | The custodian credential the gateway injects for every route. Store it with `agent-bailiff custodian put-credential --tenant quickstart --credential-id <id> --target <target>`. |
| `credential_header` | HTTP field name the custodian sets, for example `Authorization`. |
| `binding_resource` | Resource the credential binding covers; a wildcard only as a final `/*` segment. |
| `routes_file` | Route table beside this file: `{"routes": [...]}`, non-empty, every route on `service`, every resource filled. `agent-bailiff routes generate` drafts one from the server's `tools/list`. |

The file is strict JSON of at most 64 KiB with exactly these fields; duplicate keys, symlinks and unknown fields fail bootstrap. Every routed tool costs 1 unit of task budget.
