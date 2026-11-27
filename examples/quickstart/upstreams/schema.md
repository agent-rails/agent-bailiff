# Upstream config, version 1

Bootstrap reads one upstream config, `BAILIFF_UPSTREAM` (`upstreams/${UPSTREAM:-stub}.json`; set `BAILIFF_UPSTREAMS` to mount another directory as `upstreams/`), in the `decide`, `custodian` and `bootstrap` steps. It sets the routes, the cost table, and the credential bindings for one Streamable HTTP MCP server.

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
| `url` | `http://<compose-service>:<port>[/path]` for a server in the stack, or `https://<host>[:port][/path]`. No credentials, query or fragment. Not `localhost`, a stack service other than the upstream servers, or a loopback, link-local, unspecified or multicast address; a hostname that resolves to one is not checked. An `https://` url to an upstream server in the stack (`stub-upstream`, `gitea`, `gitea-mcp`, `gitea-mcp-spike`) needs `"ca_file": "install"`. |
| `credential_id`, `target` | The custodian credential the gateway injects for every route. Store it with `agent-bailiff custodian put-credential --tenant quickstart --credential-id <id> --target <target>`. |
| `credential_header` | HTTP field name the custodian sets, for example `Authorization`. |
| `binding_resource` | Resource the credential binding covers; a wildcard only as a final `/*` segment. |
| `ca_file` | Optional, `https://` only. PEM certificates beside this file; the gateway trusts only these for the upstream, not the system roots. Bootstrap keeps the certificates alone, so a bundled private key is dropped, and fails on a file with none. Without it the gateway uses its system roots. The reserved value `install` names the install CA that `certs` issues (`/var/lib/bailiff/certs/public/current/ca.pem`); it is required for, and allowed only for, an upstream server in the stack. `gateway-init` reads it, so a missing or reissued CA shows up on the next `up`. |
| `routes_file` | Route table beside this file: `{"routes": [...]}`, non-empty, every route on `service`, every resource filled. `agent-bailiff routes generate` drafts one from the server's `tools/list`. |

The file is strict JSON of at most 64 KiB with exactly these fields, `ca_file` optional; duplicate keys, symlinks and unknown fields fail bootstrap. Every routed tool costs 1 unit of task budget.

The gateway reaches only the one configured upstream. It does not follow redirects: a `307` comes back to the agent as `outcome_unknown: http_307`, and the redirect target receives nothing.
