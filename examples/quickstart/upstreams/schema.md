# Upstream config, version 1

Bootstrap reads one upstream config, `BAILIFF_UPSTREAM` (`upstreams/${UPSTREAM:-stub}.json`; set `BAILIFF_UPSTREAMS` to mount another directory as `upstreams/`), in the `decide`, `custodian`, `bootstrap` and `credential-put` steps. It sets the routes, the cost table, and the credential bindings for one Streamable HTTP MCP server.

```json
{
  "version": 1,
  "service": "gitea",
  "url": "https://gitea-mcp-tls:8443/mcp",
  "credential_id": "gitea-token",
  "credential_header": "Authorization",
  "target": "gitea",
  "binding_resource": "gitea/repos/quickstart/*",
  "routes_file": "gitea-routes.json",
  "ca_file": "install",
  "provider": "gitea",
  "provider_api_url": "http://gitea/api/v1",
  "required_permissions": ["read:issue", "read:repository"]
}
```

| Field | Rule |
| --- | --- |
| `version` | `1` |
| `service` | Route service name: ASCII printable, no whitespace or `*`. `k8s` is reserved for catalogs. |
| `url` | `https://<host>[:port][/path]`; plain http is refused, since the gateway reaches no upstream on loopback. No credentials, query or fragment. Not `localhost`, a stack service other than the upstream servers, or a loopback, link-local, unspecified or multicast address; a hostname that resolves to one is not checked. An `https://` url to an upstream server in the stack (`stub-upstream`, `gitea-mcp-tls`) needs `"ca_file": "install"`; `gitea` and `gitea-mcp` are reached only through `gitea-mcp-tls`. |
| `credential_id`, `target` | The custodian credential the gateway injects for every route. Store it with `agent-bailiff custodian put-credential --tenant quickstart --credential-id <id> --target <target>`. |
| `credential_header` | HTTP field name the custodian sets, for example `Authorization`. |
| `binding_resource` | Resource the credential binding covers; a wildcard only as a final `/*` segment. |
| `ca_file` | Optional, `https://` only. PEM certificates beside this file; the gateway trusts only these for the upstream, not the system roots. Bootstrap keeps the certificates alone, so a bundled private key is dropped, and fails on a file with none. Without it the gateway uses its system roots. The reserved value `install` names the install CA that `certs` issues (`/var/lib/bailiff/certs/public/current/ca.pem`); it is required for, and allowed only for, an upstream server in the stack. `gateway-init` reads it, so a missing or reissued CA shows up on the next `up`. |
| `provider`, `provider_api_url`, `required_permissions` | Optional, all three or none; the `gitea` profile needs them. `provider` is `gitea`. `provider_api_url` must be `http://gitea/<path>`, the stack's Gitea, for example `http://gitea/api/v1`: bootstrap runs offline and `agent-bailiff credential-check --unix-socket /run/gitea/gitea.sock` reaches Gitea only over its Unix socket. `required_permissions` lists the scopes the bindings need and must include `read:repository` or `write:repository`. Before the custodian stores a token, `credential-check` refuses one with broader scopes or with private reach outside `binding_resource`. |
| `max_repos`, `check_timeout_seconds` | Optional, each alone or both, and only with the provider fields. Integers, not booleans or decimals. `max_repos`, from 1 to 10000, default 1000: `credential-check` refuses the token as `too_many_repos` when either repository search reports or serves more. `check_timeout_seconds`, from 1 to 60, default 10: the wall-clock deadline for the whole check, past which it refuses as `deadline_exceeded`. Bootstrap passes them as `--max-repos` and `--timeout`, and gives the check's process `check_timeout_seconds` plus 60 seconds before it fails bootstrap. Raise them for a bot user that reaches more repositories or a slow Gitea; the check still makes one attempt, with no retry. The caps keep a run inside `credential-put`'s 300 second wait: bootstrap may wait 120 seconds for Gitea and then run the check twice, once on the stored token and once on a new one. At the caps, two searches of 10000 repositories at 50 a page are 400 requests in 60 seconds, 150 ms each; a larger cap would be refused at the deadline instead. |
| `routes_file` | Route table beside this file: `{"routes": [...]}`, non-empty, every route on `service`, every resource filled. `agent-bailiff routes generate` drafts one from the server's `tools/list`. |

The file is strict JSON of at most 64 KiB with exactly these fields, `ca_file`, the provider fields and the check bounds optional; duplicate keys, symlinks and unknown fields fail bootstrap. Every routed tool costs 1 unit of task budget.

The gateway reaches only the one configured upstream. It does not follow redirects: a `307` comes back to the agent as `outcome_unknown: http_307`, and the redirect target receives nothing.
