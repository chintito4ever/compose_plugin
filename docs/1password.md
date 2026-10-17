# 1Password Integration

Compose Manager can deploy stacks whose environment holds
[1Password secret references](https://developer.1password.com/docs/cli/secret-references/)
(`op://vault/item/field`). Secrets are resolved only at the moment a container is
created, through the 1Password CLI, and are never written to disk by the plugin.

The integration builds on a 1Password CLI setup that already exists on the Unraid server.
The plugin does not install, configure or unlock 1Password.

## Contents

- [Requirements](#requirements)
- [How detection works](#how-detection-works)
- [Supported patterns](#supported-patterns)
- [Unsupported patterns and limitations](#unsupported-patterns-and-limitations)
- [UI indicators](#ui-indicators)
- [Locked vs unlocked behavior](#locked-vs-unlocked-behavior)
- [Unraid reboot behavior](#unraid-reboot-behavior)
- [Deployment workflow](#deployment-workflow)
- [Token handling and security](#token-handling-and-security)
- [Example: Sitespeed](#example-sitespeed)
- [Testing on a noncritical project](#testing-on-a-noncritical-project)
- [Disabling and rolling back](#disabling-and-rolling-back)

## Requirements

| Path | Purpose |
|------|---------|
| `/usr/local/bin/op-secure` | Runs the 1Password CLI with the runtime token. Required for deployments. |
| `/usr/local/bin/op-status` | Optional. Used for the status indicator (exit code `0` = healthy). |
| `/run/1password/service-account-token` | RAM-only service-account token written by `op-unlock`. Its presence means "unlocked". |

Recommended token setup: a read-only service account limited to one vault, the token
directory `0700` and the token file `0600`, both on `/run` (RAM), so the token is gone
after every reboot.

The plugin calls `op-secure whoami` and `op-secure run ...`. It never calls
`op-unlock`, `op-lock`, or `op-compose`, and it never changes them.

## How detection works

For every stack the plugin reads the files the stack's compose command actually uses.
These are the same files `StackInfo` resolves for every other action:

- the **interpolation env file**, which is the stack's configured external env path
  (`envpath`) or the `.env` in the compose source folder (direct or external project
  directory),
- every **compose file**: the main file (`compose.yaml`, `compose.yml`,
  `docker-compose.yaml` or `docker-compose.yml`), the override file, files listed in
  `COMPOSE_FILE`, and additional compose files,
- every file referenced by a service-level **`env_file:`** entry in those compose files.

A stack is **1Password-managed** when any of these contains `op://` outside a comment.

Detection only reads files. It never resolves a reference, never runs
`docker compose config`, and never calls the 1Password CLI. As a result:

- it works while 1Password is locked, and right after a reboot,
- it adds no external command per stack row, so it stays fast with 20 or more stacks,
- it is recomputed on every list load or row refresh, so it follows configuration
  edits immediately,
- a missing or unreadable file is skipped instead of breaking the stack row.

## Supported patterns

Put the references in the stack's env file and use them through Compose
**interpolation** (`${VAR}`) or **pass-through** (`VAR:` with no value):

```dotenv
# .env (or the configured external env file)
DATABASE_PASSWORD=op://Homelab Secrets/VehicleHub/DATABASE_PASSWORD
API_KEY="op://Homelab Secrets/VehicleHub/api key"
export SMTP_PASSWORD=op://Homelab Secrets/VehicleHub/smtp/password
```

```yaml
services:
  api:
    environment:
      DATABASE_PASSWORD: ${DATABASE_PASSWORD}   # interpolation
      API_KEY:                                  # pass-through from the environment
```

Accepted reference syntax: `op://<vault>/<item>/[<section>/]<field>[?attribute=...]`.
Vault and item names may contain spaces. Quoted values, an `export ` prefix and
`#` comments are handled.

All compose features keep working: project name, external project directories,
`-f` files, overrides, `COMPOSE_FILE`, default file discovery, profiles, the env-file
selection, recreate, remove-orphans, build-on-update, wait-for-healthy, registry
credentials and per-stack locks.

### Why only the env file

Docker Compose treats the two env mechanisms differently. This was checked against
Docker Compose 5.5.1 by putting a value in the process environment (which is what
`op run` does) and running `docker compose config`:

| Pattern | Container receives |
|---------|--------------------|
| `X: ${FOO}` with `FOO=op://...` in `--env-file` and `FOO=resolved` in the process env | `resolved` (process env wins for interpolation) |
| `PASS_THROUGH:` with `PASS_THROUGH=resolved` in the process env | `resolved` |
| `env_file: svc.env` with `BAR=op://...` in `svc.env` and `BAR=resolved` in the process env | `op://...` (**the literal reference**) |

Wrapping Compose in `op run` resolves interpolation, but **service-level `env_file:`
entries reach the container verbatim**. The plugin therefore refuses that pattern
instead of deploying literal references.

## Unsupported patterns and limitations

These are detected, and **Compose Up, Update and auto-update are refused** with an
explanation (orange warning icon next to the stack name, with the reason in its
tooltip):

| Pattern | Why it is refused | What to do |
|---------|-------------------|------------|
| `op://` directly in a compose file (`environment: {X: op://...}`) | The container would receive the reference text. | Move it to the env file and use `${X}`. |
| A service `env_file:` whose file contains `op://`, including `env_file: .env` | Compose passes env_file values to containers verbatim. | Use `environment:` with `${VAR}` instead of `env_file:`. |
| A malformed reference (e.g. `op://Vault/Item` with no field) | `op run` would fail or behave unexpectedly. | Fix the reference. |
| `${...}` interpolation inside the managed env file (e.g. `URL=postgres://u:${PASS}@db`) | Under `op run` such values are not expanded the way Compose would expand them, so they could change (and an embedded reference is never resolved). | Build the value in the compose file (`URL: postgres://u:${PASS}@db`) or store the whole value in 1Password. Single-quoted values are fine. Known false positive: an unquoted `$$` escape (e.g. `PASS=a$$b`) is also flagged; single-quote it. |
| `include:` or `extends: file:` in a 1Password stack | Included files are not audited. | Inline the services or keep secrets out of those stacks. |
| An `env_file:` path containing `${...}` in a 1Password stack | Its location cannot be known without interpolation. | Use a literal path. |

Other limitations:

- Only the env file that Compose uses for interpolation is checked. If an external env
  path is set, references in the stack's local `.env` are ignored, because Compose
  ignores that file too.
- Compose `secrets:` that read from a `file:` are not inspected.
- A container that intentionally receives `op://` text (for example one that resolves
  references itself through Connect or an SDK) is treated as unsupported. There is no
  per-stack opt-out in this version.
- Detection reads YAML line by line, so it does not need the PHP yaml extension.
  Unusual YAML (anchors that pull `env_file` entries in from elsewhere, multi-line
  flow lists) may be missed or blocked conservatively.
- The global status reflects whether the token file is present (and, when installed,
  the exit code of `op-status`). Validity is proven at deploy time by
  `op-secure whoami` and by resolving every reference before anything changes.

## UI indicators

**Per stack.** A small, neutral `🔑 1Password` badge sits next to the stack name,
with the tooltip *"Uses 1Password-managed environment secrets"*. It means the stack's
configuration contains references, and nothing more. It shows the same way whether
1Password is locked or unlocked and whether the stack is running or stopped, and it
survives reboots and row refreshes. Ordinary stacks show nothing. An extra orange `!`
icon means the configuration uses a pattern that cannot be deployed safely. Hover over
it for the reason.

**Global.** Next to the stack buttons:

| Text | Meaning |
|------|---------|
| `1Password: Unlocked` | The RAM token is loaded (and `op-status`, when installed, exits 0). 1Password stacks can be deployed. |
| `1Password: Locked` | No token, e.g. after a reboot. Run `op-unlock`. Running containers are unaffected. |
| `1Password: Unavailable` | `op-secure` is not installed. Hidden unless some stack uses 1Password. |
| `1Password: Check failed` | The token is present but `op-status` exited non-zero. Run `op-status` for details. |

The status is refreshed whenever the stack list loads. It only checks whether the
token file exists. The result of `op-status` is cached for 60 seconds in
`/var/tmp/compose-manager-onepassword-status.json`, which stores the state only, so
list refreshes never repeat network checks.

## Locked vs unlocked behavior

| Action | Locked | Unlocked |
|--------|--------|----------|
| Logs, container console, status, stats | Works | Works |
| Stop, container start/stop/restart | Works | Works |
| Compose Down | Works (containers are removed; creating them again needs an unlock) | Works |
| Pull | Works | Works |
| Compose Up / Recreate | **Blocked**, even if the stack is already running (`up` may recreate) | Secrets resolved, then deployed |
| Update | **Blocked before pulling** | Pull without secrets, then `up` with secrets |
| Start All / Update All | 1Password stacks are skipped and listed; others run | Deployed |
| Scheduled / manual auto-update | **Skipped before pulling**, with an Unraid notification | Pull, then `up -d` with secrets |
| Autostart at boot | **Starts existing containers only** (`docker compose start`) | Normal `up -d` |

Blocked operations stop before Compose runs, so running containers stay untouched.
Auto-update is skipped before the pull on purpose: pulling while the update cannot be
applied would make the next run see unchanged digests and never recreate the stack.

## Unraid reboot behavior

After a reboot `/run` is empty, so 1Password is **Locked** until you run `op-unlock`.

- **Containers that already exist keep their resolved environment.** Docker stores it
  with the container, so `restart: unless-stopped` / `always` containers come back on
  their own, and a stopped container can be started without 1Password.
- **Compose autostart** cannot run `up -d` for a 1Password stack while locked:
  interpolation would produce the literal references, the configuration hash would
  change, and Compose would recreate the containers with them. Instead autostart runs
  `docker compose start`, which starts existing containers and never creates or
  recreates any. If a container is missing, that start fails and is logged; nothing is
  created with unresolved references. The Autostart Force Recreate setting is ignored
  for these stacks while locked.
- **Recreating containers always needs the secrets again.** After `op-unlock`, use
  Compose Up or Update to apply configuration or image changes.

Recommended: give containers in 1Password stacks `restart: unless-stopped`, so they
come back after a reboot through Docker itself.

## Deployment workflow

```
User clicks Update
  -> Compose Manager detects op:// references (file scan)
  -> configuration check (unsupported patterns -> refused)
  -> 1Password status: op-secure installed? token present? (locked -> refused, op-unlock message)
  -> compose.sh, holding the stack lock:
       op-secure whoami                                 (authentication; output discarded)
       op-secure run --env-file=<env> -- true           (every reference resolves; nothing runs)
       docker compose ... pull                          (no secrets needed)
       op-secure run --env-file=<env> -- env -u OP_SERVICE_ACCOUNT_TOKEN -u OP_CONNECT_TOKEN -u OP_CONNECT_HOST \
         docker compose --env-file <env> -f ... -p <project> up -d [flags]
  -> result saved, UI refreshes normally
```

If authentication or any reference fails, the operation stops before pull or up, with
the CLI's error line (which names the variable or item, never a value). Ordinary stacks
take exactly the same command path as before. The `op-secure run` wrapper is applied
only to the `up` call. Every other Compose call (`pull`, `config`, `images`, `down`,
`stop`, `logs`) runs without secrets.

## Token handling and security

- The token is never read by the plugin. Only the existence and size of
  `/run/1password/service-account-token` are checked. `op-secure` reads it.
- It is never stored in plugin config, never written to `/boot`, never sent to or
  returned by any browser request, and never put in labels or logs.
- `op run` exports resolved values to the single `docker compose up` process. Nothing
  decrypted is written to disk, and no resolved `.env` or `docker compose config`
  output is produced or printed.
- `env -u OP_SERVICE_ACCOUNT_TOKEN -u OP_CONNECT_TOKEN -u OP_CONNECT_HOST` removes the
  1Password credentials from Compose's environment, so a compose file cannot pass the
  token to a container (for example through a pass-through `OP_SERVICE_ACCOUNT_TOKEN:`
  entry).
- `op run` output masking stays on, so values that Compose echoes are redacted in the
  terminal, `last_cmd.log` and background notifications.
- Commands are built as quoted argument arrays (no `eval`). Debug logging records
  compose arguments, which are file paths and flags, never environment values.
- The UI shows stack names, variable names and reasons only, never reference values
  or secrets.
- Containers receive exactly the variables the compose file maps to them. Anyone with
  Docker access on the host can still read a container's environment with
  `docker inspect`, as with any secret passed through environment variables.
- The plugin's registry credential vault is separate and unchanged.

## Example: Sitespeed

`/boot/config/plugins/compose.manager/projects/sitespeedio/.env`:

```dotenv
GRAFANA_MCP_TOKEN=op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_TOKEN
GRAFANA_MCP_SERVER_TOKEN=op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_SERVER_TOKEN
```

`compose.yaml`:

```yaml
services:
  grafana-mcp:
    image: grafana/mcp-grafana:latest
    restart: unless-stopped
    environment:
      GRAFANA_SERVICE_ACCOUNT_TOKEN: ${GRAFANA_MCP_TOKEN}
      MCP_GRAFANA_SERVER_TOKEN: ${GRAFANA_MCP_SERVER_TOKEN}
```

1. The stack list shows **Sitespeed `🔑 1Password`**, locked or not.
2. While locked, clicking **Update** shows *"This project uses 1Password secrets.
   Unlock 1Password on Unraid using op-unlock before deploying."* The running
   container is not touched.
3. On the Unraid shell run `op-unlock`. The global indicator turns to
   `1Password: Unlocked` on the next list refresh.
4. Click **Update**. The terminal shows *"Resolving 1Password secrets for sitespeedio
   at deploy time (values are never shown)."*, then the normal pull and recreate.
   This is equivalent to `op-compose sitespeedio up -d`, without opening a terminal.
5. Optionally run `op-lock` afterwards. The container keeps running with its resolved
   environment.

## Testing on a noncritical project

1. Create a vault item with a dummy field, for example `Homelab Secrets/CM Test/VALUE`.
2. Add a new stack `op-test`:

   ```yaml
   services:
     echo:
       image: alpine:3.20
       command: ["sh", "-c", "test -n \"$$VALUE\" && test \"$${VALUE#op://}\" = \"$$VALUE\" && echo resolved-ok; sleep 3600"]
       environment:
         VALUE: ${VALUE}
   ```

   with `.env` containing `VALUE=op://Homelab Secrets/CM Test/VALUE`.
3. Confirm the badge appears. Run `op-lock`, click **Compose Up**, and confirm it is
   refused and no container is created.
4. Run `op-unlock`, click **Compose Up**, and check that the container log prints
   `resolved-ok`, which proves the value is not an `op://` reference. Don't print the
   value itself.
5. Run `op-lock`, then Stop and start the container from the stack row. This should
   work. Then click Compose Up, which should be refused.
6. Break the reference (`VALUE=op://Homelab Secrets/CM Test/MISSING`) and confirm
   Compose Up fails with a lookup error before anything changes.
7. Remove the stack when done.

## Disabling and rolling back

- **Turn off secret resolution:** Settings → *Resolve 1Password Secrets on Deploy* →
  off (`ONEPASSWORD_SECRET_INJECTION="false"` in
  `/boot/config/plugins/compose.manager/compose.manager.cfg`). Detection, indicators and
  safety guards stay active. Up, Update and auto-update are refused for 1Password stacks
  instead of resolving secrets. This is the safe "off" state. There is intentionally no
  setting that deploys literal `op://` references.
- **Roll back the plugin:** reinstall the previous Compose Manager Plus release from its
  `.plg` / `.txz`. No data migration is involved: the integration adds no metadata files
  to stacks, and the only runtime file is the status cache in `/var/tmp`, which is
  removed by a reboot. Your 1Password CLI helpers and `op-compose` keep working as before.
