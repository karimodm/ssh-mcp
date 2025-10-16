# SSH MCP Server

[![NPM Version](https://img.shields.io/npm/v/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Downloads](https://img.shields.io/npm/dm/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Node Version](https://img.shields.io/node/v/ssh-mcp)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/tufantunc/ssh-mcp)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/forks)
[![Build Status](https://github.com/tufantunc/ssh-mcp/actions/workflows/publish.yml/badge.svg)](https://github.com/tufantunc/ssh-mcp/actions)
[![GitHub issues](https://img.shields.io/github/issues/tufantunc/ssh-mcp)](https://github.com/tufantunc/ssh-mcp/issues)

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/tufantunc/ssh-mcp)](https://archestra.ai/mcp-catalog/tufantunc__ssh-mcp)

**SSH MCP Server** is a local Model Context Protocol (MCP) server that exposes SSH control for Linux and Windows systems, enabling LLMs and other MCP clients to execute shell commands securely via SSH.

## Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Client Setup](#client-setup)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [Support](#support)

## Quick Start

- [Install](#installation) SSH MCP Server
- [Configure](#configuration) SSH MCP Server
- [Set up](#client-setup) your MCP Client (e.g. Claude Desktop, Cursor, etc)
- Execute remote shell commands on your Linux or Windows server via natural language

## Features

- MCP-compliant server exposing SSH capabilities
- Execute shell commands on remote Linux and Windows systems
- Secure authentication via password or SSH key
- Built with TypeScript and the official MCP SDK
- **Configurable timeout protection** with automatic process abortion
- **Graceful timeout handling** - attempts to kill hanging processes before closing connections

### Tools

- `exec`: Execute a shell command on a remote server
  - **Parameters:**
    - `command` (required): Shell command to execute on the remote SSH server
    - `host`: Remote hostname or IP. Required unless provided via `--host` CLI default.
    - `port`: SSH port (default: 22 if neither tool input nor CLI default specified).
    - `username`: SSH username. Required unless provided via `--user` CLI default.
    - `password`: SSH password when using password authentication.
    - `privateKey`: PEM-encoded private key contents (preferred when the LLM already has the key material).
    - `privateKeyPath`: Path on the MCP server machine to a PEM-encoded private key (useful when the key resides locally alongside the server).
    - `passphrase`: Passphrase for the provided private key, if needed.
    - `agent`: Path to an SSH agent socket (for example the value of `SSH_AUTH_SOCK`) to authenticate using keys already loaded in the agent.
    - `timeoutMs`: Override the per-command execution timeout in milliseconds (falls back to CLI `--timeout` or the 60000ms default).
    - `reuseConnection`: Boolean flag (default `true`) to control whether the MCP server reuses a pooled SSH connection for the same host/user credentials.
  - **Timeout Configuration:**
    - Timeout is configured via command line argument `--timeout` (in milliseconds) and can be overridden per call via `timeoutMs`.
    - Default timeout: 60000ms (1 minute)
    - When a command times out, the server automatically attempts to abort the running process before closing the connection
  - **Max Command Length Configuration:**
    - Max command characters are configured via `--maxChars`
    - Default: `1000`
    - No-limit mode: set `--maxChars=none` or any `<= 0` value (e.g. `--maxChars=0`)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tufantunc/ssh-mcp.git
   cd ssh-mcp
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```

## Client Setup

Configure your MCP client (Claude Desktop, Cursor, etc.) by adding the server definition to the `mcpServers` block. For Claude Desktop, edit `~/Library/Application Support/Claude/mcp.json` (macOS) or the corresponding location on Windows/Linux and insert:

**CLI Defaults (optional):**
- `host`: Hostname or IP to use as a default target. You can omit this to let the tool decide per request.
- `user`: SSH username to use as a default. Required only if the tool input will not provide `username`. Do not embed the username in the `host` value (i.e. prefer `"host": "example.com"` alongside `"username": "ops"`).
- `port`: SSH port (default: 22)
- `password`: SSH password (or use `key` / `privateKey` for key-based auth)
- `key`: Path to a private SSH key stored alongside the MCP server
- `agent`: Path to an SSH agent socket to use for authentication (defaults to the environment's `SSH_AUTH_SOCK` if provided)
- `allowlist`: Path to a JSON file containing wildcard patterns for commands the server is allowed to execute (defaults to the bundled `config/command-allowlist.json`; can also be provided via the `SSH_MCP_ALLOWLIST` environment variable)
- `timeout`: Command execution timeout in milliseconds (default: 60000ms = 1 minute)
- `maxChars`: Maximum allowed characters for the `command` input (default: 1000). Use `none` or `0` to disable the limit.

At runtime, the `exec` tool can override any of these values per call by supplying `host`, `username`, `port`, `password`, `privateKey`, `privateKeyPath`, `agent`, `timeoutMs`, or `reuseConnection`.


```commandline
{
    "mcpServers": {
        "ssh-mcp": {
            "command": "npx",
            "args": [
                "ssh-mcp",
                "-y",
                "--",
                "--host=1.2.3.4",
                "--port=22",
                "--user=root",
                "--password=pass",
                "--key=path/to/key",
                "--allowlist=/path/to/command-allowlist.json",
                "--agent=/run/user/1000/ssh-agent.sock",
                "--timeout=30000",
                "--maxChars=none"
            ]
        }
    }
}
```

For a locally modified checkout (e.g. this repo under `/tmp/ssh-mcp`), build it once with `npm run build` and point the MCP client directly at the compiled entry point:

```commandline
{
    "mcpServers": {
        "ssh-mcp": {
            "command": "node",
            "args": [
                "/tmp/ssh-mcp/build/index.js",
                "--allowlist=/tmp/ssh-mcp/config/command-allowlist.json",
                "--agent=/run/user/1000/ssh-agent.sock",
                "--timeout=30000",
                "--maxChars=none"
            ]
        }
    }
}
```

If you prefer to choose the destination dynamically, you can omit `--host` (and even `--user`) from the CLI arguments and provide those fields in each `exec` tool call instead.

### Command Allowlist

All commands executed through the MCP server must match one of the wildcard patterns defined in `config/command-allowlist.json` (or a custom file provided via `--allowlist` or the `SSH_MCP_ALLOWLIST` environment variable). The bundled list is seeded with a broad set of read-only diagnostics, including:

- Network probes: `ping`, `traceroute`, `tracepath`, `mtr`, `dig`, `nslookup`, `host`, `whois`, `nc -vz`, `nmap -sn`, `socat -V`, `openssl s_client ...`, and `curl`/`wget` requests.
- Container and cluster discovery: `docker` read-only commands (containers/images/networks/volumes/logs/events/stats), Docker Compose inspection, and Docker Swarm/stack/service/node/config/secret queries for fleet visibility.
- Interface and routing introspection: `ip addr show`, `ip route show`, `ip neigh show`, `ifconfig -a`, `ethtool -i/-S`, `nmcli device show`, `ss -tuna`, `netstat -an`, `lsof -i`, `tcpdump -D`, `tshark -D`, `ipt(6)ables -L`, `firewall-cmd --list-all`, and `ufw status`.
- System observability: `journalctl -n`, `dmesg -T`, `tail -n`, `head -n`, `cat`, `grep`, `rg`, `ls -la`, `stat`, `ps aux`, `top -b -n 1`, `df -h`, `free -h`, `vmstat`, `iostat`, `sar`, `env`, `printenv`, `systemctl status`, `timedatectl`, `resolvectl status`, `showmount -e`, `lsblk`, and more.

Additional behavior:

- Patterns support the `*` wildcard and are matched against commands after whitespace is normalized.
- Command chaining via pipes (`|`), semicolons (`;`), logical operators (`&&`, `||`), backticks, `$()`, or redirection operators (`>`, `<`, `>>`, `<<`) is blocked even if the base command matches the allowlist, preventing command injection and write operations.
- When a command is rejected, the error message includes the full allowlist so the LLM can choose a permitted alternative.
- Update the JSON file to add or remove patterns as needed, then restart the MCP server so it reloads the configuration.

## Testing

You can use the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) for visual debugging of this MCP Server.

```sh
npm run inspect
```

## Disclaimer

SSH MCP Server is provided under the [MIT License](./LICENSE). Use at your own risk. This project is not affiliated with or endorsed by any SSH or MCP provider.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](./CONTRIBUTING.md) for more information.

## Code of Conduct

This project follows a [Code of Conduct](./CODE_OF_CONDUCT.md) to ensure a welcoming environment for everyone.

## Support

If you find SSH MCP Server helpful, consider starring the repository or contributing! Pull requests and feedback are welcome. 
