# PwrSudo

Implements Unix-style `sudo` (elevated execution) for PowerShell on Windows, and SSH-key-based elevation helpers.

## Key Commands

### `sudo` / `Execute-Elevated <command> [args...]`

Runs a command elevated via `gsudo`. Requires `gsudo` to be installed (see `Enable-Execute-Elevated`).

```powershell
sudo net localgroup Administrators user /add
sudo Stop-Service wuauserv
```

### `elevate` / `Open-Elevated [-wait] <file> [args...]`

Launches an executable with the `runas` verb (UAC prompt). Use `-wait` to block until the elevated process exits.

```powershell
elevate pwsh -c "Set-ExecutionPolicy Unrestricted"
Open-Elevated -wait notepad C:\Windows\System32\drivers\etc\hosts
```

### `Enable-Execute-Elevated`

One-time setup: installs `gsudo` via Scoop and configures cache mode. Run once per machine; must be called from an admin shell or will re-invoke itself elevated.

## Notes

- `sudo` alias is set only on Windows (non-Unix); on Linux/macOS the system `sudo` is used instead.
- `Test-IsAdmin` returns `$true` if the current session is running as Administrator (Windows) or root (Unix).
- `Enable-SSH` — configures OpenSSH server/client on Windows and sets the default shell.
- `Add-AdministratorsAuthorizedKeys` — appends a public key to `administrators_authorized_keys` with proper ACLs.
