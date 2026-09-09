# ECDAT setup and run guide

Use the supplied `ecdat.bat` on Windows. Choose **2 — Set up / repair dependencies**, then **3 — Run frontend and backend**. On later runs, choose 3 directly. The dashboard is **http://127.0.0.1:3001/** and the API is **http://127.0.0.1:8000/**.

Use the updated source package or a repository revision containing `ecdat.bat` and `scripts/launcher.py`. Extract the ZIP completely before running it. Create dependencies on each computer; do not transfer `.venv`, `node_modules`, `.ecdat`, or `ecdat.db` to perform a fresh installation.

## Requirements

| Tool | Version or requirement | Why it is needed |
| --- | --- | --- |
| Windows | Windows 10 or 11, preferably x64 | Target environment for the batch launcher |
| Python | 3.10 or newer; 3.12 recommended | API, scanners, worker and reports |
| Node.js | 22.12 or newer, including npm | Frontend installation, development and build |
| Git | 2.30 or newer, available on PATH | Repository installation and public Git scans |
| Browser | Current Chrome, Edge or Firefox | Local dashboard |
| Trivy | Optional, on PATH | Live container image inventory only |
| Storage and network | A writable project folder; internet for initial package installation | Virtual environment, npm packages, database and uploads |

The launcher checks tool versions, write access, Python package consistency, application imports and installed frontend dependencies. Setup installs packages from `requirements.txt`, `pyproject.toml` and `frontend/package-lock.json`, then builds the frontend. Source scanning and offline inventory input do not need Docker, a GPU, a quantum computer, or Trivy.

## First installation on Windows

1. Install Python, Node.js and Git. Enable Python's launcher and PATH option. Open a **new** Command Prompt after installation so it sees the updated PATH.
2. Put the project in a folder you can write to, such as `C:\Users\YourName\Documents\Akatsuki-Ecdat`. Paths with spaces are supported. Avoid installing the project under Program Files.
3. Open `ecdat.bat`, choose 2, and wait for **Setup complete**. Read any error before continuing.
4. Choose 1 to check the installation, then 3 to run it. The browser opens only after both services respond.
5. Keep the launcher window open. Press Ctrl+C to stop the services started by that launcher; the interactive menu then returns.

If Windows Package Manager is available, these commands install the main tools. Review any installer or license prompts normally:

```bat
winget install --id Python.Python.3.12 --exact
winget install --id OpenJS.NodeJS.LTS --exact
winget install --id Git.Git --exact
```

Verify the tools in the new terminal:

```bat
py -3.12 --version
node --version
npm.cmd --version
git --version
```

If `winget` is unavailable, use the official Python, Node.js and Git installers listed in References. The batch file tries Python 3.12, 3.11, 3.10, the launcher's default Python 3, and finally `python` on PATH. An unsupported interpreter produces an explanation rather than attempting to start the API.

## Launcher options

| Menu | Command | Behavior |
| --- | --- | --- |
| 1 | `ecdat.bat check` | Check tools, writable folders and installed dependencies |
| 2 | `ecdat.bat setup` | Create or repair `.venv`, install packages, run dependency checks and build the frontend |
| 3 | `ecdat.bat dev` | Start API and frontend together, open the dashboard and stop both with Ctrl+C |
| 4 | `ecdat.bat preview` | Build the frontend and serve the built files with the API for a local demonstration |
| 5 | `ecdat.bat backend` | Start the API only |
| 6 | `ecdat.bat frontend` | Start the development frontend only; the API must be started separately |
| 7 | `ecdat.bat test` | Run backend tests, frontend tests and production build |
| 8 | `ecdat.bat commands` | Print the underlying manual run commands |
| 9 | `ecdat.bat lan` | Build and share the dashboard on the local network, with an access token |
| 0 | Interactive menu only | Exit |

Run direct commands from Command Prompt in the repository root. In PowerShell, prefix the batch filename with `.` and a backslash: `.\ecdat.bat dev`. Local preview is for checking the built bundle; it is not a public production deployment.

For alternative ports or a terminal-only session:

```bat
ecdat.bat dev --api-port 8010 --ui-port 3010
ecdat.bat dev --no-browser
```

The launcher sets the frontend proxy to the selected API port. It reports port conflicts and does not terminate unrelated processes or silently select a different port. For separate backend and frontend launcher windows, give both the same `--api-port`.

## Share with other devices on the local network

After setup, choose **9** in the menu or run:

```bat
ecdat.bat lan
```

The launcher builds the frontend, listens on all IPv4 interfaces at port 3001, and prints candidate LAN links such as `http://192.168.1.20:3001/`. Use the address of the host's Wi-Fi or Ethernet adapter. The API stays on `127.0.0.1:8000`; the dashboard forwards `/api` requests to it. A client needs only a browser on the same network. It must use the host's LAN address, not `localhost` or `127.0.0.1`.

LAN mode uses `ECDAT_API_TOKEN` if set, otherwise generates a new token for that run. On each browser, expand **Workspace access token**, paste the token printed in the host terminal, and click **Connect**. A token-required message on first opening is expected. The token has full workspace access, including scans and deletion. It changes on restart unless you configure a fixed value. Use this HTTP mode only for a trusted local demonstration network; use HTTPS for a deployed service.

Keep the launcher open. Use `ecdat.bat lan --api-port 8010 --ui-port 3010` when the default ports are busy. On macOS/Linux the equivalent is `python3.12 scripts/launcher.py lan`.

### Windows network and firewall

1. Connect the host and client to the same trusted Wi-Fi or Ethernet network. A guest Wi-Fi or access-point isolation setting can prevent device-to-device access.
2. On the host, run `ipconfig` and use the IPv4 address of the active Wi-Fi/Ethernet adapter. VPN and virtual adapters may produce additional candidate links. DHCP can change the address later.
3. Confirm the trusted network uses the Windows **Private** profile. If Windows asks about Node.js firewall access, allow it for this private network.
4. If the firewall still blocks access, create this narrowly scoped rule from an Administrator PowerShell window on the host. Administrator rights are needed only to change the firewall, not to run ECDAT:

```powershell
$nodePath = (Get-Command node.exe).Source
New-NetFirewallRule -DisplayName "ECDAT LAN demo 3001" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3001 -Program $nodePath -Profile Private -RemoteAddress LocalSubnet
```

For a custom UI port, change both the port and rule name. Do not open the API port or configure router port forwarding. Remove the demo rule when no longer needed:

```powershell
Remove-NetFirewallRule -DisplayName "ECDAT LAN demo 3001"
```

From a second Windows computer, replace the example address with the host's address:

```powershell
Test-NetConnection 192.168.1.20 -Port 3001
curl.exe http://192.168.1.20:3001/api/health
```

`TcpTestSucceeded: True` and a healthy JSON response verify the connection. Then open the same host URL in the browser and connect with the token. If local access works but remote access fails, check the selected adapter address, firewall profile, VPN and Wi-Fi client isolation. A successful request from the host to its own LAN address does not prove that the router/firewall permits a second device.

Local path scans read files on the host. To scan a file from a phone or another computer, use **File or ZIP upload**. Only the host needs Python, Node.js, Git and the project dependencies. These modes use HTTP and do not require installing any bundled certificate.

### Underlying manual LAN commands

In the backend CMD terminal, configure a shared token and start the API:

```bat
set "ECDAT_API_TOKEN=replace-with-your-own-token"
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In the frontend CMD terminal:

```bat
cd frontend
set "API_PROXY_TARGET=http://127.0.0.1:8000"
npm.cmd run build
npm.cmd run preview -- --host 0.0.0.0 --port 3001 --strictPort
```

The token is a backend setting, not a Vite build variable. Use the same token in the browser. PowerShell uses `$env:ECDAT_API_TOKEN = 'your-token'` and `$env:API_PROXY_TARGET = 'http://127.0.0.1:8000'`; invoke the backend with `.\.venv\Scripts\python.exe`.

## Manual setup in Windows Command Prompt

Run each command from the repository root unless `cd` changes the directory:

```bat
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pip check
cd frontend
npm.cmd ci
npm.cmd ls --depth=0
npm.cmd run build
cd ..
.venv\Scripts\python.exe -c "import backend.main; print('Backend imports OK')"
```

If `.venv` came from an unsupported Python or another operating system, use the launcher's setup option. It moves an unusable environment into `.ecdat/venv-backups` before creating a replacement. It leaves the application database and uploads intact. Stop running services before repairing dependencies.

## Manual run after setup

Backend terminal, repository root:

```bat
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Frontend terminal, repository root:

```bat
cd frontend
set "API_PROXY_TARGET=http://127.0.0.1:8000"
npm.cmd run dev -- --host 127.0.0.1 --port 3001 --strictPort
```

For PowerShell, use these corresponding commands:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In another PowerShell terminal:

```powershell
cd frontend
$env:API_PROXY_TARGET = 'http://127.0.0.1:8000'
npm.cmd run dev -- --host 127.0.0.1 --port 3001 --strictPort
```

Check `http://127.0.0.1:8000/health` for a healthy response, then open `http://127.0.0.1:3001/`. API documentation is at `http://127.0.0.1:8000/docs`. Restart the backend after Python changes. Vite updates the frontend during development.

## Permissions and workspace access

Run ECDAT as your normal user. It needs read access to scan inputs and write access to the repository, `.venv`, `frontend/node_modules`, the configured database, and `.ecdat`. If access is denied, use a folder owned by your account or request the appropriate access from the machine owner. Do not grant broad drive permissions.

Virtual environment activation is optional: these commands call its Python executable directly. `ecdat.bat` and `npm.cmd` avoid the PowerShell script activation restriction, so no execution-policy change is needed. Default modes bind to `127.0.0.1`; a single-computer demo does not require a LAN-facing port or an inbound firewall rule. Initial installation and public Git or live image inputs need normal outbound network access.

To enable the optional shared access token, set it before launching. Replace the example value with your own token.

Command Prompt:

```bat
set "ECDAT_API_TOKEN=replace-with-your-own-token"
ecdat.bat dev
```

PowerShell:

```powershell
$env:ECDAT_API_TOKEN = 'replace-with-your-own-token'
.\ecdat.bat dev
```

Enter the same token under **Workspace access token** in the dashboard and click Connect. It stays in the tab's memory and must be entered again after reloading. The token protects scan creation, history deletion, inventory and exports. `/health` remains public; opening `/docs` directly also needs authentication when protection is enabled.

## Usage and demonstration

1. Choose **Local path**, enter `demo/workspace`, and start a scan. The supplied fixture produces 10 assets and 3 Critical findings with the default assessment.
2. Review Overview, then search for SHA or TLS in Inventory. Open an asset to see its source location, recommendation and risk inputs.
3. On Risk heatmap, adjust the quantum threat timeline Z. Years display with at most two decimals. X is required data confidentiality lifetime, Y is migration duration, and Z is an assumed threat horizon, not a prediction.
4. The heatmap groups assets by business criticality and assessed risk tier. Each cell shows the number of findings, so overlapping assets are not hidden. Select a populated cell to list its assets, then open one for details.
5. Heatmap changes are temporary. Downloads retain the saved scan assessment. Recommendations provides PDF, CSV, XLSX and CBOM JSON downloads.
6. Use Scan history to reopen earlier work. **Delete selected** removes the selected scan and **Delete all** clears the saved history after confirmation. Deletion persists after reload.
7. Deletion removes database records, findings, recommendations, job options and the stored report data. Original source files, uploaded input copies in `.ecdat/uploads`, and already downloaded reports are retained. There is no undo. Wait for queued/running scans to finish before deleting them; deleting all is rejected if any scan is still active.

For a ZIP example, open PowerShell in the repository root:

```powershell
Compress-Archive -Path .\demo\workspace\* -DestinationPath .\demo-workspace.zip -Force
```

Upload the resulting ZIP using **File or ZIP upload**. For an offline container example, select **Container image or SBOM** and upload `demo/image-inventory.json`; it produces 2 package findings. A public Git example is `https://github.com/ACE4AKSHAY/Akatsuki-Ecdat`. Git counts vary with repository content. Uploaded source code is inspected statically, not executed.

With the API already running, run the repeatable sample-and-export check:

```bat
.venv\Scripts\python.exe scripts\demo_smoke.py --output work\demo-results
```

## Test inputs and certificate files

See [Test code and sample scan inputs](TEST_DATA.md) for the automated test folders, sample source/configuration/manifests, and the four PEM certificate fixtures. Install only the repository-root requirements for ECDAT; requirements files inside `demo` and `seed_corpus` are inputs for scanning. The PEM files are public self-signed test certificates and are not HTTPS server credentials or certificates to install in Windows.

## macOS and Linux

Use a Python 3.10+ interpreter; Python 3.12 is recommended. There is no need to use the batch wrapper:

```sh
python3.12 scripts/launcher.py setup
python3.12 scripts/launcher.py check
python3.12 scripts/launcher.py dev
```

Underlying backend command: `.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`. In a second terminal, `cd frontend` and run `npm run dev`. To set a token, use `export ECDAT_API_TOKEN='your-token'` before starting the backend or launcher.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Python/Node/Git not found or too old | Install the required version and reopen the terminal. Run option 1. |
| No module named fastapi or filelock | Run setup with a supported Python. Use `.venv\Scripts\python.exe`, not another global interpreter. |
| Python 3.9 environment | Run setup with Python 3.12 so it backs up and replaces the incompatible environment. |
| npm.ps1 cannot be loaded | Use `npm.cmd` or the batch launcher; no execution-policy change is needed. |
| Access denied / files locked | Stop running services and use a writable local folder. Do not disable antivirus or broaden permissions to the whole drive. |
| Port unavailable | Close the existing app yourself or use `--api-port` and `--ui-port`. |
| Another worker owns the state directory | Stop the earlier ECDAT instance. Run one API worker per state directory; do not delete a live worker's lock. |
| 401 / access token required | Enter the configured token. Re-enter it after reloading the tab. |
| Backend error or blank frontend | Run `ecdat.bat check`; inspect `.ecdat/logs/backend.log` and `.ecdat/logs/frontend.log`; verify health and proxy ports. |
| Dependency install or native package build fails | Confirm Python 3.12 and a current x64 Node installation, network access and the exact pip/npm error. Do not bypass package integrity checks. |
| Local target not found | Resolve paths from the backend's repository root or use an existing absolute Windows path. |
| Delete all refused | Wait until every queued or running scan finishes, then retry. |
| Live image scan unavailable | Install Trivy separately or use the offline JSON fixture. |

Tests automatically use temporary storage and can run alongside the app. With manual startup, logs appear in their respective terminals. With the launcher, logs are under `.ecdat/logs`. Local history uses `ecdat.db` by default. Keep the database and `.ecdat` if you want to preserve results across restarts.

Validation for this update includes automated backend/frontend tests, a fresh installation in a path containing spaces, and browser checks on macOS. The compatibility workflow runs batch setup, tests, build, LAN proxy and process-shutdown checks on a Windows runner. Check its result for the revision you use; a second device on your own Windows network must still verify the firewall/router connection. Trivy live scanning is also unverified here. If a Windows issue occurs, share the selected launcher option, version-check output and relevant log excerpt, with access tokens removed.

## References

- [Python on Windows](https://docs.python.org/3.12/using/windows.html)
- [Node.js downloads](https://nodejs.org/en/download)
- [Git downloads](https://git-scm.com/downloads)
- [Microsoft WinGet install command](https://learn.microsoft.com/en-us/windows/package-manager/winget/install)
- [Filelock documentation](https://py-filelock.readthedocs.io/en/latest/)

- [Vite host and proxy options](https://vite.dev/config/server-options)
- [Windows firewall rule parameters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)
