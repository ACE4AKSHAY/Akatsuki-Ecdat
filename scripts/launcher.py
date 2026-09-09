"""Local setup and process launcher for Windows, macOS and Linux (stdlib only)."""
from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / 'frontend'
STATE = ROOT / '.ecdat'
MIN_PYTHON = (3, 10, 0)
MIN_NODE = (22, 12, 0)
MIN_GIT = (2, 30, 0)


class LauncherError(RuntimeError):
    pass


def version_tuple(value: str):
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', value)
    if not match:
        raise LauncherError(f'Cannot read a version from: {value.strip()}')
    return tuple(int(part or 0) for part in match.groups())


def venv_python():
    return ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def process_arguments(args):
    """npm.cmd is a Windows command script; all its arguments here are fixed commands."""
    args = [str(arg) for arg in args]
    if os.name == 'nt' and Path(args[0]).suffix.lower() in ('.cmd', '.bat'):
        # Always quote the executable: a Windows username can contain '&'
        # even when its path contains no spaces.
        return f'"{args[0]}" ' + subprocess.list2cmdline(args[1:]), True
    return args, False


def command(args, *, cwd=ROOT, capture=False, env=None):
    argv, use_shell = process_arguments(args)
    try:
        result = subprocess.run(argv, cwd=cwd, shell=use_shell, env=env,
                                text=True, capture_output=capture, check=False)
    except OSError as exc:
        raise LauncherError(f'Cannot run {args[0]}: {exc}') from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or '').strip() if capture else ''
        raise LauncherError(f'Command failed ({result.returncode}): {args[0]} {" ".join(map(str, args[1:]))}\n{detail}')
    return result.stdout.strip() if capture else ''


def npm():
    executable = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
    if not executable:
        raise LauncherError('npm is missing. Install Node.js with npm, then reopen the terminal.')
    return executable


def check_tools(frontend=True):
    if sys.version_info[:3] < MIN_PYTHON:
        raise LauncherError('Python 3.10+ is required. Python 3.12 is recommended.')
    print(f'[OK] Python {sys.version.split()[0]}: {sys.executable}', flush=True)
    requirements = [('git', MIN_GIT)] + ([('node', MIN_NODE)] if frontend else [])
    for name, minimum in requirements:
        executable = shutil.which(name)
        if not executable:
            raise LauncherError(f'{name} is missing from PATH. Install it and reopen the terminal.')
        output = command([executable, '--version'], capture=True)
        if version_tuple(output) < minimum:
            raise LauncherError(f'{name} {".".join(map(str, minimum))}+ is required; found {output}.')
        print(f'[OK] {output}: {executable}', flush=True)
    if frontend:
        print(f'[OK] npm {command([npm(), "--version"], capture=True)}', flush=True)
    for folder in (ROOT, STATE):
        try:
            folder.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryFile(dir=folder):
                pass
        except OSError as exc:
            raise LauncherError(f'Cannot write to {folder}. Use a folder owned by your account, such as Documents. {exc}') from exc
    print('[OK] Repository and local state are writable. Administrator rights are not required.', flush=True)
    print('[INFO] Trivy: ' + ('available' if shutil.which('trivy') else 'not installed; live images unavailable, offline JSON works'), flush=True)


def check_backend():
    python = venv_python()
    if not python.is_file():
        raise LauncherError('Backend environment is missing. Run setup first; do not copy .venv from another machine.')
    version = command([python, '-c', 'import sys; print(".".join(map(str, sys.version_info[:3])))'], capture=True)
    if version_tuple(version) < MIN_PYTHON:
        raise LauncherError('The existing .venv uses an unsupported Python version. Run setup to replace it with a backup.')
    command([python, '-m', 'pip', 'check'])
    command([python, '-c', 'import fastapi, uvicorn, pydantic, sqlalchemy, httpx, multipart, reportlab, openpyxl, tree_sitter, tree_sitter_python, tree_sitter_java, tree_sitter_javascript, tree_sitter_go, cryptography, yaml, packaging, filelock; import backend.main; print("[OK] Backend dependencies and application imports")'])


def check_frontend():
    if not (FRONTEND / 'node_modules').is_dir():
        raise LauncherError('Frontend dependencies are missing. Run setup first.')
    command([npm(), 'ls', '--depth=0'], cwd=FRONTEND)


def setup():
    check_tools()
    old = ROOT / '.venv'
    usable = False
    if venv_python().is_file():
        try:
            current = command([venv_python(), '-c', 'import sys; print(".".join(map(str, sys.version_info[:3])))'], capture=True)
            usable = version_tuple(current) >= MIN_PYTHON
        except LauncherError:
            pass
    if old.exists() and not usable:
        backup = STATE / 'venv-backups' / datetime.now().strftime('venv-%Y%m%d-%H%M%S-%f')
        backup.parent.mkdir(parents=True, exist_ok=True)
        old.rename(backup)
        print(f'[INFO] Previous unusable environment moved to {backup}', flush=True)
    if not usable:
        command([sys.executable, '-m', 'venv', str(old)])
    command([venv_python(), '-m', 'pip', 'install', '--upgrade', 'pip'])
    command([venv_python(), '-m', 'pip', 'install', '-r', 'requirements.txt'])
    command([npm(), 'ci'], cwd=FRONTEND)
    check_backend()
    check_frontend()
    command([npm(), 'run', 'build'], cwd=FRONTEND)
    print('\nSetup complete. Choose dev to start both services, or preview to build and run locally.', flush=True)


def require_free_port(port, host='127.0.0.1'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError as exc:
            raise LauncherError(f'Port {port} is unavailable. Close the server using it, or select another --api-port / --ui-port. No existing processes were stopped.') from exc


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        if os.name == 'nt':
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)


def local_ipv4_addresses():
    """Find candidate LAN addresses without sending network requests."""
    addresses = set()
    try:
        addresses.update(item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # UDP connect only selects a route; no packets are sent.
            sock.connect(('192.0.2.1', 80))
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass
    return sorted(address for address in addresses if not address.startswith('127.') and address != '0.0.0.0')


def service_environment(mode, api_port):
    environment = dict(os.environ, API_PROXY_TARGET=f'http://127.0.0.1:{api_port}')
    if mode == 'lan' and not environment.get('ECDAT_API_TOKEN'):
        environment['ECDAT_API_TOKEN'] = secrets.token_urlsafe(24)
    return environment


def run_services(mode, api_port, ui_port, no_browser):
    backend = mode != 'frontend'
    frontend = mode != 'backend'
    ui_host = '0.0.0.0' if mode == 'lan' else '127.0.0.1'
    if backend and frontend and api_port == ui_port:
        raise LauncherError('The backend and frontend need different ports.')
    check_tools(frontend=frontend)
    if backend:
        check_backend()
        require_free_port(api_port)
    if frontend:
        check_frontend()
        require_free_port(ui_port, ui_host)
    if mode in ('preview', 'lan'):
        command([npm(), 'run', 'build'], cwd=FRONTEND)
    # Run Vite through node directly so process ownership is reliable on Windows.
    environment = service_environment(mode, api_port)
    specifications = []
    if backend:
        specifications.append(('backend', [venv_python(), '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', str(api_port)], ROOT, f'http://127.0.0.1:{api_port}/health'))
    if frontend:
        vite_args = ['preview'] if mode in ('preview', 'lan') else []
        specifications.append(('frontend', [shutil.which('node'), FRONTEND / 'node_modules/vite/bin/vite.js', *vite_args, '--host', ui_host, '--port', str(ui_port), '--strictPort'], FRONTEND, f'http://127.0.0.1:{ui_port}/'))
    processes = []
    logs = []
    log_dir = STATE / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        for name, args, cwd, url in specifications:
            log_path = log_dir / f'{name}.log'
            log = log_path.open('a', encoding='utf-8')
            logs.append(log)
            kwargs = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
            process = subprocess.Popen(list(map(str, args)), cwd=cwd, env=environment, stdout=log, stderr=subprocess.STDOUT, **kwargs)
            processes.append(process)
            deadline = time.monotonic() + 30
            ready = False
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise LauncherError(f'{name} stopped during startup. Read {log_path}.')
                try:
                    with urlopen(url, timeout=1) as response:
                        if response.status == 200:
                            ready = True
                            break
                except (URLError, OSError):
                    time.sleep(.2)
            if not ready:
                raise LauncherError(f'{name} did not become ready within 30 seconds. Read {log_path}.')
            print(f'[RUNNING] {name}: {url}\n          Log: {log_path}', flush=True)
        if mode == 'lan':
            for address in local_ipv4_addresses():
                print(f'[LAN] http://{address}:{ui_port}/', flush=True)
            print(f'[LAN] Workspace access token: {environment["ECDAT_API_TOKEN"]}', flush=True)
            print('On each device, open a LAN URL, expand Workspace access token, paste the token and click Connect.\nUse the same trusted local network. Allow the dashboard port on the Windows Private firewall profile if needed.\nThe API stays on loopback; uploads select files from the client, while Local path refers to the host computer.', flush=True)
        if frontend and not no_browser:
            webbrowser.open(f'http://127.0.0.1:{ui_port}/')
        print('Keep this window open. Press Ctrl+C to stop the services started here.', flush=True)
        while all(process.poll() is None for process in processes):
            time.sleep(.5)
        raise LauncherError('A service exited. Check .ecdat/logs; the other service will be stopped.')
    except KeyboardInterrupt:
        print('\nStopping ECDAT...', flush=True)
    finally:
        for process in reversed(processes):
            stop_process(process)
        for log in logs:
            log.close()


def print_commands(api_port, ui_port):
    python = '.venv\\Scripts\\python.exe' if os.name == 'nt' else '.venv/bin/python'
    print(f'''Run these from the repository root after setup:
{python} -m pip check
{python} -m uvicorn backend.main:app --host 127.0.0.1 --port {api_port}

In a second terminal:
cd frontend
npm run dev -- --host 127.0.0.1 --port {ui_port} --strictPort

Set API_PROXY_TARGET=http://127.0.0.1:{api_port} in the frontend terminal if using a custom API port.
Open http://127.0.0.1:{ui_port}/. Press Ctrl+C in both terminals to stop.
See documentation/SETUP_AND_RUN.md for CMD, PowerShell, token and permission instructions.''')


def execute(args):
    if args.action == 'setup':
        setup()
    elif args.action == 'check':
        check_tools()
        check_backend()
        check_frontend()
    elif args.action == 'test':
        check_tools()
        check_backend()
        check_frontend()
        command([venv_python(), '-m', 'pytest', '-q'])
        command([npm(), 'test'], cwd=FRONTEND)
        command([npm(), 'run', 'build'], cwd=FRONTEND)
    elif args.action == 'commands':
        print_commands(args.api_port, args.ui_port)
    else:
        run_services(args.action, args.api_port, args.ui_port, args.no_browser)


def port(value):
    number = int(value)
    if not 1024 <= number <= 65535:
        raise argparse.ArgumentTypeError('Use a port between 1024 and 65535.')
    return number


def main():
    if os.name == 'nt':
        # Treat Ctrl+Break like Ctrl+C so owned child processes are cleaned up.
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['check', 'setup', 'dev', 'preview', 'lan', 'backend', 'frontend', 'test', 'commands'])
    parser.add_argument('--api-port', type=port, default=8000)
    parser.add_argument('--ui-port', type=port, default=3001)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.action:
        try:
            execute(args)
            return 0
        except (LauncherError, OSError) as exc:
            print(f'\n[ERROR] {exc}', file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            return 130
    choices = {'1': 'check', '2': 'setup', '3': 'dev', '4': 'preview', '5': 'backend', '6': 'frontend', '7': 'test', '8': 'commands', '9': 'lan'}
    while True:
        print('\nECDAT local launcher\n1  Check tools, permissions and dependencies\n2  Set up / repair dependencies\n3  Run frontend and backend (development)\n4  Build and run frontend + backend (local preview)\n5  Run backend only\n6  Run frontend only\n7  Run tests and production build\n8  Show manual run commands\n9  Share built dashboard on local network\n0  Exit')
        try:
            selected = input('Choose an option: ').strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if selected == '0':
            return 0
        if selected not in choices:
            print('Choose 0 through 9.')
            continue
        args.action = choices[selected]
        try:
            execute(args)
        except (LauncherError, OSError) as exc:
            print(f'\n[ERROR] {exc}', file=sys.stderr)
        except KeyboardInterrupt:
            print('\nCancelled.')


if __name__ == '__main__':
    sys.exit(main())
