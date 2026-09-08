"""Bounded static ingestion for local workspaces, HTTPS Git repositories and ZIPs."""
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from urllib.parse import urlsplit

MAX_UPLOAD = 20 * 1024 * 1024
MAX_EXPANDED = 100 * 1024 * 1024
MAX_FILES = 10000


def state_dir():
    path = Path(os.getenv('ECDAT_STATE_DIR', '.ecdat')).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def validate_git_url(target):
    url = urlsplit(target)
    allowed = os.getenv('ECDAT_GIT_HOSTS', 'github.com,gitlab.com,bitbucket.org').split(',')
    if (url.scheme != 'https' or url.hostname not in allowed or url.username or url.password
            or url.port not in (None, 443) or url.query or url.fragment
            or not re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+/?', url.path)):
        raise ValueError('Use an HTTPS repository URL on an allowed Git host, without credentials or query parameters.')
    return target


def validate_input(source_type, target):
    if source_type == 'git':
        return validate_git_url(target.strip())
    if source_type == 'image':
        from backend.scanners.infra.container import validate_image_input
        return validate_image_input(target.strip())
    root = Path(target.strip()).expanduser().resolve()
    if not target.strip() or not root.exists() or not (root.is_file() or root.is_dir()):
        raise ValueError('Scan target does not exist. Enter a local file or directory path.')
    if source_type == 'upload' and not root.is_relative_to(state_dir() / 'uploads'):
        raise ValueError('Submit uploaded files using POST /scans/upload.')
    if source_type not in ('path', 'upload'):
        raise ValueError('Unsupported input type.')
    return str(root)


def extract_zip(archive, destination):
    """Extract regular files only, with member/count/expanded-size limits."""
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_FILES or sum(m.file_size for m in members) > MAX_EXPANDED:
            raise ValueError('ZIP exceeds 100 MB expanded size or 10000 entries.')
        for member in members:
            name = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (name.is_absolute() or '..' in name.parts or '\\' in member.filename
                    or stat.S_ISLNK(mode) or member.flag_bits & 1):
                raise ValueError('ZIP must contain ordinary unencrypted files with relative paths.')
            if member.is_dir():
                continue
            out = destination.joinpath(*name.parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as src, out.open('wb') as dst:
                shutil.copyfileobj(src, dst)


@contextmanager
def prepared_target(source_type, target):
    if source_type == 'git':
        with tempfile.TemporaryDirectory(prefix='git-', dir=state_dir()) as tmp:
            destination = Path(tmp) / 'repository'
            env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
            try:
                result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'http.followRedirects=false',
                    '-c', 'protocol.file.allow=never', 'clone', '--depth', '1', '--single-branch', '--no-tags',
                    '--', validate_git_url(target), str(destination)], env=env, capture_output=True, timeout=120)
            except subprocess.TimeoutExpired as exc:
                raise ValueError('Git clone exceeded the 120 second limit.') from exc
            if result.returncode:
                raise ValueError('Git clone failed. Verify the public repository URL and network access.')
            snapshot = Path(tmp) / "snapshot"
            snapshot.mkdir()
            snapshot_workspace(destination, snapshot)
            yield snapshot
    elif source_type == 'upload' and zipfile.is_zipfile(target):
        with tempfile.TemporaryDirectory(prefix='zip-', dir=state_dir()) as tmp:
            root = Path(tmp)
            extract_zip(target, root)
            yield root
    else:
        source = Path(target)
        if source.is_dir():
            with tempfile.TemporaryDirectory(prefix="workspace-", dir=state_dir()) as tmp:
                snapshot_workspace(source, Path(tmp))
                yield Path(tmp)
        else:
            yield source


def snapshot_workspace(source, destination):
    """Copy bounded regular files; exclude tool output and linked filesystem content."""
    excluded = {'.git', '.venv', '.venv-runtime', 'venv', 'node_modules', '__pycache__', '.ecdat', 'dist', 'work'}
    count = total = 0
    for root, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = [name for name in dirs if name not in excluded and not Path(root, name).is_symlink()]
        for name in files:
            src = Path(root, name)
            if src.is_symlink() or not src.is_file():
                continue
            count += 1
            total += src.stat().st_size
            if count > MAX_FILES or total > MAX_EXPANDED:
                raise ValueError('Workspace exceeds 100 MB or 10000 files after dependency/output exclusions.')
            dst = destination / src.relative_to(source)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
