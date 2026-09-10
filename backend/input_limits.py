"""Shared ingestion limits; environment values are positive integers in MiB/seconds."""
from dataclasses import dataclass
import os

MIB = 1024 * 1024


def _positive_integer(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    if not raw.isascii() or not raw.isdecimal() or int(raw) <= 0:
        raise ValueError(f'{name} must be a positive integer; received {raw!r}.')
    return int(raw)


@dataclass(frozen=True)
class InputLimits:
    upload_mib: int
    workspace_mib: int
    files: int
    inventory_mib: int
    git_timeout_seconds: int
    image_timeout_seconds: int

    def summary(self) -> str:
        return (f'Upload {self.upload_mib:,} MiB; workspace {self.workspace_mib:,} MiB; '
                f'{self.files:,} files/ZIP entries; image inventory {self.inventory_mib:,} MiB; '
                f'Git clone {self.git_timeout_seconds}s; image inventory {self.image_timeout_seconds}s.')


def get_input_limits() -> InputLimits:
    return InputLimits(
        upload_mib=_positive_integer('ECDAT_MAX_UPLOAD_MIB', 512),
        workspace_mib=_positive_integer('ECDAT_MAX_WORKSPACE_MIB', 2048),
        files=_positive_integer('ECDAT_MAX_FILES', 100000),
        inventory_mib=_positive_integer('ECDAT_MAX_INVENTORY_MIB', 128),
        git_timeout_seconds=_positive_integer('ECDAT_GIT_TIMEOUT_SECONDS', 600),
        image_timeout_seconds=_positive_integer('ECDAT_IMAGE_TIMEOUT_SECONDS', 600),
    )
