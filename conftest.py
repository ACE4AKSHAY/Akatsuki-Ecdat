"""Keep backend tests separate from the running application's data and worker."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory


# Configure storage before pytest imports the API and its SQLAlchemy engine.
_test_storage = TemporaryDirectory(prefix="ecdat-pytest-")
_test_root = Path(_test_storage.name)
os.environ["DATABASE_URL"] = os.environ.get(
    "ECDAT_TEST_DATABASE_URL", f"sqlite:///{_test_root / 'tests.db'}"
)
os.environ["ECDAT_STATE_DIR"] = str(_test_root / "state")
os.environ.pop("ECDAT_API_TOKEN", None)


def pytest_sessionfinish(session, exitstatus):
    from backend.database import engine

    engine.dispose()
    _test_storage.cleanup()
