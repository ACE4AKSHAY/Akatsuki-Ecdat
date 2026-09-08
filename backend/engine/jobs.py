"""Single-process durable queue. Run exactly one API worker per state directory."""
import json
import fcntl
from backend.ingestion import state_dir
import logging
import threading
from backend.database import SessionLocal
from backend.models.db_models import Scan, ScanJob
from backend.engine.orchestrator import run_scan_pipeline_sync

log = logging.getLogger(__name__)


def recover_interrupted():
    with SessionLocal() as db:
        for scan in db.query(Scan).join(ScanJob, ScanJob.scan_id == Scan.id).filter(Scan.status == 'running'):
            scan.status = 'queued'
            scan.progress = 0
            scan.error = None
        db.commit()


def process_next():
    with SessionLocal() as db:
        scan = db.query(Scan).join(ScanJob, ScanJob.scan_id == Scan.id).filter(Scan.status == 'queued').order_by(Scan.created_at).first()
        if not scan:
            return False
        job = db.get(ScanJob, scan.id)
        args = json.loads(job.options_json)
        scan_id, source_type, target = scan.id, scan.source_type, scan.target
    run_scan_pipeline_sync(scan_id, source_type, target, **args)
    return True


class JobWorker:
    def __init__(self):
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True, name='ecdat-scan-worker')

    def start(self):
        self.lock_file = (state_dir() / 'worker.lock').open('a+')
        try:
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.lock_file.close()
            raise RuntimeError('Another ECDAT worker owns this state directory. Run one API worker.') from exc
        recover_interrupted()
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            try:
                if process_next():
                    continue
            except Exception:
                log.exception('Scan queue iteration failed')
            self.stop_event.wait(0.5)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=195)
        if not self.thread.is_alive():
            self.lock_file.close()
