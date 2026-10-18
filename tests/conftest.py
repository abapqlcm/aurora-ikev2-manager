import os
import tempfile

os.environ.setdefault("AURORA_BACKUP_DIR", tempfile.mkdtemp(prefix="aurora-bak-"))
