import os
import sys
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("WORKOS_API_KEY", "test-workos-key")
os.environ.setdefault("WORKOS_CLIENT_ID", "test-workos-client")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
