import json
import os
import tempfile
import threading
from typing import Any


class JsonStore:
    """
    Thread-safe atomic JSON read/write helper.
    Prevents partially written / corrupted JSON files.
    """

    _global_lock = threading.Lock()

    @classmethod
    def load(cls, path: str, default: Any):
        if not os.path.exists(path):
            return default

        with cls._global_lock:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Type compatibility fallback
                if default is not None and not isinstance(data, type(default)):
                    return default

                return data
            except Exception:
                return default

    @classmethod
    def save(cls, path: str, data: Any):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        with cls._global_lock:
            fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=os.path.dirname(path) or ".")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())

                os.replace(tmp_path, path)
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
