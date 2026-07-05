"""
quarantine.py
-------------
Handles moving flagged files into a quarantine folder so they can no
longer be accidentally opened or executed from their original location.
"""

import os
import shutil
import time


def quarantine_file(file_path, quarantine_dir):
    """
    Move a flagged file into the quarantine directory.

    The file is renamed with a timestamp prefix and a ".quarantined"
    suffix so it won't be double-clicked or run by accident, and so
    multiple files with the same name don't collide.

    Returns the new path, or None if the move failed.
    """
    os.makedirs(quarantine_dir, exist_ok=True)

    original_name = os.path.basename(file_path)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    safe_name = f"{timestamp}_{original_name}.quarantined"
    destination = os.path.join(quarantine_dir, safe_name)

    try:
        shutil.move(file_path, destination)
        return destination
    except (IOError, OSError) as e:
        print(f"[!] Failed to quarantine {file_path}: {e}")
        return None
