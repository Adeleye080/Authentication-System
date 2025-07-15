import logging
from logging.handlers import TimedRotatingFileHandler
import os
from datetime import datetime


def find_project_root(marker_files=("requirements.txt", "pyproject.toml", ".git")):
    current_dir = os.path.abspath(os.path.dirname(__file__))
    while current_dir != os.path.dirname(current_dir):  # Stop at the filesystem root
        if any(
            os.path.exists(os.path.join(current_dir, marker)) for marker in marker_files
        ):
            return current_dir
        current_dir = os.path.dirname(current_dir)
    return os.path.abspath(os.path.dirname(__file__))


def setup_logging():
    # Get the project dir
    project_root = find_project_root()
    date_str = datetime.now().strftime("%d_%m_%Y")

    log_dir = os.path.join(project_root, "app_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "app.log")
    # Set up timed rotating handler (rotates daily)
    handler = TimedRotatingFileHandler(
        log_path, when="midnight", interval=1, backupCount=7, encoding="utf-8"
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            handler
            # logging.StreamHandler(),  # Also log to the console (optional)
        ],
    )
