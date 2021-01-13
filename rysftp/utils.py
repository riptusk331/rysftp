import logging
from shutil import copy
from datetime import date
from pathlib import Path

logger = logging.getLogger(__name__)
"""

"""

def moveAndDateStamp(src_file, tgt_dir, format, rename):
    """
    Moves a file and stamps the date on it. Creates target directory if it doesn't exist

    Returns the new stamped filename if successful
    """
    if Path(src_file).exists():
        copied = []
        if not isinstance(tgt_dir, list):
            tgt_dir = [tgt_dir]
        for tgt in tgt_dir:
            Path(tgt).mkdir(parents=True, exist_ok=True)
            if rename:
                stem = rename
            else:
                stem = Path(src_file).stem
            if format:
                date_stamp = date.today().strftime(format)
            else:
                date_stamp = str(date.today())
            new = f"{stem}_{date_stamp}{Path(src_file).suffix}"
            tgt_file = Path(tgt, new)
            try:
                copy(src_file, tgt_file)
                logger.info(f'Moved & stamped "{Path(src_file)}" --> "{tgt_file}')
                return tgt_file
            except:
                logger.exception(f'Unexpected error copying "{src_file}"')
        return copied
    else:
        logger.error(f'Source file "{src_file}" not found')


def moveAndCopy(src_file, tgt_dir, rename):
    """
    Copies a file from one location to another. Creates target directory if it doesn't exist

    Returns filename if successful.
    """
    if Path(src_file).exists():
        copied = []
        if not isinstance(tgt_dir, list):
            tgt_dir = [tgt_dir]
        for tgt in tgt_dir:
            Path(tgt).mkdir(parents=True, exist_ok=True)
            if rename:
                new = f"{rename}{Path(src_file).suffix}"
            else:
                new = Path(src_file).name
            tgt_file = Path(tgt, new)
            try:
                copy(src_file, tgt_file)
                copied.append(tgt_file)
                logger.info(f'Copied "{Path(src_file)}" --> "{tgt_file}')
            except:
                logger.exception(f'Unexpected error copying "{src_file}"')
        return copied
    else:
        logger.error(f'Source file "{src_file}" not found')


def _getSecret(secret_name):
    """
    Reads the contents of mounted docker secrets.

    Used when running in docker
    """
    try:
        with open(f"/run/secrets/{secret_name}", "r") as s:
            secret = s.read().strip()
        return secret
    except FileNotFoundError:
        logger.error(f'Error: no secret found for "{secret_name}"')
    except Exception:
        logger.exception("Unknown error")
