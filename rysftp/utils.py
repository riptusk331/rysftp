import logging
import csv
from shutil import copy
from datetime import date
from typing import Union, List
from pathlib import Path

logger = logging.getLogger(__name__)
"""

"""

def moveAndDateStamp(
    src_file: Union[str, Path],
    tgt_dir: Union[str, Path, List[Union[str, Path]]],
    format: str = None,
    rename: str = None,
) -> List[Path]:
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


def moveAndCopy(
    src_file: Union[str, Path],
    tgt_dir: Union[str, Path, List[Union[str, Path]]],
    rename: str = None,
) -> List[Path]:
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


def add_ms_basket_prefix(tgt_file: Union[str, Path]) -> bool:
    """Adds the 'MSCMS' prefix to the 'basket_id' column in the MS Stovell basket file

    Arguments:
        tgt_file {Union[str, Path]} -- the target CSV file to edit

    Returns:
        bool -- return True if successful
    """
    if Path(tgt_file).exists():
        try:
            with open(tgt_file, "r") as f:
                reader = csv.reader(f, delimiter=",")
                prepend = [next(reader)]
                for line in reader:
                    if len(line) == 5:
                        basket_num = "{:03d}".format(int(line[4]))
                        prepend.append([*line[:4], f"MSCMS{basket_num}"])
            with open(tgt_file, "w") as f:
                writer = csv.writer(
                    f, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
                )
                for row in prepend:
                    writer.writerow(row)
            return True
        except IOError:
            logger.error(f'Error accessing file "{tgt_file}""')
            return False
    else:
        logger.error(f'Target file "{tgt_file}" not found')
        return False


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
