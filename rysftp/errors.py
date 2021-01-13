import logging
from functools import wraps
from paramiko.ssh_exception import (
    AuthenticationException,
    SSHException,
    NoValidConnectionsError,
)

logger = logging.getLogger(__name__)


def catch_errors(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (AuthenticationException, SSHException, NoValidConnectionsError):
            logger.exception("Connection Error")
        except BadTransferError:
            pass
        except OutsideAppContextError:
            logger.exception("RySftp Error")
        except NotAFileError as exc:
            logger.error(f"'{exc}' is not a valid file to transfer")
        except (LocalFileExistsError, RemoteFileExistsError) as exc:
            logger.error(f"File exists: {exc}")
        except Exception:
            logger.exception("Unexpected error")
    return wrapped


class LocalFileExistsError(FileExistsError):
    pass


class RemoteFileExistsError(FileExistsError):
    pass


class NotAFileError(Exception):
    pass


class OutsideAppContextError(RuntimeError):
    pass


class BadTransferError(IOError):
    pass
