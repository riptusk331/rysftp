import logging
from os import getenv
from threading import Lock, Thread, Event
from stat import S_ISREG
from functools import wraps
from pathlib import Path
from paramiko import Transport, SFTPClient, Message
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp import (
    CMD_CLOSE,
    CMD_DATA,
    CMD_OPEN,
    CMD_READ,
    CMD_HANDLE,
    CMD_STATUS, 
    CMD_WRITE,
    SFTP_FLAG_CREATE,
    SFTP_FLAG_READ,
    SFTP_FLAG_TRUNC,
    SFTP_FLAG_WRITE,
    SFTPError,
)

try:
    from gnupg import GPG
except ImportError:
    pass

from .ctx import (
    RyContext,
    _ry_ctx_stack,
    _ry_ctx_err_msg,
    _request_buffer,
    _event_stack,
    g,
    lo,
)
from .errors import (
    catch_errors,
    LocalFileExistsError,
    OutsideAppContextError,
)


log = logging.getLogger(__name__)


class long(int):
    pass


class _RySftpConfig:
    def __init__(self, **kwargs):
        self.remotedir = kwargs.get("remotedir", ".")
        self.localdir = kwargs.get("localdir", ".")
        self.overwrite_local = kwargs.get("overwrite_local", True)
        self.overwrite_remote = kwargs.get("overwrite_remote", True)

        self.gpgdir = kwargs.get("gpgdir", None)
        self.gpg_passphrase = kwargs.get("gpg_passphrase", None)

        @property
        def localdir(self):
            return str(self._localdir)

        @localdir.setter
        def localdir(self, value):
            if Path(value).is_dir():
                self._localdir = Path(value)

        @property
        def gpgdir(self):
            return None if not self._gpgdir else str(self._gpgdir)

        @gpgdir.setter
        def gpgdir(self, value):
            if Path(value).is_dir():
                self._gpgdir = Path(value)


class RySftp:
    """
    Copyright (C) 2020  Ryan Joyce <ryan.joyce.88@gmail.com>

    My first attempt at building a utility that securely connects
    to an SFTP server and downloads a file.

    I make use of the 'Paramiko' package to connect to SFTP servers, and
    shamelessly rip off the concept of Flask's application context.

    It also includes PGP decryption capability, provided by the
    'python-gnupg' package.
    """

    @catch_errors
    def __init__(self, **kwargs):
        self.user = kwargs.get('user', getenv('RYSFTP_USER'))
        self.password = kwargs.get('password', getenv('RYSFTP_PASSWORD'))
        self.hostname = kwargs.get('hostname', getenv('RYSFTP_HOSTNAME'))
        port = kwargs.get("port", getenv("RYSFTP_PORT"))
        self.port = int(port or 22)
        self.config = _RySftpConfig(**kwargs)

        self._t = Transport((self.hostname, self.port))
        # enable ultra debugging while building
        self._t.set_hexdump(False)

        self._sftp = None
        self._gpg = self.gpg_instance()
        self._connected = False
        self._lock = Lock()

        self._downloaded = []
        self._uploaded = []

    def __call__(self, *args, **kwargs):
        if kwargs.get("remotedir") or args:
            self.config.remotedir = args[0] if args else kwargs["remotedir"]
        return self

    @catch_errors
    def __enter__(self):
        self._t.connect(None, self.user, self.password)
        self._sftp = SFTPClient.from_transport(self._t)
        self._connected = True
        self._sftp.chdir(self.config.remotedir)

        ctx = _ry_ctx_stack.top
        if ctx is None or ctx.ry != self:
            ctx = self.ry_context()
            ctx.push()
        return self

    @catch_errors
    def __exit__(self, exc_type, exc_value, traceback):
        self._t.close()
        self._sftp.close()
        self._connected = False

        ctx = _ry_ctx_stack.top
        if ctx is not None:
            ctx.pop()

    def connects(f):
        @wraps(f)
        @catch_errors
        def wrapped(self, *args, **kwargs):
            ry_ctx = _ry_ctx_stack.top
            # If we're in a background thread, push an app context
            if kwargs.pop("thread", False) is True:
                log.debug("Running In Child Thread")
                with self.ry_context():
                    return f(self, *args, **kwargs)
            if ry_ctx is not None and ry_ctx.ry == self and self._connected:
                return f(self, *args, **kwargs)
            raise OutsideAppContextError(_ry_ctx_err_msg)
        return wrapped

    def secure(f):
        """
        NOT IMPLEMENTED YET
        WRAPPER TO CHECK IF WE WANT TO ENABLE GNUPG ENCRYPTION ON FILES
        TRANSFERRED

        Args:
            f ([type]): [description]

        Returns:
            [type]: [description]
        """

        @wraps(f)
        @catch_errors
        def wrapped(self, *args, **kwargs):
            if kwargs.get("decrypt"):
                pass
            elif kwargs.get("encrypt"):
                pass
            return f(self, *args, **kwargs)
        return wrapped

    def ry_context(self):
        return RyContext(self)

    def gpg_instance(self):
        if self.config.gpgdir:
            return GPG(gnupghome=self.config.gpgdir)

    @connects
    def dirlist(self, full_remotepath=False):
        """
        Returns a directory list of the passed remote directory (remotedir)

        If a remote directory is not passed in, it uses the home directory
        """
        dirlist = self._sftp.listdir()
        if full_remotepath:
            dirlist = [f"{self.config.remotedir}/{d}" for d in dirlist]
        return dirlist

    def open(self, filename, mode="r"):
        """
        Open a remote file, ``filename``, on the server for reading
        or writing.

        Args:
            filename (str): name of remote file to open
            mode (str): mode to open file in
        """
        filename = self.encode_path(filename)
        pflags = 0
        if "r" in mode:
            pflags |= SFTP_FLAG_READ
        if "w" in mode:
            pflags |= SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_TRUNC
        attrs = SFTPAttributes()
        resp_type, msg = self._request(CMD_OPEN, filename, pflags, attrs)
        if resp_type != CMD_HANDLE:
            raise SFTPError("Expected remote file handle")
        return msg.get_binary()

    def read(self, handle, size):
        """
        Read ```size``` bytes from the remote file indicated by the
        server supplied ``handle``

        Args:
            handle (str): remote file handle to read
            size (int): bytes to read
        """
        resp_type, msg = self._request(CMD_READ, handle, long(0), size)
        if resp_type != CMD_DATA:
            raise SFTPError("Expected data")
        return msg.get_string()

    def write(self, handle, data):
        resp_type, msg = self._request(CMD_WRITE, handle, long(0), data)
        if resp_type != CMD_STATUS:
            raise SFTPError("Expected status")
        status = msg.get_int()
        if status != 0:
            raise SFTPError("Write failed")
        
    def close(self, handle):
        """
        Close the remote file

        Args:
            handle (str): remote file handle to close
        """
        resp_type, msg = self._request(CMD_CLOSE, handle)
        if resp_type != CMD_STATUS:
            raise SFTPError("Error closing file")
        status = msg.get_int()
        return status

    @connects
    def download(self, file):
        """
        Downloads a single file as specified in the passed remotefile
        parameter. 'remotefile' must be the full absolute path to the
        file on the server

        Args:
            file (str): file to download
        """
        localfile = Path(self.config.localdir, file)
        if not self.config.overwrite_local and localfile.exists():
            raise LocalFileExistsError(localfile)
        with open(localfile, "wb") as fw:
            handle = self.open(file)
            data = self.read(handle, 32768)
            fw.write(data)
            closed = self.close(handle)
            log.debug(f"remote file close status: {closed}")
        with self._lock:
            self._downloaded.append(str(localfile))
        return str(localfile)

    @connects
    def download_latest(self, dl_num=1, name_filter=[], **kwargs):
        """
        Downloads the latest # of files as given in <dl_num> from the
        remote directory <remotedir>
        """
        remote_list = sorted(
            self._sftp.listdir_attr(), key=lambda x: x.st_mtime, reverse=True
        )
        to_download = [
            f.filename
            for f in remote_list
            if S_ISREG(f.st_mode) and _apply_name_filter(f.filename, name_filter)
        ][:dl_num]
        self._threaded_transfer('download', to_download)
        return self._downloaded

    def download_all(self, **kwargs):
        """
        Downloads all files in the given remote directory (remotedir).

        This needs to be tested for what happens when there are no files
        in the remote directory
        """
        return self.download_latest(None, **kwargs)

    @connects
    def upload_latest(self, ul_num=1, name_filter=[], **kwargs):
        """
        Uploads the latest # of files, specified by ``dl_num``
        """
        if not name_filter:
            name_filter = ["?."]
        to_upload = []
        for filter in name_filter:
            to_upload.extend(
                [p for p in Path(self.config.localdir).glob(f"*{filter}*")]
                )
        to_upload = sorted(
            to_upload,
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )[:ul_num]
        log.debug(to_upload)
        self._threaded_transfer('upload', to_upload)
        return self._uploaded

    @connects
    @secure
    def upload(self, file):
        """
        Uploads a single file as specified in the passed `file`
        parameter.

        Args:
            file (str/Path): file to download
        """
        with open(file, "rb") as fw:
            handle = self.open(file, 'w')
            data = fw.read(32768)
            self.write(handle, data)
            close = self.close(handle)
            log.debug(f'closed new file "{file}" on server: {close}')
        with self._lock:
            self._uploaded.append(file)

    def encode_path(self, file):
        """Take a standalone filename, append it to the currently set remote
        directory, and convert it to a utf-8 bytestring

        Args:
            file (str/Path): standalone filename

        Returns:
            bytes: bytestring of remotedir/filename
        """
        path = f"{self.config.remotedir}/{file}"
        return path.encode("utf-8")

    def _request(self, cmd, *args):
        """Make a request to the server and wait for a response back
        Returns the response

        Args:
            cmd (int): SSH FTP packet type
            args: additional contents of packet

        """
        req_num = self._async_request(type(None), cmd, *args)
        return self._async_response(req_num)

    def _async_request(self, expects, cmd, *args):
        """
        Build an SSH FTP packet and send it to the server

        Args:
            expects (type): a type we expect back from server, if any
            cmd (int): SSH FTP packet type
            args: additional contents of packet
        """
        with self._lock:
            if getattr(g, "req_num", False):
                req_num = g["req_num"]
            else:
                g["req_num"] = req_num = 0
            if not getattr(g, "resp_num", False):
                g["resp_num"] = 0
            msg = Message()
            msg.add_int(req_num)
            [_add_to_message(msg, a) for a in args]
            lo["expects"] = {req_num: expects}
            g["req_num"] += 1
            _event_stack[req_num] = Event()
        self._sftp._send_packet(cmd, msg)
        return req_num

    def _async_response(self, wantsback=None):
        """
        Read a packet and then process it into a ``Message`` object

        Returns the SSH packet type value of the response, along with
        the response itself wrapped in a Paramiko ``Message`` object

        Args:
            wantsback (int): the request # associated with the packet we're
            expecting back
        """
        with self._lock:
            resp_type, data = self._sftp._read_packet()
            g["resp_num"] += 1
        msg = Message(data)
        req_num = msg.get_int()
        with self._lock:
            if req_num == wantsback and req_num in lo["expects"]:
                del lo["expects"][req_num]
                return resp_type, msg
            _request_buffer[req_num] = (resp_type, msg)
            _event_stack[req_num].set()
        while True:
            with self._lock:
                if wantsback in _request_buffer:
                    resp_type, data = _request_buffer[wantsback]
                    del _request_buffer[wantsback]
                    return resp_type, data
            # Add a timeout here eventually to prevent deadlocking
            _event_stack[wantsback].wait()

    def _threaded_transfer(self, way, to_transfer):
        threads = []
        for xfr in to_transfer:
            t = Thread(target=getattr(self, way), args=(xfr,), kwargs={"thread": True})
            threads.append(t)
            t.start()
        [t.join() for t in threads]


def _apply_name_filter(name, name_list):
    if not name_list:
        return True
    return any(fltr in name for fltr in name_list)


def _add_to_message(msg, value):
    if isinstance(value, long):
        msg.add_int64(value)
    elif isinstance(value, int):
        msg.add_int(value)
    elif isinstance(value, SFTPAttributes):
        value._pack(msg)
    else:
        msg.add_string(value)
