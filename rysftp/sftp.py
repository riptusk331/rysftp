import logging
import math
import time
from os import getenv
import os
from threading import Lock, Thread
from concurrent.futures import ThreadPoolExecutor
from stat import S_ISREG
from functools import wraps
from pathlib import Path
from paramiko import Transport, SFTPClient, Message
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp import (
    CMD_ATTRS,
    CMD_CLOSE,
    CMD_DATA,
    CMD_OPEN,
    CMD_READ,
    CMD_FSTAT,
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
    _request_stack,
    g,
    lo,
)
from .errors import (
    catch_errors,
    LocalFileExistsError,
    OutsideAppContextError,
)


log = logging.getLogger(__name__)
MAX_PAYLOAD_SIZE = 32768


class long(int):
    pass


class _RySftpConfig:
    def __init__(self, **kwargs):
        remotedir = kwargs.get("remotedir", getenv("RYSFTP_REMOTEDIR"))
        self.remotedir = remotedir or "."
        localdir = kwargs.get("localdir", getenv("RYSFTP_LOCALDIR"))
        self.localdir = localdir or "."
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
        self.user = kwargs.get("user", getenv("RYSFTP_USER"))
        self.password = kwargs.get("password", getenv("RYSFTP_PASSWORD"))
        self.hostname = kwargs.get("hostname", getenv("RYSFTP_HOSTNAME"))
        port = kwargs.get("port", getenv("RYSFTP_PORT"))
        self.port = int(port or 22)
        self.config = _RySftpConfig(**kwargs)

        self._t = Transport((self.hostname, self.port))
        self._t.set_hexdump(False)

        self._sftp = None
        self._channel = None
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
        self._channel = self.ssh_channel()
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

    def ssh_channel(self):
        """Get the paramiko Channel from the underlying sftp client

        """
        return self._sftp.get_channel()

    def connects(f):
        @wraps(f)
        @catch_errors
        def wrapped(self, *args, **kwargs):
            ry_ctx = _ry_ctx_stack.top
            if kwargs.pop("thread", False) is True:
                with self.ry_context():
                    x = f(self, *args, **kwargs)
                    return x
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

    def fstat(self, handle):
        """
        Get stats about a file on the remote server via it's handle

        """
        log.debug(f"stat request: [{handle}]")
        resp_type, msg = self._blocking_request(CMD_FSTAT, handle)
        if resp_type != CMD_ATTRS:
            raise SFTPError("Expected back attributes")
        return SFTPAttributes._from_msg(msg)

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
        resp_type, msg = self._blocking_request(CMD_OPEN, filename, pflags, attrs)
        if resp_type != CMD_HANDLE:
            raise SFTPError("Expected remote file handle")
        return msg.get_binary()

    @connects
    def read(self, handle, size, offset=0):
        """
        Read ```size``` bytes from the remote file indicated by the
        server supplied ``handle``

        :param str handle: remote file handle to read
        :param int size: bytes to read
        """
        log.debug(f"read request: [{handle}] at byte [{offset}]")
        req_num = self._request(type(None), CMD_READ, handle, long(offset), size)
        if req_num:
            _request_stack[req_num] = (offset, size)
        return req_num

    @connects
    def write(self, handle, data, offset=0):
        """
        Read ```data```  to the remote file indicated by ``handle``

        :param str handle: remote file handle to write to
        :param bytes data: data to write
        """
        log.debug(f'write request: [{handle}] at byte {offset}')
        return self._request(type(None), CMD_WRITE, handle, long(offset), data) 

    def close(self, handle):
        """
        Close the remote file
        
        :param str handle: remote file handle to close
        """
        resp_type, msg = self._blocking_request(CMD_CLOSE, handle)
        if resp_type != CMD_STATUS:
            raise SFTPError("Error closing file")
        status = msg.get_int()
        log.debug(f'closed [{handle}] on server: {status}')
        return status

    @connects
    def download(self, file):
        """
        Downloads a single file as specified in the passed remotefile
        parameter. 'remotefile' must be the full absolute path to the
        file on the server

        :param str file: file to download
        """
        localfile = Path(self.config.localdir, file)
        if not self.config.overwrite_local and localfile.exists():
            raise LocalFileExistsError(localfile)
        with open(localfile, "wb") as fw:
            handle = self.open(file)
            file_size = self.fstat(handle).st_size
            t1 = time.time()
            self._threaded_reader(handle, fw, file_size)
            t2 = time.time()
        self.close(handle)
        log.debug(f'download completed in {t2-t1} seconds at {round(file_size/(t2-t1)/1000, 2)} kB/s')
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
        [self.download(d) for d in to_download]
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
        log.debug(f"UPLOADING THE LATEST {ul_num} FILES")
        if not name_filter:
            name_filter = ["?."]
        to_upload = []
        for filter in name_filter:
            to_upload.extend([p for p in Path(self.config.localdir).glob(f"*{filter}*")])
        to_upload = sorted(
            to_upload,
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )[:ul_num]
        [self.upload(u) for u in to_upload]
        return self._uploaded

    @connects
    def upload(self, file):
        """
        Uploads a single file as specified in the passed `file`
        parameter.

        :parama file: file to download
        """
        with open(file, "rb") as fr:
            file_size = os.fstat(fr.fileno()).st_size
            handle = self.open(Path(file).name, "w")
            t1 = time.time()
            self._threaded_writer(handle, fr, file_size)
            t2 = time.time()
        close = self.close(handle)
        log.debug(f'upload completed in {t2-t1} seconds at {round(file_size/(t2-t1)/1000, 2)} kB/s')
        with self._lock:
            self._uploaded.append(file)

    def encrypt(self, to_encrypt, recipients, fingerprint):
        output = Path(self.config.localdir, f"{Path(to_encrypt).name}.gpg")
        with open(to_encrypt, "rb") as f:
            result = self._gpg.encrypt_file(
                recipients=recipients,
                armor=False,
                file=f,
                output=str(output),
                sign=fingerprint,
                passphrase=self.config.gpg_passphrase,
            )
        if not result.ok:
            raise RuntimeError("Error encrypting")
        return result

    def decrypt(self, to_decrypt, output_dir=None, overwrite=False):
        with open(to_decrypt, "rb") as open_f:
            result = self._gpg.decrypt_file(
                file=open_f,
                passphrase=self.config.gpg_passphrase,
                output=(
                    # f"{self.tgt_dir}/" f"{no_extension[toDecrypt.index(f)]}"
                ),
            )
        if not result.ok:
            raise RuntimeError("Bad Decryption")
        return result

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

    def _blocking_request(self, cmd, *args):
        """Make a request to the server and wait for a response back, blocking
        until it's received. Returns the response

        param int cmd: SSH FTP packet type
        param args: additional contents of packet

        """
        req_num = self._request(type(None), cmd, *args)
        return self._get_response(req_num)

    def _request(self, expects, cmd, *args):
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
            msg = Message()
            msg.add_int(req_num)
            [_add_to_message(msg, a) for a in args]
            g["req_num"] += 1
            self._sftp._send_packet(cmd, msg)
        return req_num

    def _get_response(self, wantsback=None):
        """
        Read a packet and then process it into a ``Message`` object

        Returns the SSH packet type value of the response, along with
        the response itself wrapped in a Paramiko ``Message`` object

        :param int wantsback: the expected request #
        """
        resp_type, msg = self._increment_response()
        req_num = msg.get_int()
        if req_num == wantsback:
            return resp_type, msg

    def _increment_response(self):
        with self._lock:
            resp_type, data = self._sftp._read_packet()
        return resp_type, Message(data)

    def _threaded_transfer(self, way, to_transfer):
        threads = []
        for xfr in to_transfer:
            t = Thread(target=getattr(self, way), args=(xfr,), kwargs={"thread": True})
            threads.append(t)
            t.start()
        [t.join() for t in threads]

    def _threaded_reader(self, handle, writer, size):
        futures = []
        with self._lock:
            lo["expected_responses"] = math.ceil(size / MAX_PAYLOAD_SIZE)
        with ThreadPoolExecutor() as executor:
            n = 0
            while n < size:
                chunk = min(MAX_PAYLOAD_SIZE, size - n)
                futures.append(executor.submit(self.read, handle, chunk, n, thread=True))
                n += chunk
            requests = [f.result() for f in futures]
        for r in requests:
            resp_type, data = self._sftp._read_packet()
            if resp_type != CMD_DATA:
                raise SFTPError("Expected data")
            msg = Message(data)
            resp_num = msg.get_int()
            if resp_num in _request_stack:
                writer.seek(_request_stack[resp_num][0])
                log.debug(f'write local at byte {_request_stack[resp_num][0]}')
                writer.write(msg.get_string())

    def _threaded_writer(self, handle, reader, size):
        futures = []
        with self._lock:
            lo["expected_responses"] = math.ceil(size / MAX_PAYLOAD_SIZE)
        with ThreadPoolExecutor() as executor:
            pos = 0
            while pos < size:
                data = reader.read(MAX_PAYLOAD_SIZE)
                futures.append(
                    executor.submit(self.write, handle, data, pos, thread=True)
                )
                pos = reader.tell()
        for i in range(0, lo["expected_responses"]):
            resp_type, data = self._sftp._read_packet()

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
