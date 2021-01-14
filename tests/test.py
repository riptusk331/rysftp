import logging
from rysftp import RySftp
from os import getenv
from stat import S_ISREG
import time
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)05d %(levelname)s:%(threadName)s:%(module)s:%(lineno)d:%(funcName)s: %(message)s",  # noqa
    datefmt="%Y-%m-%d %H:%M:%S",
)

ry = RySftp()

how_much = int(sys.argv[1])
remotedir = getenv("RYSFTP_REMOTEDIR")
with ry(remotedir):
    # t1 = time.time()
    # whatwegot = ry.download_latest(how_much)
    # t2 = time.time()

    # remote = sorted(ry._sftp.listdir_attr(), key=lambda x: x.st_mtime, reverse=True)
    # to_download = [f.filename for f in remote if S_ISREG(f.st_mode)][:how_much]
    # t3 = time.time()
    # for dl in to_download:
    #     ry._sftp.get(dl, f"./synchronous-{dl}")
    # t4 = time.time()
    # logging.debug(f"Asynchronous Download: {len(whatwegot)} files in {t2-t1} seconds")
    # logging.debug(f"Synchronous Download: {len(to_download)} files in {t4-t3} seconds")
    
    t5 = time.time()
    uploaded = ry.upload_latest(how_much, ['.dat'])
    t6 = time.time()
    logging.debug(f"Asynchronous Upload: {len(uploaded)} files in {t6-t5} seconds")