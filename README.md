# RySftp

Why RySftp? Because PySftp was taken, and I'm selfish.

This is my first attempt at an SFTP client. It's current state should be considered alpha, and full of bugs. It barely works, and it still needs to be documented and more thoroughly tested. DON'T USE THIS RIGHT NOW. I've only published this package for testing, and to share with a few people.

RySftp is essentially a wrapper around some of the tried and true [paramiko](http://www.paramiko.org/) package's features, that aims to make SFTP usage in python quick and easy. The connection resource is managed via a context manager, accessed using with statements. RySftp also implements multithreaded upload and downloads over a single connection, dramatically improving transfer rates on large #s of files.

RySftp automatically searches for the below environment variables for connection information:

|Variable|Usage|
|--------|-----|
|RYSFTP_USER|Username|
|RYSFTP_PASSWORD|Password|
|RYSFTP_HOST|Hostname|
|RYSFTP_PORT|Port|
|RYSFTP_REMOTEDIR| Default remote dir


## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install RySftp.

```bash
pip install rysftp
```

## Usage
RySftp aims to be simple. Here is a barebones usage example:

```python
import rysftp

ry = RySftp()
with ry("home/downloads"):
    ry.download_latest(100)
    ry.upload_latest(4)

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
