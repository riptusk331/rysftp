import gnupg
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

"""
DO NOT USE
This entire module needs to be updated for compatability
with my redesign of this library
"""


class Encryptor:
    """
    Encryptor class that assists the FTP uploader in encrypting PGP files
    """

    def __init__(self, gnu_dir, gnu_pass, src_dir, tgt_dir=None):

        # specify filesystem location containing GnuPG key information
        self.gpg = gnupg.GPG(gnupghome=gnu_dir)
        self.passphrase = gnu_pass

    def encrypt(self, toEncrypt, recipients, fingerprint, output_dir=None, overwrite=True):
        """
        Encrypts the file or list of files provided via the <toEncrypt>
        parameter and spits them back out in the same location.

        If you want to place the encrypted files in a separate directory, pass
        in your desired directory via the <output_dir> parameter.

        If the 'filenames' list parameter is passed, the method will encrypt
        only files matching those named in the list

        Returns a list of encrypted filenames if successful

        :param filenames: list of filenames to encrypt
        """

        did_ec = []
        no_ec = []

        if isinstance(toEncrypt, (str, Path)):
            toEncrypt = [toEncrypt]
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            logger.debug(f'Overriding <tgt_dir> to "{output_dir}"')
        else:
            output_dir = self.tgt_dir

        for f in toEncrypt:
            logger.debug(f'Attempting to encrypt "{Path(f)}"')
            output = Path(output_dir, f"{Path(f).name}.gpg")
            if not f.exists():
                no_ec.append(Path(f).name)
                logger.error(f'File "{Path(f)}" does not exist.')
            elif not overwrite and output.exists():
                no_ec.append(Path(f).name)
                logger.warning(
                    f'Did not encrypt "{Path(f)}" - '
                    f'encrypted version exists: "{output}"'
                )
            else:
                with open(f, "rb") as open_f:
                    result = self.gpg.encrypt_file(
                        recipients=recipients,
                        armor=False,
                        file=open_f,
                        output=str(output),
                        sign=fingerprint,
                        passphrase=self.passphrase,
                    )
                if result.ok:
                    did_ec.append(output)
                    logger.info(f'Encrypted "{Path(f)}" to "{output}"')
                else:
                    no_ec.append(Path(f).name)
                    logger.error(f"Encryption failed: {result.status}")

        return did_ec

    def decrypt(self, toDecrypt, output_dir=None, overwrite=False):
        """
        Decrypts the files in the source directory and places the decrypted
        versions into the target directory.

        If the 'filenames' list parameter is passed, the method will decrypt
        only files matching those named in the list

        :param filenames: list of filenames to decrypt
        """

        did_dc = []
        no_dc = []

        if isinstance(toDecrypt, (str, Path)):
            toDecrypt = [toDecrypt]
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            logger.debug(f'Overriding <tgt_dir> to "{output_dir}"')
        else:
            output_dir = self.tgt_dir

        # filter input for encrypted files only
        toDecrypt = [
            Path(f) for f in toDecrypt if Path(f).suffix in (".asc", ".gpg", ".pgp")
        ]
        # create list of filenames without encrypted extension
        no_extension = [Path(dc).with_suffix("").name for dc in toDecrypt]
        if not overwrite:
            tgt_iter = Path(output_dir).iterdir()
            dont_dc = [f.name for f in tgt_iter if f.name in no_extension]

        # open encrypted files and start decryption
        for f in toDecrypt:
            logger.info(f'Attempting to decrypt "{f}"')
            if no_extension[toDecrypt.index(f)] not in dont_dc:
                try:
                    with open(f, "rb") as open_f:
                        result = self.gpg.decrypt_file(
                            file=open_f,
                            passphrase=self.passphrase,
                            output=(
                                f"{self.tgt_dir}/" f"{no_extension[toDecrypt.index(f)]}"
                            ),
                        )
                except FileNotFoundError:
                    no_dc.append(f.name)
                    logger.error(f'File "{f} not found')
                else:
                    if result.ok:
                        did_dc.append(f.name)
                        logger.info(f'Successfully decrypted "{f}"')
                    else:
                        no_dc.append(f.name)
                        logger.error(f"Decryption failed: {result.status}")
            else:
                no_dc.append(f.name)
                logger.warning(f'Skipping. Decrypted "{f.name}" already exists')

        return did_dc
