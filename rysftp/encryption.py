import gnupg
import logging
from pathlib import Path


def encrypt(self, to_encrypt, recipients, fingerprint, output_dir=None, overwrite=True):
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
    output = Path(output_dir, f"{Path(f).name}.gpg")
    with open(to_encrypt, "rb") as f:
        result = self.gpg.encrypt_file(
            recipients=recipients,
            armor=False,
            file=f,
            output=str(output),
            sign=fingerprint,
            passphrase=self.passphrase,
        )
    if not result.ok:
        raise RuntimeError('Bad Encryption')
    return result

def decrypt(self, to_decrypt, output_dir=None, overwrite=False):
    """
    Decrypts the files in the source directory and places the decrypted
    versions into the target directory.

    If the 'filenames' list parameter is passed, the method will decrypt
    only files matching those named in the list

    :param filenames: list of filenames to decrypt
    """
    with open(f, "rb") as open_f:
        result = self.gpg.decrypt_file(
            file=open_f,
            passphrase=self.passphrase,
            output=(
                f"{self.tgt_dir}/" f"{no_extension[toDecrypt.index(f)]}"
            ),
        )
    if not result.ok:
        raise RuntimeError("Bad Decryption")
    return result
