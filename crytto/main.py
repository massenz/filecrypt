# @copyright: AlertAvert.com (c) 2016. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Uses OpenSSL library to encrypt a file using a private/public key secret.

A full description of the process can be found at:
[HOW-TO Encrypt an archive](https://github.com/massenz/HOW-TOs/blob/master/HOW-TO%20Encrypt%20archive.rst)

See the [README](https://bitbucket.org/marco/filecrypt) for more details.
"""

import argparse
import logging
import os
import random
import sys
import traceback

from crytto import FILECRYPT_CONF_YML
from crytto.filecrypt import FileCrypto
from crytto.utils import (
    SelfDestructKey,
    shred,
    KeystoreManager,
    KeystoreEntry,
    EncryptConfiguration,
    Keypair,
)


def check_version():
    if sys.version_info < (3, 6):
        raise RuntimeError(
            "Python 3.6 or greater required (3.7 recommended). Please consider upgrading or "
            "using a virtual environment."
        )


def create_secret_filename(secrets_dir):
    """ Returns a new, randomly generated, filename for the secret key filename.


    :param secrets_dir: the path where the secret keys files are stored.
    :return: a full path (starting with ``secrets_dir``) which is also guaranteed to not conflict
        with an existing file.
    :rtype: str
    """
    result = os.path.join(secrets_dir, "pass-key-{:06d}.enc".format(random.randint(9999, 999999)))

    # We need to prevent overwriting existing encrypted passphrases, so we keep recursing
    # until we find an unused filename (Python does not have a do-until, and this is more elegant
    # than alternatives).
    return result if not os.path.exists(result) else create_secret_filename(secrets_dir)


def establish_secret(secret, secrets_dir, keystore, infile=None, decrypt=False):
    """ Will figure out a way to establish the filename where the secret is stored.

    During encryption, the secret can either be passed in by the user (`--secret`) or just
    randomly created (`create_secret_filename()`).

    Similarly, during decryption, if the user has not specified a secret, it may be looked up in
    the keystore, using the `infile` file as a lookup item.

    Unless the user has specified an existing filename via a relative path, the result will
    always be in the `secrets_dir` (typically, specified in the YAML configuration file).

    :param secret: the name of the secret file, if `None` we will try to infer it
    :type secret: str or None

    :param secrets_dir: the directory that contains the secrets' files (as specified in
        `FILECRYPT_CONF_YML`).
    :type secrets_dir: str

    :param keystore: the keystore that contains the list of encrypted files and relative secrets.
    :type keystore: `KeystoreManager` or None

    :param infile: the name of the file to encrypt/decrypt, that will be used to look up
        in the keystore; if `decrypt` is `True` it **must** be specified.
    :type infile: str or None

    :param decrypt: if we are trying to decrypt a file (and this flag will be set to `True`)
        we will continue trying to lookup in the `keystore` for a matching key; otherwise,
        a newly created one will be returned.
    :type decrypt: bool

    :return: the full path to the secret file; it may or may not exist already.
    :rtype: str or None
    """
    if secret:
        if os.path.isabs(secret) or os.path.exists(secret):
            return secret
        else:
            return os.path.join(secrets_dir, secret)

    if decrypt:
        if keystore and infile:
            entry = keystore.lookup(infile)
            if entry:
                return entry.secret
    else:
        # We are encrypting the file, but don't already have a secret specified:
        # we will create a new one and return it.
        return create_secret_filename(secrets_dir)


def parse_args():
    """ Parse command line arguments and returns a configuration object.

    :return the configuration object, arguments accessed via dotted notation
    :rtype Namespace
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--conf",
        dest="conf_file",
        default=FILECRYPT_CONF_YML,
        help="The location of the YAML configuration file, if different from "
             "the default {}.".format(FILECRYPT_CONF_YML),
    )
    parser.add_argument(
        "-d",
        dest="encrypt",
        action='store_false',
        help="If specified, the `infile` will be decrypted, using the encrypted --secret",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="If specified, the destination file will be overwritten if it " "already exists.",
    )
    parser.add_argument(
        "-k",
        "--keep",
        action="store_true",
        help="Keep the plaintext file. Overriddes the 'shred' option in the " "configuration YAML.",
    )
    parser.add_argument(
        "-o",
        "--out",
        help="The output file, overrides the default naming and the location "
             "defined in the YAML configuration file.",
    )
    parser.add_argument(
        "-p",
        "--pubkey",
        help="Only used for the encrypt_send command, to specify a Public key "
             "shared by the recipient; otherwise ignored.",
    )
    parser.add_argument(
        "-s",
        "--secret",
        help="The full path of the ENCRYPTED passphrase to use to encrypt the "
             "file; it will be left unmodified on disk.",
    )
    parser.add_argument(
        "--send",
        action='store_true',
        help="If specified, the plaintext `infile` will be encrypted and an encrypted"
             "passphrase (the 'secret') will be generated, using the --pubkey (which is"
             "required)."
    )
    parser.add_argument(
        "-v",
        dest='debug',
        action='store_true',
        help="If specified, and an error occurs, the full stacktrace is printed; "
             "also, logging is set in DEBUG mode."
    )
    parser.add_argument("infile", help="The file that will be securely encrypted or decrypted.")
    return parser.parse_args()


def encrypt(cfg):
    enc_cfg = EncryptConfiguration(conf_file=cfg.conf_file)
    if cfg.keep:
        enc_cfg.shred = False

    if cfg.debug:
        enc_cfg.log.setLevel(logging.DEBUG)

    keys = Keypair(private=enc_cfg.private, public=enc_cfg.public)
    enc_cfg.log.info("Using key pair: %s", keys)

    keystore = KeystoreManager(enc_cfg.store)

    # The secret can be defined in several ways, depending also if it's an encryption or
    # decryption that is required, etc. - best left to a specialized method.
    secret = establish_secret(
        cfg.secret, enc_cfg.secrets_dir, keystore, cfg.infile, not cfg.encrypt
    )
    if not secret:
        raise RuntimeError(
            "Could not locate a suitable decryption key for {}; keystore: {}".format(
                cfg.infile, keystore.filestore
            )
        )
    enc_cfg.log.info("Found encrypted secret: '%s'", secret)

    passphrase = SelfDestructKey(secret, keypair=keys)
    enc_cfg.log.info("Using '%s' as the encryption secret", passphrase.keyfile)

    if cfg.out:
        enc_cfg.out = None

    should_encrypt = cfg.encrypt
    plaintext, encrypted = (cfg.infile, cfg.out) if should_encrypt else (cfg.out, cfg.infile)
    encryptor = FileCrypto(
        encrypt=should_encrypt,
        secret=passphrase,
        plain_file=plaintext,
        encrypted_file=encrypted,
        dest_dir=enc_cfg.out,
        force=cfg.force,
        log=enc_cfg.log,
    )
    encryptor()
    enc_cfg.log.info("'%s' completed", "Encryption" if should_encrypt else "Decryption")

    if should_encrypt:
        if enc_cfg.shred:
            enc_cfg.log.warning("Securely destroying %s", plaintext)
            shred(plaintext)
        enc_cfg.log.info("Encryption successful; saving data to store file '%s'.", enc_cfg.store)
        entry = KeystoreEntry(os.path.abspath(secret), os.path.abspath(encryptor.outfile))
        keystore.add_entry(entry)


def encrypt_to_send(file_to_encrypt, pubkey, dest=None):
    """ Encrypts a file to be sent to another party who shared their Public key.

    :param file_to_encrypt: the name of the file to encrypt; **must exist** and will be left
        unchanged.
    :type file_to_encrypt: str

    :param pubkey: the name of the file containing a suitable Public Key to use with OpenSSL.
    :type pubkey: str

    :param dest: it can be any of: (a) an existing directory (in which case, the encrypted
        file will have the same name as the `file_to_encrypt` and extension `.enc`); or (b)
        a relative or absolute path to a not-yet-existing file, which will be the encrypted
        file; or (c) `None`, in which case the encrypted file will be in the current directory
        and named as the plaintext, with extension `.enc`.
        Passing just a filename, will create it in the current directory.
    :type dest: str or None

    :return: a tuple containing the `dest` directory, and the full paths to the `secret` used to
        encrypt the file and the encrypted file.
    :rtype: tuple
    """
    if not (os.path.exists(file_to_encrypt) and os.path.exists(pubkey)):
        raise ValueError("{} and {} must both exist, nothing to do".format(file_to_encrypt, pubkey))

    if not dest:
        dest = os.getcwd()

    if os.path.isdir(dest):
        outfile = file_to_encrypt + ".enc"
    else:
        dest, outfile = os.path.split(dest)
        if not os.path.isdir(dest):
            raise ValueError("Directory {} does not exist".format(dest))

    key = Keypair(private=None, public=pubkey)
    secret = create_secret_filename(dest)
    passphrase = SelfDestructKey(secret, key)
    encryptor = FileCrypto(
        secret=passphrase,
        plain_file=file_to_encrypt,
        dest_dir=dest,
        encrypted_file=outfile,
        force=True,
    )
    encryptor()
    return dest, secret, os.path.join(dest, outfile)


def entrypoint():
    """ Entry-point script to drive encryption/decryption.

    This method is invoked by all the various console scripts (see `setup.py`) and by
    the `zipapp` executable archive (see `filecrypt()` below).
    """
    config = None
    try:
        check_version()
        config = parse_args()
        if config.send:
            if not config.pubkey:
                raise ValueError("A valid Public key must be defined using the --pubkey option")
            _, secret, enc_file = encrypt_to_send(config.infile, config.pubkey, config.out)
            print(f"File {config.infile} encrypted to {enc_file} - encryption key in: {secret}")
        else:
            encrypt(config)
    except Exception as ex:
        print("[ERROR] Could not complete execution:", ex)
        if config and config.debug:
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)
        exit(1)
