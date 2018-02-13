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

See the [README](https://github.com/massenz/crytto) for more details.
"""

import argparse
import logging
import os
import random
import sys

from crytto.filecrypt import FileCrypto
from crytto.utils import (SelfDestructKey,
                          shred,
                          KeystoreManager,
                          KeystoreEntry, EncryptConfiguration, Keypair)


DEFAULT_CONF_FILE = "conf.yml"
DEFAULT_CONF_DIF = ".crytto"
FILECRYPT_CONF_YML = os.path.join(os.getenv('HOME'), DEFAULT_CONF_DIF, DEFAULT_CONF_FILE)


def check_version():
    if sys.version_info < (3, 0):
        print("Python 3.0 or greater required (3.5 recommended). Please consider upgrading or "
              "using a virtual environment.")
        sys.exit(1)


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
        `configuration.yaml`).
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

    if not decrypt:
        return create_secret_filename(secrets_dir)

    if keystore and infile:
        entry = keystore.lookup(infile)
        if entry:
            return entry.secret


def parse_args():
    """ Parse command line arguments and returns a configuration object.

    :return the configuration object, arguments accessed via dotted notation
    :rtype Namespace
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='conf_file', default=FILECRYPT_CONF_YML,
                        help="The location of the YAML configuration file, if different from "
                             "the default {}.".format(FILECRYPT_CONF_YML))

    parser.add_argument('-k', '--keep', action='store_true',
                        help="Keep the plaintext file. Overriddes the 'shred' option in the "
                             "configuration YAML.")

    parser.add_argument('-o', '--out',
                        help="The output file, overrides the default naming and the location "
                             "defined in the YAML configuration file.")

    parser.add_argument('-p', '--pubkey',
                        help="Only used for the encrypt_send command, to specify a Public key "
                             "shared by the recipient; otherwise ignored.")

    parser.add_argument('-s', '--secret',
                        help="The full path of the ENCRYPTED passphrase to use to encrypt the "
                             "file; it will be left unmodified on disk.")

    parser.add_argument('-w', '--force', action='store_true',
                        help="If specified, the destination file will be overwritten if it "
                             "already exists.")

    parser.add_argument('infile',
                        help="The file that will be securely encrypted or decrypted.")
    return parser.parse_args()


def encrypt(cfg, should_encrypt=True):
    enc_cfg = EncryptConfiguration(conf_file=cfg.conf_file)
    if cfg.keep:
        enc_cfg.shred = False

    keys = Keypair(private=enc_cfg.private, public=enc_cfg.public)
    enc_cfg.log.info("Using key pair: %s", keys)

    keystore = KeystoreManager(enc_cfg.store)

    # The secret can be defined in several ways, depending also if it's an encryption or
    # decryption that is required, etc. - best left to a specialized method.
    secret = establish_secret(cfg.secret, enc_cfg.secrets_dir, keystore, cfg.infile, not should_encrypt)

    if not secret:
        raise RuntimeError("Could not locate a suitable decryption key for {}; keystore: {}".format(
            cfg.infile, keystore.filestore))

    passphrase = SelfDestructKey(secret, keypair=keys)
    enc_cfg.log.info("Using '%s' as the encryption secret", passphrase.keyfile)

    if cfg.out:
        enc_cfg.out = None

    plaintext = cfg.infile if should_encrypt else cfg.out
    encrypted = cfg.out if should_encrypt else cfg.infile

    encryptor = FileCrypto(encrypt=should_encrypt,
                           secret=passphrase,
                           plain_file=plaintext,
                           encrypted_file=encrypted,
                           dest_dir=enc_cfg.out,
                           force=cfg.force,
                           log=enc_cfg.log)
    encryptor()

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

    :param pubkey: the name of the file containing a suitable Public Key to use with OpenSSH.
    :type pubkey: str

    :param dest: it can be any of: (a) an existing directory (in which case, the encrypted
        file will have the same name as the `file_to_encrypt` and extension `.enc`); or (b)
        a relative or absolute path to a not-yet-existing file, which will be the encripted
        file; or (c) `None`, in which case the encrypted file will be in the current directory
        and named as the plaintext, with extension `.enc`.
        Passing just a filename, will create it in the current directory.
    :type dest: str or None

    :return: a tuple containing the `dest` directory, and the full paths to the `secret` used to
        encrypt the file and the encrypted file.
    :rtype: tuple
    """
    if not (os.path.exists(file_to_encrypt) and os.path.exists(pubkey)):
        raise ValueError("{} and {} must both exist, nothing to do".format(
            file_to_encrypt, pubkey))

    if not dest:
        dest = os.getcwd()

    if os.path.isdir(dest):
        outfile = file_to_encrypt + '.enc'
    else:
        dest, outfile = os.path.split(dest)
        if not os.path.isdir(dest):
            raise ValueError("Directory {} does not exist".format(dest))

    key = Keypair(private=None, public=pubkey)
    secret = create_secret_filename(dest)
    passphrase = SelfDestructKey(secret, key)
    encryptor = FileCrypto(secret=passphrase,
                           plain_file=file_to_encrypt,
                           dest_dir=dest,
                           encrypted_file=outfile,
                           force=True)
    encryptor()
    return dest, secret, os.path.join(dest, outfile)


def entrypoint(should_encrypt):
    """ Entry-point script for execution"""
    check_version()
    try:
        config = parse_args()
        encrypt(config, should_encrypt=should_encrypt)
    except Exception as ex:
        print("[ERROR] Could not complete execution:", ex)
        exit(1)


def encrypt_cmd():
    """ Console entry point for the `encrypt` command."""
    entrypoint(True)


def decrypt_cmd():
    """" Console entry point for the `decrypt` command."""
    entrypoint(False)


def send_cmd():
    """ Encrypts a file to be sent to a remote recipient."""
    check_version()
    try:
        config = parse_args()
        if not config.pubkey:
            print("[ERROR] A valid Public key must be defined using the --pubkey option")
            exit(1)
        dest, secret, enc_file = encrypt_to_send(config.infile, config.pubkey, config.out)
        print("File {plain} encrypted to {enc} - encryption key in: {secret}".format(
            plain=config.infile,
            enc=enc_file,
            secret=secret
        ))
    except Exception as ex:
        print("[ERROR] Could not complete execution:", ex)
        exit(1)


def prune_cmd():
    """Prunes the keystore of unused keys (those that were used to encrypt files that no longer
    exist).

    Takes two arguments, both optional:

        - a keystore file (which will be pruned); and
        - a working directory to check for files' existence.

    If the `keystore` is not defined, the one configured in the defaul YAML configuration file
    will be used; if a `working directory` is not specified, only the location of the file as
    reported in the keystore will be checked.
    """
    enc_cfg = EncryptConfiguration(conf_file=FILECRYPT_CONF_YML)
    parser = argparse.ArgumentParser()
    parser.add_argument('--keystore', '-k', default=enc_cfg.store, help="The keystore to prune")
    parser.add_argument('--workdir', '-d', help="Alternative location to check for files")
    parser.add_argument('-v', dest='verbose', action='store_true', help="Verbose logging")
    cli_args = parser.parse_args()

    try:
        if not os.path.exists(cli_args.keystore):
            raise ValueError("File {} does not exist".format(cli_args.keystore))
        keystore = KeystoreManager(cli_args.keystore, cli_args.verbose)
        keystore.prune(alt_dir=cli_args.workdir)

        print("Keystore {} has been pruned; a backup copy has been kept in {}".format(
            keystore.filestore, keystore.filestore + '.bak'))
    except Exception as ex:
        print("[ERROR] Could not prune {}: {}".format(cli_args.keystore, ex))

