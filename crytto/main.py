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
import os
import random
import sys

from crytto.filecrypt import FileCrypto
from crytto.utils import (SelfDestructKey,
                          shred,
                          KeystoreManager,
                          KeystoreEntry, EncryptConfiguration, Keypair)

FILECRYPT_CONF_YML = os.path.join(os.getenv('HOME'), ".crytto/conf.yml")


def check_version():
    if sys.version_info < (3, 0):
        print("Python 3.0 or greater required (3.5 recommended). Please consider upgrading or "
              "using a virtual environment.")
        sys.exit(1)


def create_secret_filename(secrets_dir):
    """ Returns a new, randomly generated, filename for the secret key filename.

    We need to prevent overwriting existing encrypted passphrases, so we keep recursing
    until we find an unused filename (Python does not have a do-until, and this is more elegant
    than alternatives).

    :param secrets_dir: the path where the secret keys files are stored.
    :return: a full path (starting with ``secrets_dir``) which is also guaranteed to not conflict
        with an existing file.
    :rtype: str
    """
    result = os.path.join(secrets_dir, "pass-key-{:4d}.enc".format(random.randint(999, 9999)))
    return result if not os.path.exists(result) else create_secret_filename(secrets_dir)


def establish_secret(secret, secrets_dir, keystore, infile=None, decrypt=False):
    """ Will figure out a way to establish the filename where the secret is stored.

    During encryption, the secret can either be passed in by the user (```--secret```) or just
    randomly created (```create_secret_filename()```).

    Similarly, during decryption, if the user has not specified a secret, it may be looked up in
    the keystore, using the ```infile``` file as a lookup item.

    Unless the user has specified an existing filename via a relative path, the result will
    always be in the ```secrets_dir``` (typically, specified in the YAML configuration file).

    :param secret: the name of the secret file, may be ```None```
    :param secrets_dir: the directory that contains the secrets' files (as specified in
        ```configuration.yaml```.

    :param keystore: the keystore that contains the list of encrypted files and relative secrets.
    :type keystore: KeystoreManager or None

    :param infile: the name of the file to encrypt/decrypt, that will be used to look up
        in the keystore if ```decrypt``` is ```True```.
    :type infile: str or None

    :param decrypt: if we are trying to decrypt a file (and this flag will be set to ```True```)
        we will continue trying to lookup in the ```keystore``` for a matching key; otherwise,
        a newly created one will be returned.
    :type decrypt: bool

    :return: the full path to the secret file.
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
    parser.add_argument('-s', '--secret',
                        help="The full path of the ENCRYPTED passphrase to use to encrypt the "
                             "file; it will be left unmodified on disk.")
    parser.add_argument('-o', '--out',
                        help="The output file, overrides the default naming and the location "
                             "defined in the YAML configuration file.")
    parser.add_argument('-w', '--force', action='store_true',
                        help="If specified, the destination file will be overwritten if it "
                             "already exists.")
    parser.add_argument('infile',
                        help="The file that will be securely encrypted or decrypted.")
    return parser.parse_args()


def main(cfg, encrypt=True):
    enc_cfg = EncryptConfiguration(conf_file=cfg.conf_file)
    if cfg.keep:
        enc_cfg.shred = False

    keys = Keypair(private=enc_cfg.private, public=enc_cfg.public)
    enc_cfg.log.info("Using key pair: %s", keys)

    keystore = KeystoreManager(enc_cfg.store)

    # The secret can be defined in several ways, depending also if it's an encryption or
    # decryption that is required, etc. - best left to a specialized method.
    secret = establish_secret(cfg.secret, enc_cfg.secrets_dir, keystore, cfg.infile, not encrypt)

    if not secret:
        raise RuntimeError("Could not locate a suitable decryption key for {}; keystore: {}".format(
            cfg.infile, keystore.filestore))

    passphrase = SelfDestructKey(secret, keypair=keys)
    enc_cfg.log.info("Using '%s' as the encryption secret", passphrase.keyfile)

    if cfg.out:
        enc_cfg.out = None

    plaintext = cfg.infile if encrypt else cfg.out
    encrypted = cfg.out if encrypt else cfg.infile

    encryptor = FileCrypto(encrypt=encrypt,
                           secret=passphrase,
                           plain_file=plaintext,
                           encrypted_file=encrypted,
                           dest_dir=enc_cfg.out,
                           force=cfg.force,
                           log=enc_cfg.log)
    encryptor()

    if encrypt:
        if enc_cfg.shred:
            enc_cfg.log.warning("Securely destroying %s", plaintext)
            shred(plaintext)
        enc_cfg.log.info("Encryption successful; saving data to store file '%s'.", enc_cfg.store)
        entry = KeystoreEntry(os.path.abspath(secret), os.path.abspath(encryptor.outfile))
        keystore.add_entry(entry)


def entrypoint(encrypt):
    """ Entry-point script for execution"""
    check_version()
    try:
        config = parse_args()
        main(config, encrypt=encrypt)
    except Exception as ex:
        print("[ERROR] Could not complete execution:", ex)
        exit(1)


def encrypt_cmd():
    """ Console entry point for the ```encrypt``` command."""
    entrypoint(True)


def decrypt_cmd():
    """" Console entry point for the ```decrypt``` command."""
    entrypoint(False)


def prune_cmd():
    if len(sys.argv) < 2:
        enc_cfg = EncryptConfiguration(conf_file=FILECRYPT_CONF_YML)
        store = enc_cfg.store
    else:
        store = sys.argv[1]
    keystore = KeystoreManager(store)
    keystore.prune()
    print("Keystore {} has been pruned; a backup copy has been kept in {}".format(
        keystore.filestore, keystore.filestore + '.bak'))

