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
https://github.com/massenz/HOW-TOs/blob/master/HOW-TO%20Encrypt%20archive.rst

configuration
-------------

This uses a YAML file to describe the configuration; by default it assumes it is in
``/etc/filecrypt/conf.yml`` but its location can be specified using the ``-f`` flag.

The structure of the ``conf.yml`` file is as follows::

    keys:
        private: /home/bob/.ssh/secret.pem
        public: /home/bob/.ssh/secret.pub
        secrets: /opt/store/

    store: /home/bob/encrypt/stores.csv

    # Where to store the encrypted file; the folder MUST already exist and the user
    # have write permissions.
    out: /data/store/enc

    # Whether to securely delete the original plaintext file (optional).
    shred: false

The ``private``/``public`` keys are a key-pair generated using the ``openssl genrsa`` command; the
encryption key used to actually encrypt the file will be created in a temporary location,
and afterward encrypted using the ``public`` key and stored in the location provided and the
temporary plaintext copy securely erased.

The name will be ``pass-key-nnn.enc``, where ``nnn`` will be a random value between ``000``` and
``999``, that has not been already used for a file in that folder.

The name of the secret passphrase can also be defined by the user, using the ``--secret`` option
(specify the full path, it will **not** be modified):

* if it does not exist, a temporary one will be created, used for encryption, then encrypted and
saved with the given filename, while the plaintext version securely destroyed; OR

* if it is the name of an already existing file, it will be decrypted, used to encrypt the file,
then left unchanged on disk.

**NOTE** we recommend NOT to re-use encryption passphrases, but always generate a new secret.

**NOTE** it is currently not possible to specify a plaintext passphrase: we always assume that
the given file has been encrypted using the ``private`` key.


The ``store`` file is a CSV list of::

    "Original archive","Encryption key","Encrypted archive"
    201511_data.tar.gz,/opt/store/pass-key-001.enc,201511_data.tar.gz.enc

a new line will be appended at the end, any comments will be left unchanged.

usage
-----

Always use the ``--help`` option to see the most up-to-date options available; anyway, the basic
usage is::

    filecrypt -f /opt/enc/conf.yml /data/store/201511_data.tar.gz

See ``README.md`` for more details.
"""
import argparse
from collections import namedtuple
import logging
import os
import random
import sys
import yaml


from crytto.filecrypt import FileCrypto
from crytto.utils import (SelfDestructKey,
                          shred,
                          KeystoreManager,
                          KeystoreEntry)

__author__ = 'Marco Massenzio'
__email__ = 'marco@alertavert.com'


def check_version():
    if sys.version_info < (3, 0):
        print("Python 3.0 or greater required (3.5 recommended). Please consider upgrading or "
              "using a virtual environment.")
        sys.exit(1)

Keypair = namedtuple('Keypair', 'private public')


class EncryptConfiguration(object):

    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    LOG_FORMAT = '%(asctime)s [%(levelname)-5s] %(message)s'

    def __init__(self, conf_file):
        self.out = None
        self.private = None
        self.public = None
        self.secrets_dir = None
        self.shred = None
        self.store = None
        self._log = logging.getLogger(self.__class__.__name__)
        self.parse_configuration_file(conf_file)

    @property
    def log(self):
        return self._log

    def parse_configuration_file(self, conf_file):
        with open(conf_file) as cfg:
            configs = yaml.load(cfg)

        # First, let's get some logging going.
        self._configure_logging(configs.get('logging') or dict())

        keys = configs.get('keys')
        if not keys:
            self.log.error("The `keys:` section is required, cannot proceed without.")
            raise RuntimeError("Missing `keys` in {}".format(conf_file))

        self.private = keys.get('private')
        self.public = keys.get('public')
        self.secrets_dir = keys.get('secrets')

        if not os.path.isdir(self.secrets_dir):
            self.log.warn("Directory '%s' does not exist, trying to create it", self.secrets_dir)
            try:
                os.makedirs(self.secrets_dir, mode=0o775)
            except OSError as err:
                self.log.error("Cannot create directory '%s': %s", self.secrets_dir, err)
                raise RuntimeError(err)

        self.store = configs.get('store')

        # If the `out` key is not present, the current directory is used.
        self.out = configs.get('out', os.getcwd())

        # Unless otherwise specified, we will securely destroy the original plaintext file.
        self.shred = configs.get('shred', True)

    def _configure_logging(self, log_config):
        handler = logging.StreamHandler()
        if 'logdir' in log_config:
            handler = logging.FileHandler(os.path.join(log_config.get('logdir'), 'filecrypt.log'))
        formatter = logging.Formatter(fmt=log_config.get('format', EncryptConfiguration.LOG_FORMAT),
                                      datefmt=log_config.get('datefmt',
                                                             EncryptConfiguration.DATE_FORMAT))
        handler.setFormatter(formatter)
        self._log.setLevel(log_config.get('level', 'INFO'))
        self._log.addHandler(handler)
        self.log.debug("Logging configuration complete")


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


def establish_secret(cfg, secrets_dir, keystore, plaintext):
    """ Will figure out a way to establish the filename where the secret is stored.

    During encryption, the secret can either be passed in by the user (``--secret``) or just
    randomly created (``create_secret_filename()``).

    Similarly, during decryption, if the user has not specified a secret, it may be looked up in
    the keystore, using the ``plaintext`` file as a lookup item.

    Unless the user has specified an existing filename via a relative path, the result will
    always be in the ``secrets_dir`` (typically, specified in the YAML configuration file).

    :param cfg: the configuration parsed from the command line
    :param secrets_dir: the directory that contains the secrets' files (as specified in
        ``configuration.yaml``.
    :param keystore: the keystore that contains the list of encrypted files and relative secrets.
    :type keystore: KeystoreManager

    :param plaintext: the name of the plaintext (unencrypted) file, that will be used to look up
        in the ``keystore``.

    :return: the full path to the secret file.
    """
    if cfg.secret:
        if os.path.isabs(cfg.secret) or os.path.exists(cfg.secret):
            return cfg.secret
        else:
            return os.path.join(secrets_dir, cfg.secret)

    if not cfg.decrypt:
        return create_secret_filename(secrets_dir)

    entry = keystore.lookup(plaintext)
    if entry:
        return entry.secret


def parse_args():
    """ Parse command line arguments and returns a configuration object.

    :return the configuration object, arguments accessed via dotted notation
    :rtype dict
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='conf_file', default="/etc/filecrypt/conf.yml",
                        help="The location of the YAML configuration file, if different from "
                             "the default.")
    parser.add_argument('-s', '--secret',
                        help="The full path of the ENCRYPTED passphrase to use to encrypt the "
                             "file; it will be left unmodified on disk.")
    parser.add_argument('-d', dest='decrypt', action='store_true',
                        help="Optional, if specified, the file is assumed to be encrypted and "
                             "will be decrypted.")
    parser.add_argument('-w', '--force', action='store_true',
                        help="If specified, the destination file will be overwritten if it "
                             "already exists.")
    parser.add_argument('plaintext_file',
                        help="The file that will be encrypted and securely destroyed.")
    return parser.parse_args()


def main(cfg):
    enc_cfg = EncryptConfiguration(conf_file=cfg.conf_file)
    plaintext = cfg.plaintext_file

    keys = Keypair(private=enc_cfg.private, public=enc_cfg.public)
    enc_cfg.log.info("Using key pair: %s", keys)

    keystore = KeystoreManager(enc_cfg.store)

    # The secret can be defined in several ways, depending also if it's an encryption or
    # decryption that is required, etc. - best left to a specialized method.
    secret = establish_secret(cfg, enc_cfg.secrets_dir, keystore, plaintext)

    passphrase = SelfDestructKey(secret, keypair=keys)
    enc_cfg.log.info("Using '%s' as the encryption secret", passphrase.keyfile)

    encryptor = FileCrypto(encrypt=not cfg.decrypt,
                           secret=passphrase,
                           plain_file=plaintext,
                           dest_dir=enc_cfg.out,
                           force=cfg.force,
                           log=enc_cfg.log)
    encryptor()

    if not cfg.decrypt:
        if enc_cfg.shred:
            enc_cfg.log.warning("Securely destroing %s", plaintext)
            shred(plaintext)
        enc_cfg.log.info("Encryption successful; saving data to store file '%s'.", enc_cfg.store)
        entry = KeystoreEntry(os.path.abspath(plaintext),
                              os.path.abspath(secret),
                              os.path.abspath(encryptor.encrypted_file))
        keystore.add_entry(entry)


def run():
    """ Entry-point script for execution"""
    check_version()
    try:
        config = parse_args()
        main(config)
    except Exception as ex:
        print("[ERROR] Could not complete execution:", ex)
        exit(1)
