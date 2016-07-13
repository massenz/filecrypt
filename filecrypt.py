#!/usr/bin/env python
#
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

See the ``README.md`` file for more details.
"""
import argparse
from collections import namedtuple
import logging
import os
import random
from sh import openssl, shred as _shred, ErrorReturnCode
import sys
from tempfile import mkstemp
import yaml

__author__ = 'Marco Massenzio'


def check_version():
    if sys.version_info < (3, 0):
        print("Python 3.0 or greater required (3.5 recommended). Please consider upgrading or "
              "using a virtual environment.")
        exit(1)

Keypair = namedtuple('Keypair', 'private public')


class EncryptConfiguration(object):

    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    LOG_FORMAT = '%(asctime)s [%(levelname)-5s] %(message)s'

    def __init__(self, conf_file, secret_file=None):
        self.out = None
        self.private = None
        self.public = None
        self.secrets_dir = None
        self.secret = secret_file
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
            except OSError as ex:
                self.log.error("Cannot create directory '%s': %s", self.secrets_dir, ex)
                raise RuntimeError(ex)

        # This contorsion is necessary due to the absence of a do-until construct in Python.
        while not self.secret:
            self.secret = os.path.join(self.secrets_dir,
                                       "pass-key-{:3d}.enc".format(random.randint(0, 999)))
            # We need to prevent overwriting existing encrypted passphrases, so we keep looping
            # until we find an unused filename.
            if os.path.exists(self.secret):
                self.secret = None

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


class FileEncryptor(object):
    """ Encrypts a file using OpenSSL and a secret key.

        By passing the encrypted file as the ``plain_file`` at creation, this class can also be
        used to **decrypt** the file, by calling ``decrypt()``.
    """
    def __init__(self, secret_keyfile, plain_file, dest_dir=None, log=None):
        """ Initializes an encryptor.

        :param secret_keyfile the full path of the encryption key
        :param plain_file the file to encrypt
        :param dest_dir where to place the encrypted file (if not specified, defaults to the
            same directory as the ``plain_file``)
        """
        self.secret = secret_keyfile
        self.plain_file = plain_file
        self.dest = dest_dir or os.path.dirname(plain_file)
        self.outfile = os.path.join(self.dest, '{}.enc'.format(os.path.basename(self.plain_file)))
        self._log = log or logging

    def encrypt(self):
        """Performs the encryption step.

        This uses a combination of the `sh` module and OpenSSL to execute the following command
        line::

            openssl enc -aes-256-cbc -pass file:(secret) < plain_file > dest/plain_file.enc

        :return `True` if the encryption was successful
        :rtype bool
        """
        # Some sanity check first.
        err_msg = ""
        if not os.path.exists(self.plain_file):
            err_msg = "Could not find the file to encrypt '{}'. ".format(self.plain_file)
        if not os.path.isdir(self.dest):
            err_msg += "Destination directory '{}' does not exist. ".format(self.dest)
        if not os.path.exists(self.secret):
            err_msg += "Encryption key/passphrase file '{}' does not exist".format(self.secret)

        if len(err_msg) > 0:
            raise RuntimeError("Cannot encrypt {}: {}".format(self.plain_file, err_msg))

        try:
            self._log.info("Encrypting '%s' to '%s'", self.plain_file, self.outfile)
            with open(self.plain_file, 'rb') as plain_file:
                openssl('enc', '-aes-256-cbc', '-pass',
                        'file:{secret}'.format(secret=self.secret),
                        _in=plain_file,
                        _out=self.outfile)
                self._log.info("File %s encrypted to %s", self.plain_file, self.outfile)
                return True
        except ErrorReturnCode as rcode:
            self._log.error("Encryption failed (%d): %s", rcode.exit_code, rcode.stderr.decode("utf-8"))
        except Exception as ex:
            self._log.error("Could not encrypt %s: %s", self.plain_file, ex)


class SelfDestructKey(object):
    """A self-destructing key: it will shred its contents when it gets deleted.

       This key also encrypts itself with the given key before writing itself out to a file.
    """

    def __init__(self, encrypted_key, keypair):
        """Creates an encryption key, using the given keypair to encrypt/decrypt it.

        The plaintext version of this key is kept in a temporary file that will be securely
        destroyed upon this object becoming garbage collected.

            :param encrypted_key the encrypted version of this key is kept in this file: if it
                does not exist, it will be created when this key is saved
            :param keypair a tuple containing the (private, public) key pair that will be used to
                decrypt and encrypt (respectively) this key.
            :type keypair collections.namedtuple (Keypair)
        """
        self._plaintext = mkstemp()[1]
        self.encrypted = encrypted_key
        self.key_pair = keypair
        if not os.path.exists(encrypted_key):
            openssl('rand', '32', '-out', self._plaintext)
        else:
            with open(self._plaintext, 'w') as self_decrypted:
                openssl('rsautl', '-decrypt', '-inkey', keypair.private, _in=encrypted_key,
                        _out=self_decrypted)

    def __str__(self):
        return self._plaintext

    def __del__(self):
        try:
            if not os.path.exists(self.encrypted):
                self._save()
            shred(self._plaintext)
        except ErrorReturnCode as rcode:
            raise RuntimeError(
                "Either we could not save encrypted or not shred the plaintext passphrase "
                "in file {plain} to file {enc}.  You will have to securely delete the plaintext "
                "version using something like `shred -uz {plain}".format(
                    plain=self._plaintext, enc=self.encrypted))

    def _save(self):
        """ Encrypts the contents of the key and writes it out to disk.

        :param dest: the full path of the file that will hold the encrypted contents of this key.
        :param key: the name of the file that holds an encryption key (the PUBLIC part of a key pair).
        :return: None
        """
        if not os.path.exists(self.key_pair.public):
            raise RuntimeError("Encryption key file '%s' not found" % self.key_pair.public)
        with open(self._plaintext, 'rb') as selfkey:
            openssl('rsautl', '-encrypt', '-pubin', '-inkey', self.key_pair.public,
                    _in=selfkey, _out=self.encrypted)


def shred(filename):
    """Will securely destroy the `filename` using Linux `shred` utility."""
    try:
        _shred('-uz', filename)
    except ErrorReturnCode as rcode:
        raise RuntimeError("Could not securely destroy '%s' (%d): %s", filename,
                           rcode.exit_code, rcode.stderr)


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
    parser.add_argument('plaintext_file',
                        help="The file that will be encrypted and securely destroyed.")
    return parser.parse_args()



def main(cfg):
    enc_cfg = EncryptConfiguration(conf_file=cfg.conf_file, secret_file=cfg.secret)
    plaintext = cfg.plaintext_file

    keys = Keypair(private=enc_cfg.private, public=enc_cfg.public)
    enc_cfg.log.info("Using key pair: %s", keys)

    passphrase = SelfDestructKey(enc_cfg.secret, keypair=keys)
    enc_cfg.log.info("Using '%s' as the encryption secret", str(passphrase))
    enc_cfg.log.info("It will be securely destroyed and encrypted to '%s'", enc_cfg.secret)

    if enc_cfg.shred:
        enc_cfg.log.warning("%s will be encrypted and destroyed", plaintext)

    encryptor = FileEncryptor(secret_keyfile=str(passphrase), plain_file=plaintext,
                              dest_dir=enc_cfg.out, log=enc_cfg.log)

    if encryptor.encrypt():
        if enc_cfg.shred:
            enc_cfg.log.warn("Securely destroing %s", plaintext)
            shred(plaintext)
        enc_cfg.log.info("Encryption successful; saving data to store file '%s'.", enc_cfg.store)
        with open(enc_cfg.store, 'a') as store_file:
            store_file.write(','.join([os.path.abspath(plaintext), enc_cfg.secret,
                                       os.path.abspath(encryptor.outfile)]))
            store_file.write('\n')
    else:
        raise RuntimeError("Encryption failed, original file retained.")


check_version()
if __name__ == '__main__':
    try:
        config = parse_args()
        main(config)
    except Exception as ex:
        print("[ERROR] Could not complete execution.\nReason:", ex, sys.exc_info())
        exit(1)
