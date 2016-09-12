# Copyright AlertAvert.com (c) 2015. All rights reserved.
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

import logging
import os
from sh import ErrorReturnCode, openssl

__author__ = 'Marco Massenzio'
__email__ = 'marco@alertavert.com'


class FileCrypto(object):
    """ Encrypts a file using OpenSSL and a secret key.

        By passing the encrypted file as the ``plain_file`` at creation, this class can also be
        used to **decrypt** the file, by calling ``decrypt()``.

        More details can be found at:
        https://github.com/massenz/HOW-TOs/blob/master/HOW-TO%20Encrypt%20archive.rst
    """
    def __init__(self, secret, plain_file, dest_dir=None, encrypt=True, force=False, log=logging):
        """ Initializes an encryptor.

        This is always definted in terms of the ``plain_file``, whether it exists and needs to be
        encrypted, or it does not, and will be created from the process of decryption: the encrypted
        file is **always** assumed to have the same name as the ``plain_file`` (including any
        extensions) and the trailing ``.enc`` extension.

        Unless specified in ``dest_dir``, the output of the encryption/decryption will always be
        alongside the existing file.

        Finally, the encryption key is in the ``secret_keyfile`` in a readable format.

        :param secret: the encryption key
        :type secret: self_destruct_key.SelfDestructKey
        :param plain_file: the file to encrypt, or the destination for the decryption.
        :param dest_dir: where to place the encrypted file (if not specified, defaults to the
            same directory as the ``plain_file``)
        :param encrypt: whether this callable should perform an encryption or decryption
        :type encrypt: bool
        :param force: whether we should overwrite the destination file if it already exists
        :type force: bool
        :param log: a logger; if not specified the `logging` module is used
        """
        self.secret = secret
        self.plain_file = plain_file
        self.dest = dest_dir or os.path.dirname(plain_file)
        self.overwrite = force
        self.encrypt = encrypt
        self.encrypted_file = os.path.join(self.dest, '{}.enc'.format(os.path.basename(self.plain_file)))
        self._log = log

    def _check(self):
        """A few sanity checks before setting out to encrypt/decrypt the file.

        :param encrypt: whether we are checking before encrypting the plaintext file.
        :type encrypt: bool

        :raise RuntimeError: if any error condition is detected.
        """
        err_msg = ""
        plaintext_exists = os.path.exists(self.plain_file)
        encrypt_exists = os.path.exists(self.encrypted_file)

        if self.encrypt:
            if not plaintext_exists:
                err_msg += "Could not find the file to encrypt '{}'. ".format(self.plain_file)
        else:
            if not encrypt_exists:
                err_msg += "Could not find the encrypted file '{}'.".format(self.encrypted_file)
            if plaintext_exists and not self.overwrite:
                err_msg += "The plaintext file '{}' already exists and overwrite was not " \
                           "specified. ".format(self.plain_file)

        if not os.path.isdir(self.dest):
            err_msg += "Destination directory '{}' does not exist. ".format(self.dest)
        if not os.path.exists(self.secret.keyfile):
            err_msg += "Encryption key/passphrase file '{}' does not exist".format(self.secret.keyfile)

        if len(err_msg) > 0:
            raise RuntimeError("Cannot process {}: {}".format(self.plain_file, err_msg))

    def __call__(self, *args, **kwargs):
        """ Makes a `FileCrypto` a callable object and executes encryption/decryption."""
        self._check()
        action = None
        try:
            if self.encrypt:
                action = "encryption"
                return self._encrypt()
            else:
                action = "decryption"
                return self._decrypt()

        except ErrorReturnCode as rcode:
            self._log.error("%s failed (%d): %s", action, rcode.exit_code,
                            rcode.stderr.decode("utf-8"))
        except Exception as ex:
            self._log.error("Could not execute %s: %s", action, ex)

    def _encrypt(self):
        """Performs the encryption step.

        This uses a combination of the `sh` module and OpenSSL to execute the following command
        line::

            openssl enc -aes-256-cbc -pass file:(secret) < plain_file > dest/plain_file.enc

        :return `True` if the encryption was successful
        :rtype bool
        """
        self._log.info("Encrypting '%s' to '%s'", self.plain_file, self.encrypted_file)
        with open(self.plain_file, 'rb') as plain_file:
            openssl('enc', '-aes-256-cbc', '-pass',
                    'file:{secret}'.format(secret=self.secret.keyfile),
                    _in=plain_file,
                    _out=self.encrypted_file)
        self._log.info("File '%s' encrypted to '%s'", self.plain_file, self.encrypted_file)
        return True

    def _decrypt(self):
        """ Performs the decryption of an encrypted file.

        This is the reverse operation of ``encrypt()`` executing virtually an identical
        `openssl` command, with the in/out roles reversed and adding a `-d` flag.

        :return `True` if the deryption was successful
        :rtype bool
        """
        self._log.info("Decrypting file '%s' to '%s'", self.encrypted_file, self.plain_file)
        with open(self.encrypted_file, 'rb') as enc_file:
            openssl('enc', '-aes-256-cbc', '-d', '-pass',
                    'file:{secret}'.format(secret=self.secret.keyfile),
                    _in=enc_file,
                    _out=self.plain_file)
        self._log.info("File '%s' decrypted to '%s'", self.encrypted_file, self.plain_file)
        return True
