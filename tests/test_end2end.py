# Copyright AlertAvert.com (c) 2017. All rights reserved.
# Created by Marco Massenzio (marco@alertavert.com), 2017-09-03


import os
import tempfile

from crytto.filecrypt import FileCrypto
from crytto.utils import Keypair, SelfDestructKey
from tests.common import TestBase


class EndToEndTests(TestBase):
    def setUp(self):
        super().setUp()
        self.plaintext = os.path.join(self.data_dir, "plain.txt")
        self.keyPair = Keypair(
            private=os.path.join(self.data_dir, "test.pem"),
            public=os.path.join(self.data_dir, "test.pub"),
        )
        self.secret = self.temp_filename(suffix=".key")
        self.encrypted = self.temp_filename(suffix=".enc")

    def tearDown(self):
        if os.path.exists(self.encrypted):
            os.remove(self.encrypted)
        if os.path.exists(self.secret):
            os.remove(self.secret)

    def test_encrypt(self):
        key = SelfDestructKey(self.secret, keypair=self.keyPair)
        encrypt = FileCrypto(secret=key, plain_file=self.plaintext, encrypted_file=self.encrypted)

        self.assertTrue(encrypt())
        self.assertTrue(os.path.exists(self.encrypted))

        # Force writing out the secret key.
        key._save()
        self.assertTrue(os.path.exists(self.secret))

        restored_file = tempfile.mkstemp(suffix=".txt")[1]

        # We must set force=True because `mkstemp()` will create an empty file and,
        # without forcing it, FileCrypto will refuse to overwrite it.
        decrypt = FileCrypto(
            secret=SelfDestructKey(self.secret, keypair=self.keyPair),
            plain_file=restored_file,
            encrypted_file=self.encrypted,
            encrypt=False,
            force=True,
        )
        self.assertTrue(decrypt())
        with open(self.plaintext) as expected:
            with open(restored_file) as actual:
                self.assertListEqual(expected.readlines(), actual.readlines())

        # Cleanup.
        os.remove(restored_file)
