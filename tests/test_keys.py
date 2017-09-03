# Copyright AlertAvert.com (c) 2017. All rights reserved.
# Created by Marco Massenzio (marco@alertavert.com), 2017-09-03


import os

from crytto.utils import Keypair, SelfDestructKey
from tests.common import TestBase


class SelfDestructKeyTests(TestBase):

    def tearDown(self):
        if hasattr(self, "tempKey"):
            os.remove(self.tempKey)

    def test_key(self):
        keys = Keypair(private=os.path.join(self.data_dir, "test.pem"),
                       public=os.path.join(self.data_dir, "test.pub"))
        self.tempKey = self.temp_filename(suffix='.key')
        self.assertFalse(os.path.exists(self.tempKey))

        key = SelfDestructKey(self.tempKey, keys)

        plain_keyfile = key.keyfile
        self.assertTrue(os.path.exists(plain_keyfile))

        passphrase = bytes(key)

        # Deleting the key causes the passphrase to be wiped, and the
        # encrypted key to be saved to file.
        key = None
        self.assertFalse(os.path.exists(plain_keyfile))
        self.assertTrue(os.path.exists(self.tempKey))

        # Recreate the key from the encrypted contents of the original key.
        key = SelfDestructKey(self.tempKey, keys)

        # And assert that the decrypted passphrase matches.
        self.assertEqual(passphrase, bytes(key))



