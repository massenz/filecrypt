# @copyright: AlertAvert.com (c) 2015. All rights reserved.

import os

from crytto.main import establish_secret
from crytto.utils import KeystoreManager
from tests import common


class EstablishSecretsTests(common.TestBase):
    def test_return_given_file_if_exists(self):
        secret_file = os.path.join(self.data_dir, "secret")
        result = establish_secret(secret_file, "/secrets", None, None, False)
        self.assertEqual(secret_file, result)

    def test_lookup(self):
        keystore = KeystoreManager(os.path.join(self.data_dir, "test_keys.csv"))
        result = establish_secret(None, self.data_dir, keystore, "my_encrypted_secrets.enc", True)
        self.assertEqual("/data/keys/my-secret-key", result)

    def test_lookup_with_full_path(self):
        keystore = KeystoreManager(os.path.join(self.data_dir, "test_keys.csv"))
        result = establish_secret(
            None, self.data_dir, keystore, "/tmp/foo/bar/my_secret.doc.enc", True
        )
        self.assertEqual("/data/keys/another_secret.pem", result)

        # And should work also with the relative path to the encrypted file
        result = establish_secret(None, self.data_dir, keystore, "bar/my_secret.doc.enc", True)
        self.assertEqual("/data/keys/another_secret.pem", result)

    def test_use_secrets_dir(self):
        secret = "foo.key"
        secrets_dir = "/var/keys"
        result = establish_secret(secret=secret, secrets_dir=secrets_dir, keystore=None)
        self.assertEqual(os.path.join(secrets_dir, secret), result)
