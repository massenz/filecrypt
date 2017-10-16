# Copyright AlertAvert.com (c) 2017. All rights reserved.
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


import argparse
import os

from common import TestBase
from crytto.main import encrypt_to_send, encrypt


class TestSend(TestBase):
    def setUp(self):
        super().setUp()
        self.plaintext = os.path.join(self.data_dir, "plain.txt")
        self.pubkey = os.path.join(self.data_dir, "test.pub")
        self.encrypted = os.path.join(self.data_dir, 'plain.txt.enc')
        self.conf = os.path.join(self.data_dir, 'test.yml')

    def tearDown(self):
        if os.path.exists(self.encrypted):
            os.remove(self.encrypted)

    def make_fake_cli_opts(self, secret, infile, outfile):
        args = [
            '--secret',
            '--conf-file',
            '--out',
            '--keep',
            'infile',
            '--force',
        ]
        fakeparser = argparse.ArgumentParser()
        for arg in args:
            fakeparser.add_argument(arg)
        return fakeparser.parse_args(['--secret', secret,
                                      '--conf-file', self.conf,
                                      '--out', outfile,
                                      infile,
                                      ])

    def test_send(self):
        secret = None
        decrypted = None
        try:
            with open(self.plaintext) as plain:
                text = plain.read()

            dest, secret, outfile = encrypt_to_send(self.plaintext, self.pubkey, self.data_dir)
            self.assertTrue(os.path.exists(secret))
            self.assertEqual(self.encrypted, os.path.join(dest, outfile))
            self.assertTrue(os.path.exists(self.encrypted))

            decrypted = '/tmp/decrypt.txt'
            options = self.make_fake_cli_opts(secret, self.encrypted, decrypted)
            encrypt(options, should_encrypt=False)

            with open(decrypted) as plain:
                self.assertEqual(text, plain.read())
        finally:
            if secret and os.path.exists(secret):
                os.remove(secret)
            if os.path.exists(decrypted):
                os.remove(decrypted)
