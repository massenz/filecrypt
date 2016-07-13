
# filecrypt - OpenSSL file encryption

Author  | [M. Massenzio](https://www.linkedin.com/in/mmassenzio)
:-------|---------------------------------:
Version | 0.1.0
Updated | 2016-07-10

## overview


Uses OpenSSL library to encrypt a file using a private/public key pair and a one-time secret.

A full description of the process can be found [here][how-to].

# configuration

This uses a YAML file to describe the configuration; by default it assumes it is in
`/etc/filecrypt/conf.yml` but its location can be specified using the `-f` flag.

The structure of the `conf.yml` file is as follows:

```yaml
keys:
    private: /home/bob/.ssh/secret.pem
    public: /home/bob/.ssh/secret.pub
    secrets: /opt/store/

store: /home/bob/encrypt/stores.csv

# Where to store the encrypted file; the folder MUST already exist and the user
# have write permissions.
out: /data/store/enc

# Whether to securely delete the original plain-text file (optional, default true).
shred: false
```

The `private`/`public` keys are a key-pair generated using the `openssl genrsa` command; the
encryption key used to actually encrypt the file will be created in the `secrets` folder,
and afterward encrypted using the `public` key and stored in the location provided.

The name will be `pass-key-nnn.enc`, where `nnn` will be a random value between `000` and
`999`, that has not been already used for a file in that folder.

The name of the secret passphrase can also be defined by the user, using the `--secret` option
(specify the full path, it will be left unmodified):

* if it does not exist a random secure one will be created, used for encryption, then encrypted and saved with the given path, while the plain-text temporary version securely destroyed; OR

* if it is the name of an already existing file, it will be decrypted, used to encrypt the file,
then left __unchanged__ on disk.

**NOTE** we recommend NOT to re-use encryption passphrases, but always generate a new secret.

**NOTE** it is currently not possible to specify a plain-text passphrase: we always assume that
the given file has been encrypted using the `private` key.


The `store` file is a CSV list of:

```
"Original archive","Encryption key","Encrypted archive"
201511_data.tar.gz,/opt/store/pass-key-001.enc,201511_data.tar.gz.enc
```

a new line will be appended at the end; any comments will be left unchanged.

## usage

Always use the `--help` option to see the most up-to-date options available; anyway, the basic
usage is (assuming the example configuration shown above is saved in `/opt/enc/conf.yml`):

    filecrypt.py -f /opt/enc/conf.yml /data/store/201511_data.tar.gz

will create an encrypted copy of the file to be stored as `/data/store/201511_data.tar.gz.enc`,
the original file __will not__ be securely destroyed (using `shred`) and the new encryption key to be stored, encrypted in `/opt/store/pass-key-778.enc`.

A new line will be appended to `/home/bob/encrypt/stores.csv`:

    /data/store/201511_data.tar,pass-key-778.enc,/data/store/201511_data.tar.gz.enc

__IMPORTANT__
>We recommend testing your configuration and command-line options on test files: `shred` erases files in a _terminal_ way that is __not__ recoverable: if you mess up, __you will lose data__.
>
>You have been warned.

## references

* a [detailed HOW-TO](how-to) with the steps to encrypt a file manually;
* the original [Ask Ubuntu][ask-ubuntu] post;
* [OpenSSL](https://openssl.org);
* [Ubuntu guide to OpenSSL][ubuntu openssl].

[how-to]: https://github.com/massenz/HOW-TOs/blob/master/HOW-TO%20Encrypt%20archive.rst
[ask-ubuntu]: http://askubuntu.com/questions/95920/encrypt-tar-gz-file-on-create
[ubuntu openssl]: https://help.ubuntu.com/community/OpenSSL
