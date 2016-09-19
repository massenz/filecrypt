
# filecrypt - OpenSSL file encryption

Author  | [M. Massenzio](https://www.linkedin.com/in/mmassenzio)
 -------|-----------
Version | 0.3.0
Updated | 2016-09-18

## overview

Uses OpenSSL library to encrypt a file using a private/public key pair and a one-time secret.

A full description of the process can be found [here][how-to].

See also this [blog entry](https://codetrips.com/2016/07/13/filecrypt-openssl-file-encryption/) for more details.

# install

This package has now been published on [PyPi](http://pypi.org) and can be installed simply using 
`pip`:

    pip install crytto
    
Please note the package name (`filecrypt` was conflicting with the existing `FileCrypt` package 
name).


# configuration

This uses a YAML file to describe the configuration; by default it assumes it is in
`/etc/filecrypt/conf.yml` but its location can be specified using the `-f` flag.

The structure of the `conf.yml` file is as follows:

```yaml
keys:
     private: sample.pem
     public: sample.pub
     secrets: .

store: keys.csv

# Where to store the encrypted file; the folder MUST already exist and the user
# have write permissions.
#out: /data/store/file

# Whether to securely delete the original plaintext file.
shred: true

logging:
   format: "%(asctime)s [%(levelname)-5s] %(message)s"
   level: DEBUG

```

The `private`/`public` keys are a key-pair generated using the `openssl genrsa` command; the
encryption key used to actually encrypt the file will be created in the `secrets` folder,
and afterward encrypted using the `public` key and stored in the location provided.

The name will be `pass-key-nnnn.enc`, where `nnnn` will be a random value between `1000` and
`9999`, that has not been already used for a file in that folder.

The name of the secret passphrase can also be defined by the user, using the `--secret` option
(it will be left unmodified):

* if it does not exist a random secure one will be created, used for encryption, 
  then encrypted and saved with the given path, while the plain-text temporary version securely 
  destroyed; OR

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

### keypair generation

We do not provide the means to generate them (this will be done at a later stage), but for now 
they can be generated using:

    openssl genrsa -out ./key.pem 2048
    openssl rsa -in key.pem -out key.pub -outform PEM -pubout

their path can then be specified in the `conf.yaml` file.

### encryption

Always use the `--help` option to see the most up-to-date options available; anyway, the basic
usage is (see the example configuration in `examples/example_conf.yaml`):
    
    python3 main.py -f example_conf.yaml -s secret-key.enc plaintext.txt

will create an encrypted copy of the file to be stored as `/data/store/201511_data.tar.gz.enc`,
the original file __will not__ be securely destroyed (using `shred`) and the new encryption key to be stored, encrypted in `/opt/store/pass-key-778.enc`.

A new line will be appended to `keys.csv`:

    /.../filecrypt/examples/plaintext.txt,secret-key.enc,/.../filecrypt/examples/plaintext.txt.enc

the full path to both files will __always__ be used, regardless of whether a relative or absolute
 path was specified on the command line.
 
 
__IMPORTANT__
>We recommend testing your configuration and command-line options on test files: `shred` erases files in a _terminal_ way that is __not__ recoverable: if you mess up, __you will lose data__.
>
>You have been warned.

### decryption

To decrypt a file that has been encrypted using this utility, just run virtually the same 
command, but add the `-d` flag: we will automatically append the `.enc` extension to the file 
name given, and decrypt it using the passed in secret key (`-s` flag):

    python3 main.py -f example_conf.yaml -s secret-key.enc -d plaintext.txt

__NOTE__
> Use the name of the plaintext file, even if it does not currently exists: the encrypted file 
(which should obviously exist) will be assumed to be the same with a `.enc` trailing extension 
(in the case of the example above, it will look for `plaintext.txt.enc` in the current directory).

If the encryption key (`--secret` or `-s`) is not specified, then the application will try and 
locate the plaintext file in the keystore specified in the `conf.yaml` using the `store` key:

```yaml
store: keys.csv
...
```
and derive the location of the encryption key from the entry, if one is found.

Please note that __the full absolute path must match__ even if only a relative path was given at 
the command line, as files are always stored with their full path when saved to the key store.


## references

* a [detailed HOW-TO](how-to) with the steps to encrypt a file manually;
* the original [Ask Ubuntu][ask-ubuntu] post;
* [OpenSSL](https://openssl.org);
* [Ubuntu guide to OpenSSL][ubuntu openssl].

[how-to]: https://github.com/massenz/HOW-TOs/blob/master/HOW-TO%20Encrypt%20archive.rst
[ask-ubuntu]: http://askubuntu.com/questions/95920/encrypt-tar-gz-file-on-create
[ubuntu openssl]: https://help.ubuntu.com/community/OpenSSL
