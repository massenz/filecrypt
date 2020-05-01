
# filecrypt - OpenSSL file encryption

Author  | [M. Massenzio](http://codetrips.com)
 -------|-----------
Version | 0.7.2
Updated | 2020-04-30
Code    | [bitbucket.org](https://bitbucket.org/marco/filecrypt)


# overview

Uses OpenSSL library to encrypt a file using a private/public key pair and a one-time secret.

A full description of the process can be found [here](https://github.com/massenz/HOW-TOs/blob/master/HOW-TO%20Encrypt%20archive.rst).

See also this [blog entry](https://codetrips.com/2016/07/13/filecrypt-openssl-file-encryption/) for more details.

# installation

Install directly from PyPi:

    pip install crytto

Please note the **package name** (`filecrypt` was conflicting with the existing `FileCrypt` package name, and `crypto` was already taken).

This requires OpenSSL to be installed on your machine:

    sudo apt-get install openssl

Alternatively, clone the project from github and follow the instructions below:

    git clone git@bitbucket.org:marco/filecrypt.git

Once cloned, you can try out functionality by packaging it as a self-contained executable: use
the `package.sh` script to generate a `filecrypt.pyz` self-extracting executable in the `dist/` folder 
 and then you can encrypt/decrpyt files (see the [configuration](#configuration) section first).

```shell script
# To encrypt 
./filecrypt.pyz -o test.enc /path/to/my_plaintext.txt

# To decrypt:
./filecrypt.pyz -d -o /path/to/whatever.txt test.enc
```

Once all dependencies are installed:

    pip install -r requirements.txt

tests can be run via:

    ./run_tests.sh
    
See both the `run_tests` and `package` scripts for examples of how to use encryption/decryption.


# configuration

This uses a YAML file to describe the configuration; by default it assumes it is in `/etc/filecrypt/conf.yml` but its location can be specified using the `-f` flag.

The structure of the `conf.yml` file is as follows:

```yaml
keys:
     private: sample.pem
     public: sample.pub
     secrets: .

store: keys.csv

##
# Any option below is optional and can be omitted.
#
# Where to store the encrypted file; the folder MUST already exist and the user
# have write permissions.  Defaults to the current directory; can be overridden
# using --out on the command line.
#
#out: /data/store/file

# Whether to securely delete the original plaintext file; by default it is kept.
# It can be overridden by using `--keep` when running `filecrypt`.  True by default.
shred: true

# Optional logging configuration - mostly useful to
# diagnose issues.  Default is WARN level.
logging:
   format: "%(asctime)s [%(levelname)-5s] %(message)s"
   level: WARN

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

Always use the `--help` option to see the most up-to-date options available; anyway, the basic usage is:

    filecrypt my_secret.txt

which will create a `my_secret.txt.enc` file in the current directory, unless a different one has been specified using the `out` option in `/etc/filecrypt/conf.yml`.

A completely random and cryptographically secure key will have been created; used; and then encrypted to the `secrets` location, its full path stored in the CSV keystore named in the `store` option of the YAML configuration file.

Finally, the plaintext version of this key will have been safely destroyed.

A more elaborate one (see the example configuration in `examples/example_conf.yaml`):

    filecrypt --conf example_conf.yaml -s secret-key.enc plaintext.txt

will create an encrypted copy of the file to be stored as `/data/store/plaintext.txt.enc`; the original file __will not__ be securely destroyed (using `shred`); and the encryption key name and location (the current directory, and `secret-key.enc`) to be stored in the `keys.csv` file:

```yaml
# Fragment of example_conf.yaml
...
store: keys.csv
out: /data/store
shred: false
```

__Specifying the encryption destination__

By default, the encrypted filename has the same name as the plaintext file, with the `.enc` extension appended; and it is saved to either the current directory or the `out` location specified in the configuration YAML.

By using the `--out` (`-o`) option, it is possible to specify the location of the output encrypted file, either absolute, or relative to the current directory:

    filecrypt -o mysecret.ser my_secret.doc

or:

    filecrypt -o secret/files/mysecret.ser my_secret.doc

Regardless of the means of specifying the input/outpup files, the full path to both files will __always__ be used in the CSV keystore, regardless of whether a relative or absolute path was specified on the command line.


__IMPORTANT__
>We recommend testing your configuration and command-line options on test files: `shred` erases files in a _terminal_ way that is __not__ recoverable: if you mess up, __you will lose data__.
>
>You have been warned.


### decryption

To decrypt a file that has been encrypted using this utility, use the `-d` flag:

    decrypt -o example_conf.yaml -d plaintext.txt

If the encryption key (`--secret` or `-s`) is not specified, then the application will try and locate the plaintext file in the keystore specified in the `conf.yaml` using the `store` key:

```yaml
store: keys.csv
...
```
and derive the location of the encryption key from the entry, if one is found.

Please note that __only the filename is used to lookup the key__ and so two **encrypted** 
filenames in different directories but with the same name will be assumed to have been encrypted
with the same `passphrase`.

The `passphrase` file, is stored with its full path: if you move the keys, or rename any of
the folder in their path, you will have to update the `keystore` (or use the `-s` flag when
decrypting).

As with encryption, the `--out` flag can be used to specify the output file; otherwise,
the current directory will be used.

The encrypted file will be left untouched: the `--keep` flag _may_ be used, but will have no effect and the value of the `shred:` option will be ignored.

As the encrypted file is already cryptographically secure a simple `rm my_secret.doc.enc` will be sufficient to guarantee privacy.

### sharing files

As of `0.5.x`, `crytto` supports encrypting a file using solely a Public Key, and then the resulting ecnrypted file can be securely decrypted by the owner of the Secret Key.

The main use case is to enable Alice to send Bob an encrypted file, once Bob has given her a copy of his Public key; call the latter `bob.pub` and the file to share `my_secret.txt`, then Alice can execute:

    filecrypt --send --key bob.pub --out my-secret.ser my_secret.txt

after encryption, in the current directory there will be the following two new files:

    my-secret.ser
    pass-key-000854.enc

the former is the encrypted contents of `my_secret.txt` and the latter the encrypted passphrase (leaving out the `--out` argument would have made the encrypted file's name `my_secret.txt.enc`).

Those files can be both sent to Bob or, even better, provided to him separately for added security; either way, upon receiving them, Bob can run the following (we assume the `bob.pub` was the private half of the configured key pair that he keeps in his [configuration file](#configuration)):

    filecrypt -s pass-key-000854.enc --out alice_secret.txt -d my-secret.ser

(again, leaving out the `--out` is useful when using the defaults, as the `my_secret.txt.enc` would have turned back into `my_secret.txt` -- in this case, the plaintext decrypted file would have been called `my-secret.ser.out`).

## references

* a [detailed HOW-TO](https://github.com/massenz/HOW-TOs/blob/master/HOW-TO%20Encrypt%20archive.rst) with the steps to encrypt a file manually;
* the original [Ask Ubuntu](http://askubuntu.com/questions/95920/encrypt-tar-gz-file-on-create) post;
* [OpenSSL](https://openssl.org);
* [Ubuntu guide to OpenSSL](https://help.ubuntu.com/community/OpenSSL).
