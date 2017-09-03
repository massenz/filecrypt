#!/usr/bin/env bash
#
# Copyright AlertAvert.com (c) 2017. All rights reserved.
# Created by Marco Massenzio (marco@alertavert.com), 2017-09-03
#
# This script runs encryption/decryption end-to-end to test the
# correct installation and working of the `crytto` package.
#
# For this to work, you MUST install it first:
#   pip install crytto
#
# See: https://github.com/massenz/filecrypt for more details

TEMP_CONF="/tmp/temp_conf.yml"
WORKDIR="$(dirname $0)/examples"

# Clean up after ourselves.
function finish {
    rm -rf /tmp/plaintext* ${TEMP_CONF} /tmp/keys.csv
}
trap finish EXIT

set -eu

touch /tmp/keys.csv
cat <<EOF > ${TEMP_CONF}
keys:
     private: ${WORKDIR}/test.pem
     public: ${WORKDIR}/test.pub
     secrets: /tmp
store: /tmp/keys.csv
out: /tmp
EOF


encrypt -f ${TEMP_CONF} -s ${WORKDIR}/secret-key.enc \
    -o /tmp/plaintext.txt.enc --keep ${WORKDIR}/plaintext.txt

if [[ ! -e /tmp/plaintext.txt.enc ]]; then
    echo "[ERROR] The encrypted file could not be found"
    exit 1
fi

decrypt -f ${TEMP_CONF} -s ${WORKDIR}/secret-key.enc \
    -o /tmp/plaintext.txt /tmp/plaintext.txt.enc

DIFF=$(diff /tmp/plaintext.txt ${WORKDIR}/plaintext.txt)

if [[ -n ${DIFF} ]]; then
    echo -e "[ERROR] Files differ:\n${DIFF}"
    exit 1
fi

echo "[SUCCESS] All tests passed."
