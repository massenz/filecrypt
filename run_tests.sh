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

set -eu

# Prints the absolute path of the file given as $1
#
function abspath {
    local path=${1:-}
    if [[ -z ${path} ]]; then
        exit 1
    fi
    echo $(python -c "import os; print(os.path.abspath(\"${path}\"))")
}


TEMP_CONF="/tmp/temp_conf.yml"
BASEDIR="$(abspath $(dirname $0))"
WORKDIR="${BASEDIR}/examples"

# Clean up after ourselves.
function finish {
    rm -rf /tmp/plaintext* ${TEMP_CONF} /tmp/keys.csv
}
trap finish EXIT


export PYTHONPATH="${BASEDIR}:${PYTHONPATH:-}"

cd ${BASEDIR}/tests
nosetests ${BASEDIR}/tests

cd ${BASEDIR}
touch /tmp/keys.csv
cat <<EOF > ${TEMP_CONF}
keys:
     private: ${BASEDIR}/tests/data/test.pem
     public: ${BASEDIR}/tests/data/test.pub
     secrets: /tmp
store: /tmp/keys.csv
out: /tmp
EOF


cmd="encrypt --conf ${TEMP_CONF} -s ${WORKDIR}/secret-key.enc -o \
/tmp/plaintext.txt.enc --keep ${WORKDIR}/plaintext.txt"
echo -e "\n============\n${cmd}\n\n----------\n"
${BASEDIR}/run ${cmd}

if [[ ! -e /tmp/plaintext.txt.enc ]]; then
    echo "[ERROR] The encrypted file could not be found"
    exit 1
fi

cmd="decrypt --conf ${TEMP_CONF} -s ${WORKDIR}/secret-key.enc -o \
/tmp/plaintext.txt /tmp/plaintext.txt.enc"
echo -e "${cmd}\n============\n"
${BASEDIR}/run ${cmd}

DIFF=$(diff /tmp/plaintext.txt ${WORKDIR}/plaintext.txt)

if [[ -n ${DIFF} ]]; then
    echo -e "[ERROR] Files differ:\n\n----------\n${DIFF}\n----------\n"
    exit 1
fi

echo "[SUCCESS] All tests passed."
