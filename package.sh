#!/usr/bin/env bash
#
# Packages the project as a `zipapp` executable.

set -eu

function abspath {
    echo $(python -c "import os; print(os.path.abspath(\"${1:-}\"))")
}

function cleanup {
  [[ -d ${WORKDIR} ]] && rm -rf ${WORKDIR}
}
trap cleanup EXIT


function get_version {
  echo $(python -c "from VERSION import VERSION;print(VERSION)")
}

declare -r BASEDIR="$(abspath $(dirname $0))"
declare -r VENV="crytto"
declare -r PROJECT_NAME="filecrypt"
declare -r WORKDIR=${TMPDIR:-/tmp}/${PROJECT_NAME}
declare -r DEST="${PROJECT_NAME}.pyz"
declare -r TAR="${PROJECT_NAME}-$(get_version)-$(uname -s).tar.gz"

if [[ -z ${WORKON_HOME} || ! -e ${WORKON_HOME}/${VENV}/bin/activate ]]; then
  echo "[ERROR] Virtual environment ${VENV} does not exist"
  exit 1
fi

source ${WORKON_HOME}/${VENV}/bin/activate
cd ${BASEDIR}

# First build the Python Wheel to upload to PyPI:
python setup.py bdist_wheel > /dev/null
echo "[SUCCESS] Filecrypt distribution wheel created"

mkdir -p ${WORKDIR}
cp -r crytto ${WORKDIR}

python -m pip install -r requirements.txt --target ${WORKDIR} > /dev/null
python -m zipapp --output dist/${DEST} --python=$(which python3) \
  --main="crytto.main:entrypoint" -c ${WORKDIR}

cd dist
./${DEST} -o ${WORKDIR}/test.enc ${BASEDIR}/tests/data/plain.txt &&
  ./${DEST} -d -o ${WORKDIR}/test.txt ${WORKDIR}/test.enc

DIFF=$(diff ${BASEDIR}/tests/data/plain.txt ${WORKDIR}/test.txt)
if [[ -n ${DIFF} ]]; then
  echo -e "[ERROR] Files differ: ${DIFF}"
  exit 1
fi

chmod +x ${DEST}
tar cfz ${TAR} ${DEST}
cd ${BASEDIR}

echo "[SUCCESS] ${PROJECT_NAME} ($(get_version)) packaged to ${TAR}"
