#!/bin/bash
set -x
venv="nephoria_venv"
neph_branch="master"
adminapi_branch="master"
gpg="--nogpg"
NEPHORIA_REPO="https://github.com/eucalyptus/nephoria.git"

while [[ $# > 1 ]]
do
key="$1"

case $key in
    -r|--nephoria-repo)
    NEPHORIA_REPO="$2"
    shift # past argument
    ;;
    --gpg)
    gpg=""
    ;;
    -a|--adminapi-branch)
    adminapi_branch="$2"
    shift # past argument
    ;;
    -n|--nephoria-branch)
    neph_branch="$2"
    shift # past argument
    ;;
    -v|--virtual-env)
    venv="$2"
    shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

yum install -y $gpg python-devel gcc git python-setuptools python-virtualenv libffi-devel openssl-devel readline-devel patch
rpm -qa | grep virtualenv # verify it was installed successfully above
yum repolist # check repos
if [ ! -d adminapi ]; then
    git clone https://github.com/eucalyptus/adminapi.git
fi
if [ ! -d nephoria ]; then
    git clone $NEPHORIA_REPO
fi
if [ "x$venv" != "x" ]; then
    if [ ! -d $venv ]; then
        virtualenv $venv
    fi
    source $venv/bin/activate
fi
cd adminapi
git remote update origin --prune
git fetch
git checkout $adminapi_branch
git pull origin $adminapi_branch
python setup.py install
cd -
cd nephoria
git remote update origin --prune
git fetch
git checkout $neph_branch
git pull origin $neph_branch
python setup.py install
cd -
