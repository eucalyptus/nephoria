#!/bin/bash
venv="nephoria_venv"
neph_branch="oldboto"
adminapi_branch="master"
yum install -y python-devel gcc git python-setuptools python-virtualenv
if [ ! -d adminapi ]; then
    git clone https://github.com/nephomaniac/adminapi.git
fi
if [ ! -d nephoria ]; then
    git clone https://github.com/nephomaniac/nephoria.git
fi
if [ "x$venv" != "x" ]; then
    if [ ! -d $venv ]; then
        virtualenv $venv
    fi
    source $venv/bin/activate
fi
cd adminapi
git fetch
git checkout $adminapi_branch
git pull origin $adminapi_branch
python setup.py install
cd -
cd nephoria
git fetch
git checkout $neph_branch
git pull origin $neph_branch
python setup.py install
cd -