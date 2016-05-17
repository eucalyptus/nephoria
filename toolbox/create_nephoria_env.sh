#@IgnoreInspection BashAddShebang

# Helper script for setting up the nephoria test environment.

NEPHORIA_REPO=https://github.com/eucalyptus/nephoria
ADMINAPI_REPO=https://github.com/eucalyptus/adminapi
ADMINAPI_BRANCH='master'
NEPHORIA_BRANCH='master'
VIRT_ENV_NAME='envnephoria'

while [[ $# > 1 ]]
do
key="$1"

case $key in
    -r|--nephoria-repo)
    NEPHORIA_REPO="$2"
    shift # past argument
    ;;
    --adminapi-repo)
    ADMINAPI_REPO="$2"
    ;;
    -a|--adminapi-branch)
    ADMINAPI_BRANCH="$2"
    shift # past argument
    ;;
    -n|--nephoria-branch)
    NEPHORIA_BRANCH="$2"
    shift # past argument
    ;;
    -v|--virtual-env)
    VIRT_ENV_NAME="$2"
    shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

# Create python environment
# Create the virtualenv if it does not already exist...
if [ ! -d $VIRT_ENV_NAME ];then
    virtualenv $VIRT_ENV_NAME
fi

### Install adminapi
if [ ! -d adminapi ]; then
    git clone $ADMINAPI_REPO
fi
cd adminapi
git remote update origin --prune
git fetch
git remote -v
git branch -a
git checkout $ADMINAPI_BRANCH
git pull origin $ADMINAPI_BRANCH
../envnephoria/bin/python setup.py install > adminapi-install.log 2>&1
if [ $? -ne 0 ]; then
    echo "Error installing adminapi. See adminapi-install.log for details"
fi
cd -
pwd
ls -la
### Install nephoria
if [ ! -d nephoria ]; then
    git clone $NEPHORIA_REPO
fi
cd nephoria
ls -la
git remote update origin --prune
git fetch
git remote -v
git branch -a
git checkout $NEPHORIA_BRANCH
git pull origin $NEPHORIA_BRANCH

../envnephoria/bin/python setup.py install > nephoria-install.log 2>&1
if [ $? -ne 0 ]; then
    echo "Error installing nephoria. See nephoria-install.log for details"
fi
cd -
