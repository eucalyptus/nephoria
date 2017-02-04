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

which yum
if [ $? -eq 0 ]; then
        yum install python-setuptools python-pip python-virtualenv gcc python-devel git libffi-devel openssl-devel readline-devel patch -y
fi

# Create python environment
# Create the virtualenv if it does not already exist...
if [ ! -d $VIRT_ENV_NAME ];then
    echo "CREATING VIRTUAL ENV $VIRT_ENV_NAME in $(pwd)..."
    virtualenv $VIRT_ENV_NAME
    if [ $? -ne 0 ]; then
        echo "ERROR creating virtual env"
        exit 1
    fi
fi
source $VIRT_ENV_NAME/bin/activate
pip install --upgrade pip
pip install --upgrade distribute

### Install adminapi
echo "Cloning and Installing admin api..."
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
echo "Installing adminapi..."
../$VIRT_ENV_NAME/bin/python setup.py install > adminapi-install.log 2>&1
if [ $? -ne 0 ]; then
    echo "Error installing adminapi. See adminapi-install.log for details"
    cat adminapi-install.log
    exit 1
fi
cd -
pwd
ls -la
### Install nephoria
echo "Cloning and Installing nephoria..."
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

ls
pwd
echo "Installing nephoria..."
../$VIRT_ENV_NAME/bin/python setup.py install > nephoria-install.log 2>&1
if [ $? -ne 0 ]; then
    echo "Error installing nephoria. See nephoria-install.log for details"
    cat nephoria-install.log
    exit 1
fi
cd -
