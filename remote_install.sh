#!/usr/bin/env bash
SSH_HOST="$1"

if [ "$#" -ne 1 ]; then
  echo "$0 [SSH HOST SPECIFICATION]"
  echo "  Deploys the only wheel (*.whl) in dist/ to a remote host via pip & SSH."
  exit 1
fi

if [ -z "$VIRTUAL_ENV" ]; then
  echo -e "\e[36m No venv detected locally. Should we set one up in $(pwd)?\e[0m"
  read -p "Enter to continue, Ctrl-C to abort: " -n 1 -r
  python3 -m venv . || exit 2
  source ./bin/activate || exit 2
  echo -e "\e[36m Looking good.\e[0m"
fi

echo -e "\e[36m First, building wheel locally.\e[0m"
rm -rf ./dist
python3 -m pip install --upgrade setuptools wheel || exit 2
python3 setup.py sdist bdist_wheel || exit 2
echo -e "\e[36m Wheel files:\e[0m"
ls -hl ./dist

WHEEL_PATH="$(find ./dist -name '*.whl' | head -n1)"
echo -e "\e[36m Found wheel at '$WHEEL_PATH'\e[0m"
if [ -z "$WHEEL_PATH" ]; then
  echo "No matching wheel found..?"
  exit 1
fi

echo -e "\e[36m Connecting to $SSH_HOST to upload wheel.\e[0m"
ssh "$SSH_HOST" "rm -rf ./.ipsiblings_deploy_tmp; mkdir -p ./.ipsiblings_deploy_tmp" || exit 2
scp "$WHEEL_PATH" "$SSH_HOST:./.ipsiblings_deploy_tmp/" || exit 2

echo -e "\e[36m Make sure the packages stated in the Distribution section of README.md are installed on the server."
echo -e " Installing using pip. This might ask for your remote sudo password.\e[0m"
MAIN_SSH_COMMAND=$(
  cat <<'ENDSSH'
sudo tee /root/.ipsiblings_tmp_script.sh >/dev/null <<'ENDCMD'
#!/usr/bin/env bash
SAVED_PWD=$(pwd)
pushd .ipsiblings_deploy_tmp
WHEEL_PATH=$(find . -name '*.whl' | head -n1)
if [ -z "$WHEEL_PATH" ]; then
  echo "Unable to locate wheel on remote server."
  exit 3
fi
echo -e "\e[36m Located wheel on remote: $WHEEL_PATH\e[0m"
popd
mkdir -p /root/ipsiblings || exit 3
pushd /root/ipsiblings
mv "$SAVED_PWD/.ipsiblings_deploy_tmp/$WHEEL_PATH" . || exit 3
rm -r "$SAVED_PWD/.ipsiblings_deploy_tmp" || exit 3
python3 -m venv . || exit 3
source ./bin/activate || exit 3
pip3 install wheel || exit 3
pip3 install --upgrade "$WHEEL_PATH" || exit 3
if ! ipsiblings --help >/dev/null; then
  echo -e "\e[36m Test failed, help command exited abnormally.\e[0m"
  exit 4
fi
ENDCMD
echo -e "\e[36m Prepared setup script.\e[33m"
echo -en "\e[0m"
sudo bash /root/.ipsiblings_tmp_script.sh || echo "Setup script failed :("
echo -e "\e[36m Done, should be installed in the venv at /root/ipsiblings.\e[0m"
ENDSSH
)
ssh -t "$SSH_HOST" "$MAIN_SSH_COMMAND" || exit 2
