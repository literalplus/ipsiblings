#!/usr/bin/env bash

if [ "$1" == "--help" ]; then
  echo "$0"
  echo "  Builds the wheel and installs it locally."
  exit 1
fi

if [ -z "$VIRTUAL_ENV" ]; then
  echo -e "\e[36m No venv detected locally. Should we set one up in $(pwd)?\e[0m"
  read -p "Enter to continue, Ctrl-C to abort: " -n 1 -r
  python3 -m venv . || exit 2
  source ./bin/activate || exit 2
  echo -e "\e[36m Looking good.\e[0m"
fi

echo -e "\e[36m Building wheel.\e[0m"
rm -rf ./dist
python3 -m pip install --upgrade setuptools wheel || exit 2
python3 setup.py sdist bdist_wheel || exit 2
echo -e "\e[36m Wheel files:\e[0m"
ls -hl ./dist

LATEST_WHEEL="$(find ./dist -name '*.whl' | head -n1)"
echo -e "\e[36m Latest wheel is '$LATEST_WHEEL'\e[0m"
if [ -z "$LATEST_WHEEL" ]; then
  echo "No matching wheel found..?"
  exit 1
fi

pip3 install --upgrade "$LATEST_WHEEL" || exit 2

echo -e "\e[36m Should now be available as 'ipsiblings'.\e[0m"
