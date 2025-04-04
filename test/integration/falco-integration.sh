#!/usr/bin/env bash

if [ $# -ne 3 ]; then
  echo "usage: falco-integration.sh <garden kubeconfig> <project namespace> <shoot name>"
  exit 1
fi

dir=$(dirname $0)
cd $dir

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

pytest test_falco.py --garden-kubeconfig $1 --project-namespace $2 --shoot-name $3
