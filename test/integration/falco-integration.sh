#!/usr/bin/env bash

python3 -m venv .venv
python3 -m pip install -r requirements.txt
source .venv/bin/activate

pytest test_falco.py  --garden-kubeconfig $1 --project-namespace $2 --shoot-name $3