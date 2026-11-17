#!/bin/bash
set -e

#go to the folder this script lives in, so it works from anywhere
cd "$(dirname "$0")"

#switch on the virtual environment
source .venv/bin/activate

#run policylint and save everything it prints to the report.txt
python policylint.py > report.txt

echo "Done! Report saved to report.txt"

