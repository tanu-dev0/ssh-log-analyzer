# SSH Log Analyzer - Brute Force Detector

A Python script that reads SSH authentication logs and detects
brute-force login attempts, plus any successful login that
followed one (a possible compromise).

## What it does
- Parses auth.log-style SSH lines with a regex
- Groups failed logins by source IP
- Flags an IP if it fails 4+ times within a 5-minute window
- Flags a 'possible compromise' if that IP later logs in successfully

## How to run
python log_analyzer.py sample_auth.log
python log_analyzer.py sample_auth.log --threshold 4 --window 5

## Tech used
Python 3, standard library only (re, argparse, datetime, collections)
