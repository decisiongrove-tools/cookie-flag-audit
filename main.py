"""Inspect Secure and HttpOnly flags in supplied Set-Cookie strings."""
import argparse,csv,io,json,math,re
from collections import Counter
from datetime import date,datetime
from pathlib import Path

import base64,ipaddress,uuid
from urllib.parse import parse_qsl,urlsplit
from http.cookies import SimpleCookie

def analyze(data):
    result=[]
    for header in data['headers']:
        parsed=SimpleCookie();parsed.load(header)
        if not parsed:raise ValueError('Unparseable cookie header')
        for name,morsel in parsed.items():result.append({'name':name,'secure':bool(morsel['secure']),'httponly':bool(morsel['httponly'])})
    return {'cookies':result}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path,help='UTF-8 JSON input file')
    parser.add_argument('--explain',action='store_true',help='Send the local report to the configured chat gateway')
    args=parser.parse_args()
    report=analyze(json.loads(args.input.read_text(encoding='utf-8')))
    if args.explain:
        from gateway_client import explain
        print(explain(report))
    else:print(json.dumps(report,ensure_ascii=False,indent=2))
