#!/usr/bin/env python3
import rzpipe
import sys
import os
import argparse

def test_root_cmd_desc(rz):
    out = rz.cmd('RE?')

    failed = 0
    required_cmds = ['REa', 'REm', 'REf', 'REb', 'REc', 'REi', 'REh']

    for cmd in required_cmds:
        if cmd not in out or 'ERROR' in rz.cmd(f'{cmd}?'):
            failed += 1
            print(f"[ERROR] NOT FOUND '{cmd}' or ERRORED OUT")
        else:
            print(f"[SUCCESS] FOUND '{cmd}'")

    if failed:
        print(f"[FAIL] {failed} out of {len(required_cmds)} required commands not found!")
        return False
    else:
        print("[PASS] All required commands found")
        return True

def test_plugin_init_cmd(rz):
    """
    Test REi command

    Requires:
        - `E2E_API_KEY` environment variable set
        - `E2E_API_URL` environment variable set
    """

    # get API key from 
    if 'E2E_API_KEY' in os.environ.keys():
        api_key = os.environ['E2E_API_KEY']
    else:
        print('[ERROR] RevEngAI API key not provided in environment. "E2E_API_KEY" is required in environment.')
        return False

    if 'E2E_API_URL' in os.environ.keys():
        api_url = os.environ['E2E_API_URL']
    else:
        print('[ERROR] RevEngAI API url not provided in environment. "E2E_API_URL" is required in environment.')
        return False

    res = True
    res &= rz.cmd('REi') is not None          # Will fail and print log messages
    res &= rz.cmd(f'REi {api_key}') is None   # Will succeed and print nothing

    try:
        with open(os.path.expanduser('~/.creait'), 'r') as config:
            content = config.read()
            if api_key not in content:
                print('[ERROR] API key not found in config file. Plugin not initialized correctly.')
                res = False
            else:
                print('[SUCCESS] API key found in config file.')
                with open(os.path.expanduser('~/.creait'), 'w') as f:
                    f.write(f'api_key={api_key}\nhost={api_url}\n') 
    except File:
        print('[ERROR] Creait config file not found!')

    return res


# Basic argument parser
parser = argparse.ArgumentParser("rizin_test.py")
parser.add_argument("bin", help="Binary to open RzPipe over", type=str)
args = parser.parse_args()

failed = 0

# Run all tests
rz = rzpipe.open(args.bin)
print(f"Using binary '{args.bin}'")

if not test_root_cmd_desc(rz):
    failed += 1

if not test_plugin_init_cmd(rz):
    failed += 1
    
rz.quit()

if failed:
    sys.exit(1)    
else:
    sys.exit(0)
