#!/usr/bin/python3 -I
"""Administrator-owned sudo helper for Rivet's read-only host runsc queries.

Install this file root-owned, not writable by the registry account. The runsc
binary and every parent directory must also be root-owned and protected. No
caller-controlled path, runtime root, environment or runtime flag is accepted.
"""
import os
import re
import sys

RUNSC = '/usr/local/bin/runsc'
ROOT = '--root=/var/run/docker/runtime-runc/moby'


def query_args(args):
    if args == ['--version']:
        return [RUNSC, '--version']
    if len(args) != 4 or args[0] != ROOT or not re.fullmatch(r'[a-f0-9]{64}', args[3]):
        raise ValueError('invalid runsc query')
    if args[1:3] not in (['ps', '-format=json'], ['trace', 'list']):
        raise ValueError('unsupported runsc query')
    return [RUNSC, '--allow-flag-override', *args]


def main():
    try:
        args = query_args(sys.argv[1:])
        if os.geteuid() != 0:
            raise ValueError('invoke through the configured sudo rule')
        os.execve(RUNSC, args, {'PATH': '/usr/bin:/bin'})
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
