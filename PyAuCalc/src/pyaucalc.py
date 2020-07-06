#!/usr/bin/env python3

import pathlib
import re
import signal
import sys

import audit_sandbox

if sys.version_info[:3] < (3, 8, 2):
    raise RuntimeError('Python version too old')

WELCOME = f'''\
Welcome to PyAuCalc, an awesome calculator based on Python {'.'.join(map(str, sys.version_info[:3]))}!
(Type "source" to see my awesome source code!)
'''
SOURCE = pathlib.Path(__file__).read_text(encoding='utf-8')
SANDBOX = pathlib.Path(audit_sandbox.__file__).read_bytes()

# Calculators don't need hacking functions, ban them!
audit_sandbox.install_hook()
del audit_sandbox
del sys.modules['audit_sandbox']


def main():
    print(WELCOME)

    while True:
        try:
            expression = input('>>> ')
            # Calculators don't need non-ASCII characters.
            expression.encode('ascii')
        except EOFError:
            break
        except Exception:
            print('invalid expression')
            continue

        # No denial-of-service!
        signal.alarm(1)

        # Calculators don't need spaces.
        if not (expression := re.sub(r'\s', '', expression)):
            signal.alarm(0)
            continue

        # Feel free to inspect my super secure source code and sandbox!
        if expression == 'source':
            signal.alarm(0)
            print(SOURCE)
            continue
        if expression == 'sandbox':
            signal.alarm(0)
            print(SANDBOX)
            continue

        try:
            # Calculators don't need builtins!
            result = str(eval(expression, {'__builtins__': {}}))
            signal.alarm(0)
            print(result)
        except Exception:
            signal.alarm(0)
            print('invalid expression')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
