# PyAuCalc

This is a Python "sandbox escape" ("pyjail") challenge in 0CTF/TCTF 2020 Quals. 17 teams solved this challenge during the competition, and the first solution came in 4 hours.

## Motivation

As a Python lover, I created this challenge to draw people's attention to:

- The long-existing bytecode exploit in Python that leads to arbitrary memory read/write.
- New features in Python:
  - The audit hooks feature introduced in Python 3.8 by [PEP 578](https://www.python.org/dev/peps/pep-0578/), which is the main protection in this challenge.
  - The positional only arguments feature in Python 3.8 proposed by [PEP 570](https://www.python.org/dev/peps/pep-0570/), which you can discover when porting the bytecode exploit to Python 3.8, as illustrated below.
  - The walrus operator (assignment expression) feature in Python 3.8 proposed by [PEP 572](https://www.python.org/dev/peps/pep-0572/), which I intentionally used in the source code.
  - `pathlib` and f-strings, which many people in the field of AI still don't know despite the fact that they use Python frequently.

## Solution

### Intended Solution

The challenge installs an audit hook which basically aborts the interpreter when certain dangerous events are detected. Specifically, all command execution functions and most file operations are banned. Generally there are two obvious ways to get low-level access to the current process to pwn the Python interpreter:

- By using the `ctypes` module to manipulate memory
- On Linux, by using the `/proc/self/mem` file
  - An interesting thing is that the memory permission check is bypassed when writing to the `/proc/self/mem` file. You can even directly overwrite the code segment with a `nop` sled followed by some shellcode without having to do `mprotect`. I don't know why it is designed to behave in this way. A look into kernel source code shows that permission check of `/proc/self/mem` is roughly equivalent to `ptrace`, and a process can actually write arbitrary memory of itself if it `ptrace`s itself.

However, neither of these two ways will work for this challenge since the first one produces `import` and `ctypes` events and the second one emits the `open` event. All these events are banned in this challenge.

Nevertheless, there is a third way to get low-level access to bypass the audit hook mechanism: by constructing arbitrary Python bytecode, which is the intended solution for this challenge. [This post](https://doar-e.github.io/blog/2014/04/17/deep-dive-into-pythons-vm-story-of-load_const-bug/) explained how the bytecode exploit works (in 32 bit Python 2.7), and [this post in 2018](https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html) ported the exploit to 64 bit Python 3.6. The exploit could be further adapted to Python 3.8 by adding the `posonlyargcount` argument (which corresponds to the positional only arguments feature) to the [`types.CodeType`](https://docs.python.org/3/library/types.html#types.CodeType) constructor.

After you get arbitrary memory read/write, basically you have infinite ways to pwn Python. My exact intention is that you can overwrite the head of the audit hook linked list to clear the audit hook and then be able to run arbitrary Python code without audit. But of course you can also overwrite the GOT, or overwrite some other pointers to call `system("/bin/sh")` or jump to "one gadget", as done by some teams. The idea of overwriting the linked list head comes from [this presentation](https://github.com/daddycocoaman/SlidePresentations/blob/master/2019/BypassingPython38AuditHooks.pdf). They claim that locating the start of the audit hook linked list "might be hard" but it's actually easy, while their other way requires `ctypes` and changing memory permissions, which does not work for this challenge and generally looks less elegant to me.

For the full exploit, see the [exp](exp/) directory.

### Unintended Solution

Some teams found an unintended solution, which turns out to be a bug in the implementation of audit hooks in CPython. By reviewing the [source code of Python 3.8.3](https://github.com/python/cpython/blob/v3.8.3/Python/pylifecycle.c#L1237), you can see that after calling `_PySys_ClearAuditHooks()`, there are still opportunities to execute arbitrary user-controlled Python code. Thus, the following code snippet will be able to get a shell without audit by utilizing the `__del__` finalizer function:

```python
import os, sys

class A:
    def __del__(self):
        os.system('/bin/sh')

a = A()  # or `sys.modules['a'] = A()` or `sys.ps1 = A()` or other ways
sys.exit(0)  # The object created on the previous line will be garbage-collected and `__del__` will be called after audit hooks got cleared.
```

This bug [has been reported](https://bugs.python.org/issue41162) by one of the teams who got this unintended solution.

## My Thoughts

### General-Purpose CPython Sandbox Is Broken

As mentioned in [PEP 578](https://www.python.org/dev/peps/pep-0578/), there was a long history trying to "sandbox" CPython and all the attempts failed. In CTFs in recent years, most Python "sandbox escape" challenges focus on restricting the character set (e.g. no parentheses allowed) rather than restricting functionalities (e.g. delete `builtins` and `os`), because it is already known that once you get to execute arbitrary bytecode, the game is over. Possibly for performance reasons, CPython does not validate the bytecode being executed, and in fact normal bytecode compiled from Python source code won't go out of boundary. However in order to support importing modules, the ability to execute arbitrary bytecode is needed. Thus, trying to implement a general-purpose sandbox in CPython is almost sure to fail. [The sandbox in PyPy](https://www.pypy.org/features.html#sandboxing) has a different architecture.

### Audit Hooks Are Still Useful

Despite the infeasibility to build a CPython sandbox, the audit hooks feature is still valuable. As emphasized by the PEP author, audit hooks should generally be used for detection (logging) of malicious behaviors rather than prevention of them (i.e. simply aborting the events). The [audit events table](https://docs.python.org/3/library/audit_events.html) points out the attack surfaces of Python and makes security of Python more transparent. You can log suspicious events for further analysis, and abort extremely suspicious events if you wish to (after logging them). In fact, the bytecode code exploit triggers the `code.__new__` audit event, and monkey patching the `__code__` attribute of a function also raises the `object.__setattr__` event (which was not documented before I send [this issue](https://bugs.python.org/issue41192)). Even trying to leak address with the builtin `id` function will cause the `builtins.id` event to be raised. However in this challenge, these events are not blocked.

To some extent, audit hooks could look like `disable_functions` in PHP, but much less studied by CTF people. That's why I create this challenge to draw your attention to this. Just like `seccomp` in Linux and Content Security Policy in Web frontend security, audit hooks operate on the real attack surfaces of the system, which make much more sense to me compared to foolish string-matching-based WAFs that never get to understand the real business logic in a system (sure to produce false positives and false negatives).

### How Do You Build A Calculator

Generally you should write your own parser to implement a calculator, as presented in most algorithms and data structures courses. For "lazy guys" who want to leverage the built-in `eval` function, you should at least:

- Limit the character set to accept. For example, only allow digits and `+-*/`. The more characters you allow (to support more functionalities), the less security your calculator will have (i.e. more likely to construct arbitrary code execution).
- Limit the Python bytecode to be executed. You can checkout the implementation in the [`pwnlib.util.safeeval`](https://docs.pwntools.com/en/stable/util/safeeval.html) module.

In this challenge, if we abort more audit events (including `code.__new__`, `object.__setattr__` and `builtins.id`), without internal bugs in the audit hooks implementation (just like the bug in the unintended solution), the calculator is "probably" secure (I could only say "probably"). But for more complex applications, you cannot simply abort all these events, otherwise your applications even won't run normally.
