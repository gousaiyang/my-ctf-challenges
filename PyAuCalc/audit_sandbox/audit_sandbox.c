#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Python.h>

static const char *deny_list[] = {"breakpoint", "ctypes", "fcntl", "ftplib", "glob", "imaplib",
                                  "import", "mmap", "msvcrt", "nntplib", "open", "os", "pdb",
                                  "poplib", "pty", "resource", "shutil", "smtplib", "socket",
                                  "sqlite3", "subprocess", "syslog", "telnetlib", "tempfile",
                                  "urllib", "webbrowser", "winreg"};
static const unsigned int deny_list_len = sizeof(deny_list) / sizeof(char *);

static int hook_func(const char *event, PyObject *args, void *userData)
{
    char *ev, *str, *part, *saveptr;
    unsigned int i;
    // fprintf(stderr, "native audit log: event = %s\n", event);

    if (!(ev = strdup(event))) {
        fputs("Insufficient memory.\n", stderr);
        exit(EXIT_FAILURE);
    }

    for (str = ev; ; str = NULL) {
        part = strtok_r(str, ".", &saveptr);
        if (!part)
            break;
        for (i = 0; i < deny_list_len; ++i) {
            if (!strcmp(part, deny_list[i])) {
                puts("Hacking attempt!");
                free(ev);
                exit(EXIT_FAILURE);
            }
        }
    }

    free(ev);
    return 0;
}

static PyObject *install_hook(PyObject *self, PyObject *args)
{
    if (PySys_AddAuditHook(hook_func, NULL) < 0) {
        fputs("Failed to install audit hook.\n", stderr);
        exit(EXIT_FAILURE);
    }
    Py_RETURN_NONE;
}

static PyMethodDef export_functions[] = {
    {"install_hook", install_hook, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef audit_sandbox_module = {
    PyModuleDef_HEAD_INIT,
    "audit_sandbox",
    NULL,
    -1,
    export_functions
};

PyMODINIT_FUNC PyInit_audit_sandbox(void) {
    return PyModule_Create(&audit_sandbox_module);
}
