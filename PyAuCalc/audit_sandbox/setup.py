from distutils.core import Extension, setup


def main():
    setup(name='audit_sandbox',
          ext_modules=[Extension('audit_sandbox', ['audit_sandbox.c'])],
          )


if __name__ == '__main__':
    main()
