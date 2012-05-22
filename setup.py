from distutils.core import setup, Extension

libraries = []
library_dirs = []

include_dirs = ['/usr/local/include', 'src/_osxkeychain']

descr = "Python bindings for Mac OS X Keychain access."
long_descr = ""
modules = []
compile_args = []
link_args = ['-framework', 'Security', \
    '-framework', 'Foundation']
macros = []
package_dir={'osxkeychain': 'src/osxkeychain'}
packages=['osxkeychain']

cbinding_srcs = ['src/_osxkeychain/osxkeychain.c']

extens = [
    Extension('_osxkeychain', cbinding_srcs,
        include_dirs=include_dirs, libraries=libraries,
        library_dirs=library_dirs, define_macros=macros,
        extra_compile_args=compile_args, extra_link_args=link_args)
]

install_requires = []
tests_require = []

setup(
    name = "py-osxkeychain",
    version = "0.0.1",
    description = descr,
    author = "Scott Kroll",
    author_email = "skroll@gmail.com",
    url = "",
    download_url = "",
    long_description = long_descr,
    py_modules = modules,
    ext_modules = extens,
    package_dir = package_dir,
    packages = packages
)
