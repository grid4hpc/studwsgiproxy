#!/usr/bin/env python
# -*- encoding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import os
from distutils.core import Command
from distutils.command.build import build
from distutils.spawn import spawn

class build_stud(Command):
    description = "build bundled STUD"
    user_options = [
        ('force', 'f',
         "forcibly build everything (ignore file timestamps)"),
        ('make-command=', 'm',
         "GNU make executable name"),
        ]

    boolean_options = ['force']

    def initialize_options(self):
        self.make_command = None
        self.force = False

    def finalize_options(self):
        if self.make_command is None:
            self.make_command = "make"
        self.set_undefined_options('build',
                                   ('force', 'force'))

    def run(self):
        cwd = os.getcwd()
        os.chdir("src/stud")
        cmd = [self.make_command]
        for env_var in ("OPENSSL_INC", "OPENSSL_LD", "LIBEV_INC", "LIBEV_LD"):
            if env_var in os.environ:
                cmd.append("%s=%s" % (env_var, os.environ[env_var]))
        if self.force:
            cmd = cmd + ["clean"]
        cmd += ["stud"]
        spawn(cmd, dry_run=self.dry_run)
        os.chdir(cwd)
        self.copy_file("src/stud/stud", "studwsgiproxy/stud")

class Builder(build):
    def run(self):
        self.sub_commands.insert(0, ('build_stud', lambda self: True))
        build.run(self)

setup(name="studwsgiproxy",
      version="0.1",
      description="HTTPS WSGI Server based on stud tls-unwrapping daemon with proxy certificate support",
      long_description="""\
HTTPS WSGI Server based on stud tls-unwrapping daemon with proxy\
certificate support.\
""",
      classifiers=['Development Status :: 3 - Alpha',
                   'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
                   'Operating System :: POSIX :: Linux',
                   'Operating System :: MacOS :: MacOS X',
                   'Programming Language :: Python',
                   'Topic :: Internet',
                   'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
                   'Topic :: Internet :: WWW/HTTP :: WSGI :: Server',                   
                   'Topic :: Security :: Cryptography',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      keywords=['voms', 'proxy', 'certificate', 'x509', 'grid', 'wsgi', 'https', 'tls'],
      author="Lev Shamardin",
      author_email="shamardin@gmail.com",
      url="https://github.com/grid4hpc/studwsgiproxy",
      license="GPLv3+",
      packages=['studwsgiproxy'],
      package_data={'studwsgiproxy':['stud'],},
      install_requires=['gridproxy>=0.2.1', 'werkzeug'],
      cmdclass = {'build': Builder,
                  'build_stud': build_stud,
                  },
      zip_safe=False,
      )
