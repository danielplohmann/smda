# -*- coding: utf-8 -*-
import sys
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()


requirements = ["capstone"]

if sys.version_info >= (3, 0):
    # py3
    requirements.append("lief==0.14.0")
else:
    # py2 - newer LIEF is Python3 only
    requirements.append("lief==0.9.0")


setup(
    name='smda',
    # note to self: always change this in config as well.
    version='1.13.18',
    description='A recursive disassmbler optimized for CFG recovery from memory dumps. Based on capstone.',
    long_description_content_type="text/markdown",
    long_description=long_description,
    author='Daniel Plohmann',
    author_email='daniel.plohmann@mailbox.org',
    url='https://github.com/danielplohmann/smda',
    license="BSD 2-Clause",
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires=requirements,
    data_files=[
        ('', ['LICENSE']),
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
    ],
)
