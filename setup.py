# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import config


with open('README.rst') as f:
    README = f.read()

with open('LICENSE') as f:
    LICENSE = f.read()

setup(
    name='smda',
    version=config.VERSION,
    description='A recursive disassmbler optimized for CFG recovery from memory dumps. Based on capstone.',
    long_description=README,
    author='Daniel Plohmann',
    author_email='daniel.plohmann@mailbox.org',
    url='https://github.com/danielplohmann/smda',
    license=LICENSE,
    packages=find_packages(exclude=('tests', 'docs'))
)
