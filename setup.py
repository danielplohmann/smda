from setuptools import find_packages, setup

with open("README.md") as fh:
    long_description = fh.read()


requirements = ["capstone", "dncil", "dnfile"]

requirements.append("lief>=0.16.0")


setup(
    name="smda",
    # note to self: always change this in config as well.
    version="2.5.2",
    description="A recursive disassmbler optimized for CFG recovery from memory dumps. Based on capstone.",
    long_description_content_type="text/markdown",
    long_description=long_description,
    author="Daniel Plohmann",
    author_email="daniel.plohmann@mailbox.org",
    url="https://github.com/danielplohmann/smda",
    license="BSD 2-Clause",
    packages=find_packages(exclude=("tests", "docs")),
    install_requires=requirements,
    data_files=[
        ("", ["LICENSE"]),
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
