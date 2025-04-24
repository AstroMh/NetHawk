#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="NetHawk",
    version="1.0.0",
    description="Network Security Toolkit for ethical hacking and penetration testing",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.4.5",
        "termcolor>=2.3.0",
        "keyboard>=0.13.5",
        "pynput>=1.7.6",
    ],
    extras_require={
        "code_injector": ["netfilterqueue>=0.8.1"],
    },
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
) 