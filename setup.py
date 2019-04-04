import os
from codecs import open
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'requirements.txt')) as f:
    requirements = f.read().splitlines()

with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="iptables-exporter",
    version="0.3.2",
    description='Prometheus iptables exporter',
    long_description=long_description,

    url='https://github.com/madron/iptables-exporter',
    author='Massimiliano Ravelli',
    author_email='massimiliano.ravelli@gmail.com',

    license='MIT',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Monitoring',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='prometheus monitoring iptables bandwidth',

    packages=find_packages(),
    scripts=['iptables-exporter'],
    install_requires=requirements,
)
