import os
from codecs import open
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'requirements.txt')) as f:
    requirements = f.read().splitlines()

with open(os.path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="iptables-exporter",
    version="0.3.0",
    description='Prometheus iptables exporter',
    long_description=long_description,

    url='https://bitbucket.org/madron/iptables-exporter',
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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],
    keywords='prometheus monitoring iptables bandwidth',

    packages=find_packages(),
    scripts=['iptables-exporter'],
    install_requires=requirements,
)
