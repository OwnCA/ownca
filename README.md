[![Build Status](https://github.com/OwnCA/ownca/workflows/Tests/badge.svg)](https://github.com/OwnCA/ownca/actions?query=workflow%3ATests)
[![Documentation Status](https://readthedocs.org/projects/ownca/badge/?version=latest)](https://ownca.readthedocs.io/en/latest/?badge=latest)
[![codecov](https://codecov.io/gh/OwnCA/ownca/branch/master/graph/badge.svg)](https://codecov.io/gh/OwnCA/ownca)
[![pypi](https://img.shields.io/pypi/v/ownca.svg)](https://pypi.python.org/pypi/ownca)
[![pypi Downloads](https://img.shields.io/pypi/dm/ownca)](https://pypistats.org/packages/ownca)
[![pypi](https://img.shields.io/pypi/l/ownca.svg)](https://pypi.python.org/pypi/ownca)

Python Own Certificate Authority (ownca)
========================================

OwnCA makes easy handle Certificate Authority (CA) and manage certificates
for hosts, servers or clients.

An example of high level usage:

```pycon
>>> from ownca import CertificateAuthority
>>> ca = CertificateAuthority(ca_storage='/opt/CA', common_name='MyCorp CA')
>>> example_com = ca.issue_certificate('www.example.com', dns_names=['www.example.com', 'w3.example.com')
```

Basically in this three lines steps:
 1. Imported the ownca Certificate Authority library
 2. Created a new CA named as *Corp CA* that uses ```/opt/CA``` as CA storage
    for certificates, keys etc.
 3. Create a signed certificate by *Corp CA* server *www.mycorp.com*,
 the files are also stored in ```/opt/CA/certs/www.example.com```.

    ```pycon
     >>> example_com.cert
     <Certificate(subject=<Name(CN=www.example.com)>, ...)>
    ```

More detailed usage can be found in [http://ownca.readthedocs.org](
http://ownca.readthedocs.org)


Installation
============

```shell
pip install ownca
```

Documentation
=============
Visit [http://ownca.readthedocs.org](http://ownca.readthedocs.org)


Development
===========

Preparing environment
---------------------

```shell
$ git clone git@github.com:OwnCA/ownca.git
$ cd ownca
$ pipenv shell
$ pipenv install -d
```

Case you have macOS M1

```shell
$ pip uninstall cryptography cffi
$ LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi cryptography rust --no-binary :all:
```