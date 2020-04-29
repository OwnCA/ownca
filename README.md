[![Build Status](https://github.com/OwnCA/ownca/workflows/Tests/badge.svg)](https://github.com/OwnCA/ownca/actions?query=workflow%3ATests)
[![Documentation Status](https://readthedocs.org/projects/ownca/badge/?version=latest)](https://ownca.readthedocs.io/en/latest/?badge=latest)
[![codecov](https://codecov.io/gh/OwnCA/ownca/branch/master/graph/badge.svg)](https://codecov.io/gh/OwnCA/ownca)
[![pypi](https://img.shields.io/pypi/v/ownca.svg)](https://pypi.python.org/pypi/ownca)
[![pypi](https://img.shields.io/pypi/l/ownca.svg)](https://pypi.python.org/pypi/ownca)

Python Own Certificate Authority (ownca)
========================================

OwnCA makes easy handle Certificate Authority (CA) and manage certificates
for hosts, servers or clients.

An example of high level usage:

```pycon
>>> from ownca import CertificateAuthority
>>> ca = CertificateAuthority(ca_storage='/opt/CA', common_name='MyCorp CA')
>>> mycorp = ca.issue_certificate('www.mycorp.com', dns_names=['www.mycorp.com', 'w3.mycorp.com')

```

Basically in this three lines steps:
 1. Imported the ownca Certificate Authority library
 2. Created a new CA named as *Corp CA* that uses ```/opt/CA``` as CA storage
    for certificates, keys etc.
 3. Create a signed certificates by *Corp CA* server *www.mycorp.com*, 
 the files are also stored in ```/opt/CA/certs/mycorp.com```.

More detailed usage can be found in [http://ownca.readthedocs.org](
http://ownca.readthedocs.org)


Installation
============

```shell
pip install ownca
```
