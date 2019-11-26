[![Build Status](https://travis-ci.org/kairoaraujo/ownca.svg?branch=master)](https://travis-ci.org/kairoaraujo/ownca)
[![Documentation Status](https://readthedocs.org/projects/ownca/badge/?version=latest)](https://ownca.readthedocs.io/en/latest/?badge=latest)
[![codecov](https://codecov.io/gh/kairoaraujo/ownca/branch/master/graph/badge.svg)](https://codecov.io/gh/kairoaraujo/ownca)
[![pypi](https://img.shields.io/pypi/v/ownca.svg)](https://pypi.python.org/pypi/ownca)
[![pypi](https://img.shields.io/pypi/l/ownca.svg)](https://pypi.python.org/pypi/ownca)

Python Own Certificate Authority (ownca)
========================================

ownca make easy to handle a Certificate Authority (CA) and manage certificates
for hosts or clients.

A high level usage is

```pycon
>>> from ownca import CertificateAuthority
>>> ca = CertificateAuthority(ca_storage='/opt/CA', common_name='Corp CA')
>>> mycorp = ca.issue_certificate('mycorp', dns_names=['mycorp.com', 'tls.mycorp.com')

```

Basically in this three steps we did:
 1. Imported the ownca Certificate Authority
 2. Created a new CA name of *Corp CA* that uses ```/opt/CA``` as storage for CA
  certificates, keys and files.
 3. We created signed certificates by *Corp CA* for server *mycorp*, the server
 files are also stored in ```/opt/CA/certs/mycorp```.

More detailed usage can be found in [http://ownca.readthedocs.org](http://ownca.readthedocs.org)


Installation
============

```shell
pip install ownca
```
