.. ownca documentation master file, created by
   sphinx-quickstart on Wed Nov 20 13:19:22 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Python Own Certificate Authority (ownca)
========================================

ownca make easy to handle a Certificate Authority (CA) and manage certificates
for hosts or clients. A high level usage:

.. code-block:: python

   >>> from ownca import CertificateAuthority
   >>> ca = CertificateAuthority(ca_storage='/opt/CA', common_name='Corp CA')
   >>> mycorp = ca.issue_certificate('mycorp', dns_names=['mycorp.com', 'tls.mycorp.com')


Basically in this three steps we did:

   1. Imported the ownca Certificate Authority

   2. Created a new CA name of *Corp CA* that uses ```/opt/CA``` as storage for CA
   certificates, keys and files.

   3. We created signed certificates by *Corp CA* for server *mycorp*, the server
   files are also stored in ```/opt/CA/certs/mycorp```.

The motivation
==============

The ownca was created in 2017 as a group of scripts to manage certificates, in
2018 it was moved to a very simple library (mostly hardcoded actions) and now
in 2019 was decide to open and be a library that could help others.

Basically, ownca uses the powerful library
[http://cryptography.io](http://cryptography.io) .


.. toctree::
    :maxdepth: 2
    :caption: The implementation layer

    ownca


.. toctree::
   :maxdepth: 2
   :caption: Contents:



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
