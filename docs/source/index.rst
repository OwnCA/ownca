.. ownca documentation master file, created by
   sphinx-quickstart on Wed Nov 20 13:19:22 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. toctree::
   :maxdepth: 2

Python Own Certificate Authority (ownca)
========================================

.. image:: https://github.com/OwnCA/ownca/workflows/Tests/badge.svg
   :target: https://github.com/OwnCA/ownca/actions?query=workflow%3ATests
   :alt: Build Status

.. image:: https://readthedocs.org/projects/ownca/badge/?version=latest
   :target: https://ownca.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://codecov.io/gh/OwnCA/ownca/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/OwnCA/ownca
   :alt: Coverage

.. image:: https://img.shields.io/pypi/v/ownca.svg
   :target: https://pypi.python.org/pypi/ownca
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/dm/ownca
   :target: https://pypistats.org/packages/ownca
   :alt: PyPI Downloads

.. image:: https://img.shields.io/pypi/l/ownca.svg
   :target: https://pypi.python.org/pypi/ownca
   :alt: License



OwnCA makes easy handle Certificate Authority (CA) and manage certificates
for hosts, servers or clients.

An example of high level usage:

.. code-block:: python

   >>> from ownca import CertificateAuthority
   >>> ca = CertificateAuthority(ca_storage='/opt/CA', common_name='MyCorp CA')
   >>> example_com = ca.issue_certificate('www.example.com', dns_names=['www.example.com', 'w3.example.com')

Basically in this three lines steps:

1. Imported the ownca Certificate Authority library
2. Created a new CA named as *Corp CA* that uses ``/opt/CA`` as CA storage for certificates, keys etc.
3. Create a signed certificates by *Corp CA* server *www.mycorp.com*, the files are also stored in ``/opt/CA/certs//www.example.com``.

   .. code-block:: python

      >>> example_com.cert
      <Certificate(subject=<Name(CN=www.example.com)>, ...)>


Usage
=====

Creating a Certificate Authority
--------------------------------

The creation of a Certificate Authority (CA) is done by ``class``
`CertificateAuthority <ownca.html#ownca.ownca.CertificateAuthority>`_.

Code example:

.. code-block:: python

   >>> from ownca import CertificateAuthority
   >>> ca_corp = CertificateAuthority(ca_storage='/opt/corp_CA', common_name='Corp CA')


It will create the CA files in in ``/opt/CA``.

Creating an Intermediate Certificate Authority
..............................................

If a Certificate Authority (CA) needs to be Intermediate, it means the certificate needs to
be signed by another CA, you can create that using the option ``intermendiate=True``.

This action will generate only the Certificate Signing Request (CSR). Given the csr to
the Root CA to be signed and having the certificate file, it needs to be added to the
``ca_storage`` folder  as ``ca.crt`` and after that can be used.

Code example:

.. code-block:: python

   >>> from ownca import CertificateAuthority
   >>> ica_corp = CertificateAuthority(ca_storage='/opt/corp_CA', common_name='Corp CA', intermediate=True)
   >>> ica_corp.csr_bytes
   b'-----BEGIN CERTIFICATE REQUEST-----\nMIICijCCAXICAQAwEjEQMA4GA1UEAwwHQ29ycCBDQTCCASIwDQYJKoZIhvcNAQEB\n
   BQADggEPADCCAQoCggEBANErvwkteBXe0PybgWT7Su3Bduig/73Y75kEOzz+Ph4G\nz3a4GEG6Gowgb5TXBpPMp6JVqo7uiSqpOV9f8SJW21CWCGu518Sit5BRFJ4wFf3P\nzEtffb1i7fMr9H2JqjXVyQnVdrIAicWLJo3uF1P5RI5fm8tk5Cq1jRk/2CdfU3nP\n6UANjoE9FAVT1tA2F84TVuGlKBXvsF8OJcCU+HoQhy9suMiTJikaK5Qeti+JBvrZ\nfbijLk8L4u1cUYVVCAzFH+xtwg3TGeH02OmlybJKkm63cre4ixdSNm6AS+o456Mb\nIKn8ksja7orH9lYyocxaitUax0b3iHNPsRFF/M0Q8XsCAwEAAaAzMDEGCSqGSIb3\nDQEJDjEkMCIwEgYDVR0RBAswCYIHQ29ycCBDQTAMBgNVHRMEBTADAQH/MA0GCSqG\nSIb3DQEBCwUAA4IBAQAu9OYSeZMrJZFXrBLqdv60STmyRx+s2/7cq9khOMdayItu\n/kUAw0EIEoB3+uCRm4tvRrZeK2rgDKp4InyJ3cCPMcU02H84OOHen1V3H9WWUEBP\nuxkecQiFpGLzj/gisFjqGOuV/PzeuB/VhfiCJm7tG0PVK9n/JzZ1WBVL9u3GxDHY\n37328J7GniD4XDidevMY/3Gq+lZI9X/OHMSIMh2Q12FG/Ol8mBVdksp4gDbNs98D\nctzfHrmGBTF/f94JX/p94xerjp3NvcAIkzrm9Tfa05BDfpq8RsGgvPAZo4S8Hphz\nKHokUqabqsIC76VBMDFTb6GU3Vv80nBYTN+LrXmr\n-----END CERTIFICATE REQUEST-----\n'

.. note::

   Note that this Intermediate CA is not ready to be used, certificate file is missing.

.. code-block:: python

   >>> ica_corp.issue_certificate('qa.dev.ownca.org')
   Traceback (most recent call last):
   ...
   ownca.exceptions.OwnCAIntermediate: Intermediate Certificate Authority has not a signed certificate file in CA Storage

Is necessary get the certificate signed from the CA to have this Intermediate CA ready.
Add the certificate to ``ca_storage`` folder  as ``ca.crt``.

Available methods
.................

The Certificate Authority has built in methods such as

- `common_name <ownca.html#ownca.ownca.CertificateAuthority.common_name>`_
- `cert <ownca.html#ownca.ownca.CertificateAuthority.cert>`_
- `cert_bytes <ownca.html#ownca.ownca.CertificateAuthority.cert_bytes>`_
- `certificates <ownca.html#ownca.ownca.CertificateAuthority.certificates>`_
- `csr <ownca.html#ownca.ownca.CertificateAuthority.csr>`_
- `csr_bytes <ownca.html#ownca.ownca.CertificateAuthority.csr_bytes>`_
- `key <ownca.html#ownca.ownca.CertificateAuthority.key>`_
- `key_bytes <ownca.html#ownca.ownca.CertificateAuthority.key_bytes>`_
- `public_key <ownca.html#ownca.ownca.CertificateAuthority.public_key>`_
- `public_key_bytes <ownca.html#ownca.ownca.CertificateAuthority.public_key_bytes>`_
- `hash_name <ownca.html#ownca.ownca.CertificateAuthority.hash_name>`_
- `issue_certificate <ownca.html#ownca.ownca.CertificateAuthority.issue_certificate>`_
- `revoke_certificate <ownca.html#ownca.ownca.CertificateAuthority.revoke_certificate>`_
- `status <ownca.html#ownca.ownca.CertificateAuthority.status>`_
- `sign_csr <ownca.html#ownca.ownca.CertificateAuthority.sign_csr>`_

See `CertificateAuthority <ownca.html#ownca.ownca.CertificateAuthority>`_ for
more details.

Code Example:

.. code-block:: python

   >>> ca_corp.cert
   <Certificate(subject=<Name(CN=Corp CA)>, ...)>
   >>> ca_corp.cert_bytes
   b'-----BEGIN CERTIFICATE-----\nMIIC2TCCAcGgAwIBAgIUXn4msF6ONA8lWcehVqd1xxdRvYkwDQYJKoZIhvcNAQEL\nBQAwEjEQMA4GA1UEAwwHQ29ycCBDQTAeFw0yMDA0MjcxODA0MjBaFw0yMjA4MDEx\nODA0MjBaMBIxEDAOBgNVBAMMB0NvcnAgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQC8JqeBHwVnmJkeOKLwqMcil/nY4QBLDsAg4LKhhzFAB/SvJ16F\norqip2jLuRhpxrPNUYa9p8+ZPZziAL7ir68csnJI+UlLU7XV3+TghiaHVsd4lVz7\nHBRhMLQcFQvnEyC5sfm84fptetlL4HN8jJUda/M26kxlHidJRCL221R9g+/RI113\n73tBX7iZSAcBTv/sOndEjVquYipOQXIZwRJ4ZXZ29K4UdoW+9iMCvhtVPCHz4FEl\nPBFn2vuqRg13EcZ6X3/83VJaO5TSh7Qzl87MVmfBtGBWvib5gXxPEY1zOnhojfxc\nEPkffyHauwyORFkpaE00LkrkNjxNEQ5qhCKHAgMBAAGjJzAlMBIGA1UdEQQLMAmC\nB0NvcnAgQ0EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZyMd\n5eu76geBT8yobTyovhPUq63+9BWvmUViNhukZSFX1zKI/8NG1QrAEwG1Rai2yTU/\n07s5XBRwGIcRuFC1tcT7oqAjHYDQw+3RgYYd+isPUo3Mi7SSWQYpJWmk7ICmqYzy\nlS5uk4iZatPWFVwL4XcH9ssgTVTK3kIdG9LKPPz/4KwlBQISxYi5u9pSwCum+gIS\nx2+Vc7jJGCUEP1iMLPuxpOHIns9FusfzPfRfApFQRqZfxBO2Hpewoj1pbb6HckAJ\nVlOyV5KcAunC9UsUtliwN3eFef+U/tNakYtcZjzqn1R5hlLBfaENCwdG4pdvuFw7\na/a5r9CF+SDw0tldZw==\n-----END CERTIFICATE-----\n'


Loading a existent Certificate Authority
----------------------------------------

In the same way if the ``/opt/CA`` exists and the file is there, it will load
and it does not overwrite the files.

Code example:

.. code-block:: python

   >>> from ownca import CertificateAuthority
   >>> ca_corp = CertificateAuthority(ca_storage='/opt/corp_CA', common_name='Corp CA')
   >>> ca_corp.cert
   <Certificate(subject=<Name(CN=Corp CA)>, ...)>
   >>> ca_corp.key_bytes
   b'-----BEGIN CERTIFICATE-----\nMIIC2TCCAcGgAwIBAgIUXn4msF6ONA8lWcehVqd1xxdRvYkwDQYJKoZIhvcNAQEL\nBQAwEjEQMA4GA1UEAwwHQ29ycCBDQTAeFw0yMDA0MjcxODA0MjBaFw0yMjA4MDEx\nODA0MjBaMBIxEDAOBgNVBAMMB0NvcnAgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQC8JqeBHwVnmJkeOKLwqMcil/nY4QBLDsAg4LKhhzFAB/SvJ16F\norqip2jLuRhpxrPNUYa9p8+ZPZziAL7ir68csnJI+UlLU7XV3+TghiaHVsd4lVz7\nHBRhMLQcFQvnEyC5sfm84fptetlL4HN8jJUda/M26kxlHidJRCL221R9g+/RI113\n73tBX7iZSAcBTv/sOndEjVquYipOQXIZwRJ4ZXZ29K4UdoW+9iMCvhtVPCHz4FEl\nPBFn2vuqRg13EcZ6X3/83VJaO5TSh7Qzl87MVmfBtGBWvib5gXxPEY1zOnhojfxc\nEPkffyHauwyORFkpaE00LkrkNjxNEQ5qhCKHAgMBAAGjJzAlMBIGA1UdEQQLMAmC\nB0NvcnAgQ0EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZyMd\n5eu76geBT8yobTyovhPUq63+9BWvmUViNhukZSFX1zKI/8NG1QrAEwG1Rai2yTU/\n07s5XBRwGIcRuFC1tcT7oqAjHYDQw+3RgYYd+isPUo3Mi7SSWQYpJWmk7ICmqYzy\nlS5uk4iZatPWFVwL4XcH9ssgTVTK3kIdG9LKPPz/4KwlBQISxYi5u9pSwCum+gIS\nx2+Vc7jJGCUEP1iMLPuxpOHIns9FusfzPfRfApFQRqZfxBO2Hpewoj1pbb6HckAJ\nVlOyV5KcAunC9UsUtliwN3eFef+U/tNakYtcZjzqn1R5hlLBfaENCwdG4pdvuFw7\na/a5r9CF+SDw0tldZw==\n-----END CERTIFICATE-----\n'
   >>>
   >>> load_ca = CertificateAuthority(ca_storage='/opt/corp_CA', common_name='Corp CA')
   >>> load_ca.cert
   <Certificate(subject=<Name(CN=Corp CA)>, ...)>
   >>> load_ca.key_bytes
   b'-----BEGIN CERTIFICATE-----\nMIIC2TCCAcGgAwIBAgIUXn4msF6ONA8lWcehVqd1xxdRvYkwDQYJKoZIhvcNAQEL\nBQAwEjEQMA4GA1UEAwwHQ29ycCBDQTAeFw0yMDA0MjcxODA0MjBaFw0yMjA4MDEx\nODA0MjBaMBIxEDAOBgNVBAMMB0NvcnAgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQC8JqeBHwVnmJkeOKLwqMcil/nY4QBLDsAg4LKhhzFAB/SvJ16F\norqip2jLuRhpxrPNUYa9p8+ZPZziAL7ir68csnJI+UlLU7XV3+TghiaHVsd4lVz7\nHBRhMLQcFQvnEyC5sfm84fptetlL4HN8jJUda/M26kxlHidJRCL221R9g+/RI113\n73tBX7iZSAcBTv/sOndEjVquYipOQXIZwRJ4ZXZ29K4UdoW+9iMCvhtVPCHz4FEl\nPBFn2vuqRg13EcZ6X3/83VJaO5TSh7Qzl87MVmfBtGBWvib5gXxPEY1zOnhojfxc\nEPkffyHauwyORFkpaE00LkrkNjxNEQ5qhCKHAgMBAAGjJzAlMBIGA1UdEQQLMAmC\nB0NvcnAgQ0EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZyMd\n5eu76geBT8yobTyovhPUq63+9BWvmUViNhukZSFX1zKI/8NG1QrAEwG1Rai2yTU/\n07s5XBRwGIcRuFC1tcT7oqAjHYDQw+3RgYYd+isPUo3Mi7SSWQYpJWmk7ICmqYzy\nlS5uk4iZatPWFVwL4XcH9ssgTVTK3kIdG9LKPPz/4KwlBQISxYi5u9pSwCum+gIS\nx2+Vc7jJGCUEP1iMLPuxpOHIns9FusfzPfRfApFQRqZfxBO2Hpewoj1pbb6HckAJ\nVlOyV5KcAunC9UsUtliwN3eFef+U/tNakYtcZjzqn1R5hlLBfaENCwdG4pdvuFw7\na/a5r9CF+SDw0tldZw==\n-----END CERTIFICATE-----\n'


Multiple Certificate Authorities
--------------------------------

Just use different ``ca_storage`` and you can have/manage multiple CAs

Code example:

.. code-block:: python

   >>> from ownca import CertificateAuthority
   >>> ca_corp = CertificateAuthority(ca_storage='/opt/corp_CA', common_name='Corp CA')
   >>> ca_edu = CertificateAuthority(ca_storage='/opt/edu_CA', common_name='Edu CA')
   >>> ca_edu.cert
   <Certificate(subject=<Name(CN=Edu CA)>, ...)>
   >>> ca_corp.cert
   <Certificate(subject=<Name(CN=Corp CA)>, ...)>



Issuing certificate
-------------------

To issue a new certificate, you need use an existent instance of
``class`` `CertificateAuthority <ownca.html#ownca.ownca.CertificateAuthority>`_ and
use the ``function``
`issue_certificate() <ownca.html#ownca.ownca.CertificateAuthority.issue_certificate>`_.

Code example:

.. code-block:: python

   >>> from ownca import CertificateAuthority
   >>> ca_corp = CertificateAuthority(ca_storage='/opt/corp_CA', common_name='Corp CA')
   >>> example_com = ca_corp.issue_certificate("www.example.com", dns_names=["www.example.com", "w3.example.com"], oids={"country_name": "BR", "locality_name": "Uba"})


Available methods
.................

The Certificate Authority has built in methods such as

- `common_name <ownca.html#ownca.ownca.HostCertificate.common_name>`_
- `cert <ownca.html#ownca.ownca.HostCertificate.cert>`_
- `cert_bytes <ownca.html#ownca.ownca.HostCertificate.cert_bytes>`_
- `csr <ownca.html#ownca.ownca.HostCertificate.csr>`_
- `csr_bytes <ownca.html#ownca.ownca.HostCertificate.csr_bytes>`_
- `key <ownca.html#ownca.ownca.HostCertificate.key>`_
- `key_bytes <ownca.html#ownca.ownca.HostCertificate.key_bytes>`_
- `public_key <ownca.html#ownca.ownca.HostCertificate.public_key>`_
- `public_key_bytes <ownca.html#ownca.ownca.HostCertificate.public_key_bytes>`_
- `revoked <ownca.html#ownca.ownca.HostCertificate.revoked>`_

See `HostCertificate <ownca.html#ownca.ownca.HostCertificate>`_ for
more details.

Checking the certificate

.. code-block:: python

   >>> example_com.cert
   <Certificate(subject=<Name(C=BR,L=Uba,CN=www.example.com)>, ...)>


Loading host/client certificate
-------------------------------

Same as the CA, if you use an existent certificate, it will be loaded and not
overwrited.

Example:

.. code-block:: python

   >>> load_cert = ca_corp.load_certificate("www.example.com")
   >>> load_cert.cert == example_com.cert
   True

The motivation
==============

The ownca was created in 2017 as a group of scripts to manage certificates, in
2018 it was moved to a very simple library (mostly hardcoded actions) and now
2019 was decide to open and be a library that could help others.

Basically, OwnCA uses the powerful library http://cryptography.io .


.. toctree::
    :maxdepth: 4
    :caption: The implementation layer

    ownca
    ownca.crypto


.. toctree::
   :maxdepth: 4
   :caption: Contents:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
