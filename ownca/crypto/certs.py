#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 Kairo de Araujo
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
import uuid

one_day = datetime.timedelta(1, 0, 0)


def _valid_cert(certificate):
    """
    Validate if the Certificate object is correct.
    https://cryptography.io/en/latest/x509/reference/

    :param certificate: certificate object ``cryptography.x509.Certificate``
    :type certificate: object, required.

    :return: certificate object when valid
    :rtype: ``cryptography.x509.Certificate`` or None
    """
    if isinstance(certificate, x509.Certificate):
        return certificate

    else:
        return None


def _valid_csr(csr):
    """
    Validate if the Certificate Signing Request.
    https://cryptography.io/en/latest/x509/reference/

    :param csr: Certificate Signing Request object
        ``cryptography.x509.CertificateSigningRequest``
    :type cs: object, required.

    :return: certificate object when valid
    :rtype: ``cryptography.x509.Certificate`` or None
    """
    if isinstance(csr, x509.CertificateSigningRequest):
        return csr

    else:
        return None


def _add_dns_as_subjectaltname(builder, c_name, dns_names):
    """
    Add DNS Name (``cryptography.x509.DNSName``) and Subject Alternative
    Name (``cryptography.x509.SubjectAlternativeName``) to the certificate
    object.

    :param builder: the initiated builder ``x509.CertificateBuilder()``.
    :type builder: object, required.
    :param c_name: common name.
    :type c_name: str, required.

    :return: builder object ``x509.CertificateBuilder()``
    """

    if dns_names is not None:

        if type(dns_names) is not list:
            raise TypeError("dns_names require a list of strings.")

        if len(dns_names) != 0:
            if all(isinstance(item, str) for item in dns_names):
                x509_dns_names = []
                for dns_name in dns_names:
                    x509_dns_names.append(x509.DNSName(dns_name))

                builder = builder.add_extension(
                    x509.SubjectAlternativeName(x509_dns_names),
                    critical=False,
                )

            else:
                raise TypeError("All DNS Names must to be string values.")

    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(c_name)]),
            critical=False,
        )

    return builder


def _add_subjectaltnames_sign_csr(builder, csr):
    """
    Adds to the certificate (during singing CSR) the SubjectAltNames.

    :param builder: certificate builder
    :type builder: ``cryptography.x509.CertificateBuilder()``, required
    :param csr: CSR object
    :type csr: ``cryptography.x509.CertificateSigningRequest``, required
    :return: builder object
    :rtype: ``cryptography.x509.CertificateBuilder()``
    """
    for extension in csr.extensions:
        if extension.value.oid._name != "subjectAltName":
            continue

        builder = builder.add_extension(
            extension.value, critical=extension.critical
        )

    return builder


def issue_cert(
    oids,
    maximum_days=None,
    key=None,
    pem_public_key=None,
    ca_common_name=None,
    common_name=None,
    dns_names=None,
    host=False,
    ca=True,
):
    """
    Issue a new certificate

    :param oids: list of OID Objects (``cryptography.x509.oid.NameOID``)
        or None. See ``ownca.format_oids``.
    :type oids: list, required.
    :param maximum_days: number of maximum days of certificate (expiration)
    :type maximum_days: int, required, min 1 max 825.
    :param key: key object ``cryptography.hazmat.backends.openssl.rsa``
    :type key: object, required.
    :param pem_public_key: PEM public key object
        ``cryptography.hazmat.backends.openssl.rsa.public_key()``.
    :type pem_public_key: object, required.
    :param ca_common_name: Certificate Authority Common Name when issuing cert.
    :type ca_common_name: string, optional.
    :param common_name: Common Name when issuing Certificate Authority cert.
    :type common_name: string, optional.
    :param dns_names: list of DNS names to the cert.
    :type dns_names: list of strings.
    :param host: Issuing a host certificate.
    :type host: bool, default True.
    :param ca: Certificate is CA or not.
    :type ca: bool, default True.

    :return: certificate object
    :rtype: ``cryptography.x509.Certificate``
    """

    if maximum_days is None or 0 < maximum_days > 826:
        raise ValueError("maximum_days is required: Minimum 1, Maximum 825")

    oids.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(x509.Name(oids))

    if host:
        builder = builder.issuer_name(
            x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name)]
            )
        )

        builder = _add_dns_as_subjectaltname(
            builder, ca_common_name, dns_names
        )

    else:

        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )

        builder = _add_dns_as_subjectaltname(builder, common_name, dns_names)

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (one_day * maximum_days)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pem_public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca, path_length=None), critical=True
    )

    certificate = builder.sign(
        private_key=key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    return _valid_cert(certificate)


def issue_csr(key=None, common_name=None, dns_names=None, oids=None):
    """
    Issue a new CSR (Certificate Signing Request)

    :param key: key object ``cryptography.hazmat.backends.openssl.rsa``
    :type key: object, required.
    :param common_name: Common Name when issuing Certificate Authority cert.
    :type common_name: string, optional.
    :param dns_names: list of DNS names to the cert.
    :type dns_names: list of strings.
    :param oids: list of OID Objects (``cryptography.x509.oid.NameOID``)
        or None. See ``ownca.format_oids``.
    :type oids: list, required.

    :return: certificate sigining request object
    :rtype: ``cryptography.x509.CertificateSigningRequest``
    :raises: ``TypeError``
    """
    csr_builder = x509.CertificateSigningRequestBuilder()

    oids.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    csr_builder = csr_builder.subject_name(x509.Name(oids))

    csr_builder = _add_dns_as_subjectaltname(
        csr_builder, common_name, dns_names
    )

    csr_builder = csr_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=False
    )
    csr = csr_builder.sign(
        private_key=key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    return _valid_csr(csr)


def ca_sign_csr(ca_cert, ca_key, csr, public_key, maximum_days=None):
    """
    Sign a Certificate Signing Request

    :param ca_cert: CA certificate object ``cryptography.x509.Certificate``
    :type ca_cert: object, required.
    :param ca_key: CA key object ``cryptography.hazmat.backends.openssl.rsa``
    :type ca_key: object, required.
    :param csr: CSR object ``cryptography.x509.CertificateSigningRequest``
    :type csr: object, required.
    :param key: key object ``cryptography.hazmat.backends.openssl.rsa``
    :param maximum_days: number of maximum days of certificate (expiration)
    :type maximum_days: int, required, min 1 max 825.

    :return: certificate object
    :rtype: ``cryptography.x509.Certificate``
    :raises: ``ValueError``
    """
    if maximum_days is None or 0 < maximum_days > 826:
        raise ValueError("Value is required: Minimum 1, Maximum 825")

    certificate = x509.CertificateBuilder()
    certificate = certificate.subject_name(csr.subject)
    certificate = _add_subjectaltnames_sign_csr(certificate, csr)
    certificate = certificate.issuer_name(ca_cert.subject)
    certificate = certificate.public_key(csr.public_key())
    certificate = certificate.serial_number(uuid.uuid4().int)
    certificate = certificate.not_valid_before(
        datetime.datetime.today() - one_day
    )
    certificate = certificate.not_valid_after(
        datetime.datetime.today() + (one_day * maximum_days)
    )
    certificate = certificate.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=True,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False,
        ),
        critical=True,
    )
    certificate = certificate.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    certificate = certificate.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            public_key
        ),
        critical=False,
    )
    certificate = certificate.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    return _valid_cert(certificate)


def ca_crl(
    ca_cert,
    ca_key=None,
    common_name=None,
    certificates_revoke=None
):
    """
    Generates the CA Certificate Revocation List (CRL)

    :param ca_cert: CA certificate object ``cryptography.x509.Certificate``
    :type ca_cert: object, required.
    :param ca_key: CA key object ``cryptography.hazmat.backends.openssl.rsa``
    :type ca_key: object, required.
    :param common_name: Common Name when issuing Certificate Authority cert.
    :type common_name: string, required.
    :param certificates_revoke: List of certificates to be revoked, if none \
    an empty list is returned
    :type certificates_revoke: list of \
    ``cryptography.hazmat.backends.openssl.x509._RevokedCertificate``,
    optional.

    :return: Certificate Revocation List object
    :rtype:
    ``cryptography.hazmat.backends.openssl.x509._CertificateRevocationList``
    """
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + one_day)

    if certificates_revoke:
        for certificate in certificates_revoke:
            builder = builder.add_revoked_certificate(certificate)

    crl = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return crl
