#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020,2022 Kairo de Araujo
#

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from ownca import CertificateAuthority
from ownca.exceptions import OwnCAIntermediate
from ownca.utils import CAStatus
from tests.integrations.conftest import (CA_COMMON_NAME, CA_DNS_NAMES,
                                         CA_MAXIMUM_DAYS, CA_OIDS, CA_STORAGE,
                                         ICA_STORAGE, clean_test)


def test_ca():
    """Int Test: if CA is initialize as expected."""
    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        maximum_days=CA_MAXIMUM_DAYS,
    )

    assert ca.status == CAStatus(
        ca_type_intermediate=False,
        ca_home="CA_test",
        certificate=True,
        crl=True,
        csr=False,
        key=True,
        public_key=True,
    )

    assert isinstance(ca.cert, x509.Certificate)
    assert isinstance(ca.key, rsa.RSAPrivateKeyWithSerialization)
    assert type(ca.public_key_bytes) == bytes
    assert ca.public_key_bytes.startswith(b"ssh-rsa")
    assert ca.common_name == CA_COMMON_NAME
    assert len(ca.hash_name) == 8


def test_ca_load():
    """Int Test: loading the existent CA from CA Storage is consistent"""

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        dns_names=CA_DNS_NAMES,
    )

    ca_loaded = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        dns_names=CA_DNS_NAMES,
    )

    assert ca.status == ca_loaded.status
    assert ca.cert_bytes == ca_loaded.cert_bytes
    assert ca.key_bytes == ca.key_bytes
    assert ca.common_name == ca_loaded.common_name
    assert ca.public_key_bytes == ca_loaded.public_key_bytes
    assert ca.hash_name == ca_loaded.hash_name

    clean_test()


def test_ca_issue_cert():
    """Int Test: CA issuing a certificate"""

    cert_oids = {
        "country_name": "BR",
        "locality_name": "Juiz de Fora",
        "state_or_province": "Minas Gerais",
        "street_address": "Rua Constantino Paleta",
        "organization_name": "This place",
        "organization_unit_name": "It was hard and fun",
        "email_address": "kairo at ...",
    }

    cert_common_name = "home.ownca.org"

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME, ca_storage=CA_STORAGE, oids=CA_OIDS
    )

    cert1 = ca.issue_certificate(
        cert_common_name, maximum_days=30, oids=cert_oids
    )

    assert isinstance(cert1.cert, x509.Certificate)
    assert isinstance(cert1.key, rsa.RSAPrivateKeyWithSerialization)
    assert type(cert1.public_key_bytes) == bytes
    assert cert1.public_key_bytes.startswith(b"ssh-rsa")
    assert cert1.common_name == cert_common_name
    assert ca.certificates == ["home.ownca.org"]

    clean_test()


def test_ca_issue_cert_loaded_by_second_ca_instance():
    """Int Test: CA issuing a certificate and consistence second instance"""

    cert_oids = {
        "country_name": "BR",
        "locality_name": "Juiz de Fora",
        "state_or_province": "Minas Gerais",
        "street_address": "Rua Constantino Paleta",
        "organization_name": "This place",
        "organization_unit_name": "It was hard and fun",
        "email_address": "kairo at ...",
    }

    cert_common_name = "home.ownca.org"

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME, ca_storage=CA_STORAGE, oids=CA_OIDS
    )

    ca_loaded = CertificateAuthority(
        common_name=CA_COMMON_NAME, ca_storage=CA_STORAGE, oids=CA_OIDS
    )

    cert1 = ca.issue_certificate(
        cert_common_name, maximum_days=30, oids=cert_oids
    )

    assert isinstance(cert1.cert, x509.Certificate)
    assert isinstance(cert1.key, rsa.RSAPrivateKeyWithSerialization)
    assert type(cert1.public_key_bytes) == bytes
    assert cert1.public_key_bytes.startswith(b"ssh-rsa")
    assert cert1.common_name == cert_common_name

    cert1_loaded = ca_loaded.issue_certificate(
        cert_common_name, maximum_days=30, oids=cert_oids
    )

    assert cert1.cert_bytes == cert1_loaded.cert_bytes
    assert cert1.key_bytes == cert1_loaded.key_bytes
    assert cert1.public_key_bytes == cert1_loaded.public_key_bytes
    assert cert1.common_name == cert1_loaded.common_name

    clean_test()


def test_ica():
    """Int Test: if Intermediate CA is initialize as expected."""
    clean_test(path="ICA_test")
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=ICA_STORAGE,
        maximum_days=CA_MAXIMUM_DAYS,
        intermediate=True,
    )

    assert ca.status == CAStatus(
        ca_type_intermediate=True,
        ca_home="ICA_test",
        certificate=False,
        crl=False,
        csr=True,
        key=True,
        public_key=True,
    )

    with pytest.raises(OwnCAIntermediate) as err:
        ca.cert
        assert (
            "Intermediate Certificate Authority has not a signed "
            + "certificate file in CA Storage"
        ) in err.value

    assert isinstance(ca.key, rsa.RSAPrivateKeyWithSerialization)
    assert type(ca.public_key_bytes) == bytes
    assert ca.public_key_bytes.startswith(b"ssh-rsa")
    assert ca.common_name == CA_COMMON_NAME


def test_ica_load():
    """Int Test: loading the existent CA from CA Storage is consistent"""

    clean_test(path="ICA_test")
    ica = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=ICA_STORAGE,
        dns_names=CA_DNS_NAMES,
        intermediate=True,
    )

    ica_loaded = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=ICA_STORAGE,
        dns_names=CA_DNS_NAMES,
        intermediate=True,
    )

    assert ica.status == ica_loaded.status
    assert ica.type == "Intermediate Certificate Authority"
    assert ica.cert_bytes == ica_loaded.cert_bytes
    assert ica.key_bytes == ica.key_bytes
    assert ica.common_name == ica_loaded.common_name
    assert ica.public_key_bytes == ica_loaded.public_key_bytes
    assert ica.csr == ica_loaded.csr
    assert ica.csr_bytes == ica_loaded.csr_bytes

    clean_test(path="ICA_test")


def test_ca_sign_ica():
    """Int Test: A CA will sign an ICA CSR request"""

    clean_test(path="ICA_test")
    clean_test(path="CA_test")
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        dns_names=CA_DNS_NAMES,
    )

    ica = CertificateAuthority(
        common_name="ica.dev.ownca.org",
        ca_storage=ICA_STORAGE,
        dns_names=CA_DNS_NAMES,
        intermediate=True,
    )

    # before siging it shows the exception OwnCAIntermediate
    with pytest.raises(OwnCAIntermediate) as err:
        ica.cert
        assert (
            "Intermediate Certificate Authority has not a signed "
            + "certificate file in CA Storage"
        ) in err.value

    ica_certificate = ca.sign_csr(ica.csr, ica.public_key)

    with open(f"{ICA_STORAGE}/ca.crt", "w") as ca_cert_file:
        ca_cert_file.write(ica_certificate.cert_bytes.decode())
        ca_cert_file.close()

    ica = CertificateAuthority(
        common_name="ica.dev.ownca.org",
        ca_storage=ICA_STORAGE,
        dns_names=CA_DNS_NAMES,
        intermediate=True,
    )

    assert isinstance(ca.cert, x509.Certificate)
    assert ca.type == "Certificate Authority"
    assert ica.type == "Intermediate Certificate Authority"
    assert ica.cert.subject.rfc4514_string() == "CN=ica.dev.ownca.org"
    assert ica.cert.issuer.rfc4514_string() == "CN=ownca.org"
