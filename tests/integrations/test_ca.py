#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020 Kairo de Araujo
#

from cryptography import x509
from cryptography.hazmat.backends.openssl import rsa

from ownca import CertificateAuthority
from tests.integrations.conftest import (
    CA_STORAGE,
    CA_COMMON_NAME,
    CA_OIDS,
    CA_MAXIMUM_DAYS,
    CA_DNS_NAMES,
    clean_test,
)


def test_ca():
    """Test if CA is initialize as expected."""

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        maximum_days=CA_MAXIMUM_DAYS,
    )

    assert ca.status == {
        "certificate": True,
        "key": True,
        "public_key": True,
        "ca_home": CA_STORAGE,
    }

    assert isinstance(ca.cert, x509.Certificate)
    assert isinstance(ca.key, rsa.RSAPrivateKeyWithSerialization)
    assert type(ca.public_key_bytes) == bytes
    assert ca.public_key_bytes.startswith(b"ssh-rsa")
    assert ca.common_name == CA_COMMON_NAME
    assert len(ca.hash_name) == 8


def test_ca_load():
    """Test if loading the existent CA from CA Storage is consistent"""

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        dns_name=CA_DNS_NAMES,
    )

    ca_loaded = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        dns_name=CA_DNS_NAMES,
    )

    assert ca.status == ca_loaded.status
    assert ca.cert_bytes == ca_loaded.cert_bytes
    assert ca.key_bytes == ca.key_bytes
    assert ca.common_name == ca_loaded.common_name
    assert ca.public_key_bytes == ca_loaded.public_key_bytes
    assert ca.hash_name == ca_loaded.hash_name

    clean_test()


def test_ca_issue_cert():
    """Test CA issuing a certificate"""

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

    clean_test()


def test_ca_issue_cert_loaded_by_second_ca_instance():
    """Test CA issuing a certificate and consistence second instance"""

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
