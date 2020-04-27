#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020 Kairo de Araujo
#

from cryptography import x509
from cryptography.hazmat.backends.openssl import rsa

from ownca import CertificateAuthority
from tests.integrations.conftest import (
    CA_STORAGE, CA_COMMON_NAME, CA_OIDS, CA_MAXIMUM_DAYS, CA_DNS_NAMES,
    clean_test
)


def test_ca():
    """Test if CA is initialize as expected."""

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME, ca_storage=CA_STORAGE,
        maximum_days=CA_MAXIMUM_DAYS
    )

    assert ca.status == {
        "certificate": True,
        "key": True,
        "public_key": True,
        "ca_home": CA_STORAGE,
    }

    assert isinstance(ca.get_certificate, x509.Certificate)

    assert isinstance(ca.get_key, rsa.RSAPrivateKeyWithSerialization)

    assert type(ca.get_public_key) == bytes
    assert ca.get_public_key.startswith(b"ssh-rsa")

    assert ca.get_common_name == CA_COMMON_NAME

    assert len(ca.get_hash_name) == 8


def test_ca_load():
    """Test if loading the existent CA from CA Storage is consistent"""

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME, ca_storage=CA_STORAGE,
        dns_name=CA_DNS_NAMES
    )

    ca_loaded = CertificateAuthority(
        common_name=CA_COMMON_NAME, ca_storage=CA_STORAGE,
        dns_name=CA_DNS_NAMES
    )

    assert ca.status == ca_loaded.status
    assert ca.get_certificate == ca_loaded.get_certificate
    assert ca.get_key_string == ca.get_key_string
    assert ca.get_common_name == ca_loaded.get_common_name
    assert ca.get_public_key == ca_loaded.get_public_key
    assert ca.get_hash_name == ca_loaded.get_hash_name

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

    assert isinstance(cert1.get_certificate, x509.Certificate)

    assert isinstance(cert1.get_key, rsa.RSAPrivateKeyWithSerialization)

    assert type(cert1.get_public_key) == bytes
    assert cert1.get_public_key.startswith(b"ssh-rsa")

    assert cert1.get_common_name == cert_common_name

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

    assert isinstance(cert1.get_certificate, x509.Certificate)

    assert isinstance(cert1.get_key, rsa.RSAPrivateKeyWithSerialization)

    assert type(cert1.get_public_key) == bytes
    assert cert1.get_public_key.startswith(b"ssh-rsa")

    assert cert1.get_common_name == cert_common_name

    cert1_loaded = ca_loaded.issue_certificate(
        cert_common_name, maximum_days=30, oids=cert_oids
    )

    assert cert1.get_certificate == cert1_loaded.get_certificate
    assert cert1.get_key_string == cert1_loaded.get_key_string
    assert cert1.get_public_key == cert1_loaded.get_public_key
    assert cert1.get_common_name == cert1_loaded.get_common_name

    clean_test()
