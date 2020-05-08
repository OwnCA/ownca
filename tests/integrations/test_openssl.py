#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020 Kairo de Araujo
#
import subprocess

from ownca import CertificateAuthority
from tests.integrations.conftest import (
    CA_STORAGE,
    CA_OIDS,
    CA_COMMON_NAME,
    CA_MAXIMUM_DAYS,
    CA_DNS_NAMES,
    clean_test,
)


def test_valid_cert_ca():
    """Test if OpenSSL is able to validate the certificate against CA."""

    clean_test()
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        maximum_days=CA_MAXIMUM_DAYS,
        dns_names=CA_DNS_NAMES,
        oids=CA_OIDS
    )

    ca.issue_certificate(
        "dev.ownca.org",
        maximum_days=30,
        dns_names=["www.dev.ownca.org", "developer.ownca.org"],
        oids={"country_name": "NL", "locality_name": "Veldhoven"},
    )

    openssl_cmd = (
        "openssl verify -verbose -CAfile CA_test/ca.crt "
        + "CA_test/certs/dev.ownca.org/dev.ownca.org.crt"
    )
    openssl = subprocess.run(
        openssl_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    assert openssl.returncode == 0, openssl.stdout

    clean_test()


def test_validad_cert_sencond_ca():
    """Test if OpenSSL FAILS to validate certificate against other CA"""

    clean_test()
    clean_test("CA_test_second")
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        maximum_days=CA_MAXIMUM_DAYS,
        dns_names=CA_DNS_NAMES,
    )

    ca.issue_certificate(
        "dev.ownca.org",
        maximum_days=30,
        dns_names=["www.dev.ownca.org", "developer.ownca.org"],
        oids={"country_name": "NL", "locality_name": "Veldhoven"},
    )

    openssl_cmd = (
        "openssl verify -verbose -CAfile CA_test/ca.crt "
        + "CA_test/certs/dev.ownca.org/dev.ownca.org.crt"
    )
    openssl = subprocess.run(
        openssl_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    assert openssl.returncode == 0, openssl.stdout

    CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage="CA_test_second",
        maximum_days=CA_MAXIMUM_DAYS,
        dns_names=CA_DNS_NAMES,
    )

    # test to wrong CA
    openssl_cmd = (
        "openssl verify -verbose -CAfile CA_test_second/ca.crt "
        + "CA_test/certs/dev.ownca.org/dev.ownca.org.crt"
    )
    openssl = subprocess.run(
        openssl_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    assert openssl.returncode == 2, openssl.stdout

    clean_test()
    clean_test("CA_test_second")


def test_extension_subject_alternative_name():
    """Test if OpenSSL gets correct Subject Alternative Name"""

    clean_test()
    clean_test("CA_test_second")
    ca = CertificateAuthority(
        common_name=CA_COMMON_NAME,
        ca_storage=CA_STORAGE,
        maximum_days=CA_MAXIMUM_DAYS,
        dns_names=CA_DNS_NAMES,
    )

    ca.issue_certificate(
        "dev.ownca.org",
        maximum_days=30,
        dns_names=["www.dev.ownca.org", "developer.ownca.org"],
        oids={"country_name": "NL", "locality_name": "Veldhoven"},
    )

    openssl_cmd = (
        "openssl x509 -text -noout -in "
        + "CA_test/certs/dev.ownca.org/dev.ownca.org.crt "
        + "-certopt no_subject,no_header,no_version,no_serial,no_signame,"
        + "no_validity,no_issuer,no_pubkey,no_sigdump,no_aux"
    )
    openssl = subprocess.run(
        openssl_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    expected_dns_san = (
        "DNS:www.dev.ownca.org, DNS:developer.ownca.org"
    )

    assert openssl.returncode == 0, openssl.stdout
    assert "Subject Alternative Name:" in openssl.stdout.decode()
    assert expected_dns_san in openssl.stdout.decode()
