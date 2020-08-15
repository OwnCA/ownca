# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 Kairo de Araujo
"""
import pytest
from unittest import mock

from ownca.ownca import CertificateAuthority, OwncaCertData
from ownca.crypto.keys import OwncaKeyData


@pytest.fixture
def ownca_directory():
    ownca_directory_return = {
        "certificate": False,
        "key": False,
        "public_key": False,
        "ca_home": "fake_dir",
    }

    return ownca_directory_return


@pytest.fixture
def oids_sample():
    sample_oids = {
        "country_name": "BR",
        "locality_name": "Uba",
        "state_or_province": "Minas Gerais",
        "street_address": "Rua Agostinho Martins de Oliveira",
        "organization_name": "First home",
        "organization_unit_name": "Good memories",
        "email_address": "kairo at ...",
    }

    return sample_oids


@pytest.fixture
def fake_certificate():

    fake_certificate = mock.MagicMock()
    fake_certificate.__class__ = classmethod
    fake_certificate.return_value._backend = "123"
    fake_certificate.subject.rfc4514_string.return_value = "CN=fake-ca.com"

    return fake_certificate


@pytest.fixture
def fake_csr():

    mocked_extension = mock.MagicMock()
    mocked_extension.return_value.value.oid._name = ["OID", "SomeExtension"]

    fake_csr = mock.MagicMock()
    fake_csr.__class__ = classmethod
    fake_csr.public_bytes.return_value = "CSR"
    fake_csr.return_value.extensions = mocked_extension

    return fake_csr


@pytest.fixture
def fake_crl():

    fake_crl = mock.MagicMock()
    fake_crl.__class__ = classmethod
    fake_crl.public_bytes.return_value = "CRL"
    fake_crl.get_revoked_certificate_by_serial_number = "000000"

    return fake_crl


@pytest.fixture()
@mock.patch("ownca.ownca.OwncaCertData")
@mock.patch("ownca.ownca.ca_crl")
@mock.patch("ownca.ownca.issue_cert")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
def certificateauthority(
    mock_os,
    mock_file_data_status,
    mock_ownca_directory,
    mock_keys,
    mock_store_file,
    mock_ca_certificate,
    mock_ca_crl,
    mock_OwncaCertData,
    ownca_directory,
    oids_sample,
    fake_certificate,
    fake_crl,
    ownca_certdata,
    ownca_keydata,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = None
    mock_ownca_directory.return_value = ownca_directory
    mock_keys.generate.return_value = ownca_keydata
    mock_ca_crl.return_value = fake_crl
    mock_OwncaCertData.return_value = ownca_certdata

    mock_store_file.return_value = True

    mock_ca_certificate.return_value = fake_certificate

    return CertificateAuthority(common_name="fake-ca.com", oids=oids_sample)


@pytest.fixture
def x509_certificate_builder(fake_certificate):
    mocked_builder = mock.MagicMock()
    mocked_builder.subject_name.return_value = mocked_builder
    mocked_builder.issuer_name.return_value = mocked_builder
    mocked_builder.not_valid_before.return_value = mocked_builder
    mocked_builder.not_valid_after.return_value = mocked_builder
    mocked_builder.serial_number.return_value = mocked_builder
    mocked_builder.public_key.return_value = mocked_builder
    mocked_builder.add_extension.return_value = mocked_builder
    mocked_builder.sign.return_value = fake_certificate

    return mocked_builder


@pytest.fixture()
@mock.patch("ownca.ownca._validate_owncacertdata")
def ownca_certdata(mock_validate_owncacertdata, fake_certificate):

    mock_validate_owncacertdata.return_value = None

    mocked_crl = mock.MagicMock()
    mocked_crl.__class__ = classmethod
    mocked_crl.public_bytes.return_value = "CRL"
    mocked_crl.get_revoked_certificate_by_serial_number.return_value = "000"

    mocked_cert = mock.MagicMock()
    mocked_cert.__class__ = classmethod
    mocked_cert.return_value._backend = "123"
    mocked_cert.subject.rfc4514_string.return_value = "CN=fake-ca.com"
    mocked_cert.serial_number = "001"

    cert_data = OwncaCertData(
        {
            "cert": mocked_cert,
            "cert_bytes": "cert_bytes",
            "key": "key",
            "key_bytes": "key_bytes",
            "public_key": "public_key",
            "public_key_bytes": "public_key_bytes",
            "crl": mocked_crl,
            "crl_bytes": "crl_bytes"
        }
    )

    return cert_data


@pytest.fixture()
@mock.patch("ownca.crypto.keys._validate_owncakeydata")
def ownca_keydata(mock__validate_owncakeydata):

    mock__validate_owncakeydata.return_value = None
    cert_data = OwncaKeyData(
        {
            "key": "key",
            "key_bytes": "key_bytes",
            "public_key": "public_key",
            "public_key_bytes": "public_key_bytes",
        }
    )

    return cert_data
