# -*- coding: utf-8 -*-
"""
Copyright (c) 2019-2020 Kairo de Araujo
"""
from unittest import mock
import pytest

from ownca.ownca import CertificateAuthority, format_oids, load_cert_files
from ownca.exceptions import (
    InvalidOID,
    InvalidCAFiles,
    InconsistentCertificateData,
)

sample_file_data_status_return = {"key": True, "certificate": True}


@mock.patch("ownca.ownca.x509")
def test_format_oids(mock_x509, oids_sample):

    mock_x509.NameAttribute.side_effect = list(oids_sample.values())
    result = format_oids(oids_sample)
    assert result == list(oids_sample.values())


def test_format_oids_non_string():

    with pytest.raises(TypeError):
        format_oids({"locality_name": 1})


def test_format_oids_bad_country_name():

    with pytest.raises(InvalidOID) as excinfo:
        format_oids({"country_name": "Watopia"})
        assert "must be ISO 3166-1 (alfa-2)" in excinfo.value


@mock.patch("ownca.ownca.serialization")
@mock.patch("ownca.ownca.x509")
@mock.patch("builtins.open")
def test_load_cert_files(
    mock_file, mock_x509, mock_serialization, fake_certificate
):

    mock.mock_open(mock_file)

    mocked_key = mock.MagicMock()
    mocked_key.__class__ = classmethod
    mocked_key.private_bytes.return_value = "Key"
    mock_x509.load_pem_x509_certificate.return_value = fake_certificate
    mock_serialization.load_pem_private_key.return_value = mocked_key
    mocked_public_key = mock.MagicMock()
    mocked_public_key.public_bytes.return_value = b'ssh-rsa ...'
    mock_serialization.load_ssh_public_key.return_value = mocked_public_key

    result = load_cert_files(
        "fake-ca.com", "key_file", "public_key_file", "certificate_file"
    )

    assert isinstance(result[0], classmethod)
    assert isinstance(result[1], classmethod)
    assert result[2:] == ("Key", b'ssh-rsa ...')


@mock.patch("ownca.ownca.serialization")
@mock.patch("ownca.ownca.x509")
@mock.patch("builtins.open")
def test_load_cert_files_inconsistent_certificate_data(
    mock_file, mock_x509, mock_serialization, fake_certificate
):

    mock.mock_open(mock_file)
    mock_x509.load_pem_x509_certificate.return_value = fake_certificate
    mock_serialization.load_pem_private_key.return_value = "Key"
    mock_serialization.load_ssh_public_key.return_value = "Public_Key"

    with pytest.raises(InconsistentCertificateData) as excinfo:
        load_cert_files(
            "not-ca.com", "key_file", "public_key_file", "certificate_file"
        )

        assert "not-ca.com" in excinfo.value


@mock.patch("ownca.ownca.issue_cert")
@mock.patch("ownca.ownca.format_oids")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
@mock.patch("builtins.format")
def test_certificateauthority_properties(
    mock_format,
    mock_os,
    mock_file_data_status,
    mock_ownca_directory,
    mock_keys,
    mock_store_file,
    mock_format_oids,
    mock_ca_certificate,
    ownca_directory,
    fake_certificate,
    oids_sample,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = None
    mock_ownca_directory.return_value = ownca_directory
    mock_format_oids.return_value = list(oids_sample.values())

    mock_keys.generate.return_value = (
        "key",
        "key_string",
        "pem_key",
        "public_key",
    )

    mock_store_file.return_value = True

    mock_ca_certificate.return_value = fake_certificate

    ownca = CertificateAuthority(common_name="fake-ca.com", oids=oids_sample)

    assert isinstance(ownca.get_certificate, classmethod)
    assert ownca.get_key == "key"
    assert ownca.get_key_string == "key_string"
    assert ownca.get_public_key == "public_key"
    assert ownca.get_common_name == "fake-ca.com"

    mock_format.return_value = "abcdef0123456789"
    assert ownca.get_hash_name == "abcdef0123456789"


@mock.patch("ownca.ownca.issue_cert")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
@mock.patch("builtins.format")
def test_certificateauthority_ca_storage(
    mock_format,
    mock_os,
    mock_file_data_status,
    mock_ownca_directory,
    mock_keys,
    mock_store_file,
    mock_ca_certificate,
    ownca_directory,
    fake_certificate,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = None
    mock_ownca_directory.return_value = ownca_directory

    mock_keys.generate.return_value = (
        "key",
        "private_key",
        "pem_key",
        "public_key",
    )

    mock_store_file.return_value = True

    mock_ca_certificate.return_value = fake_certificate

    ownca = CertificateAuthority(
        common_name="fake-ca.com", ca_storage="FAKE_STORAGE"
    )

    assert isinstance(ownca.get_certificate, classmethod)
    assert ownca.get_key == "key"
    assert ownca.get_public_key == "public_key"
    assert ownca.get_common_name == "fake-ca.com"

    mock_format.return_value = "abcdef0123456789"
    assert ownca.get_hash_name == "abcdef0123456789"


@mock.patch("ownca.ownca.issue_cert")
@mock.patch("ownca.ownca.load_cert_files")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
@mock.patch("builtins.format")
def test_certificateauthority_already_exists(
    mock_format,
    mock_os,
    mock_file_data_status,
    mock_ownca_directory,
    mock__load_cert_keys,
    ownca_directory,
    fake_certificate,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = True
    mock_ownca_directory.return_value = ownca_directory

    mock__load_cert_keys.return_value = (
        fake_certificate, "key", "key_string", "public_key"
    )

    ownca = CertificateAuthority(
        common_name="fake-ca.com", ca_storage="FAKE_STORAGE"
    )

    assert isinstance(ownca.get_certificate, classmethod)
    assert ownca.get_key == "key"
    assert ownca.get_public_key == "public_key"
    assert ownca.get_common_name == "fake-ca.com"

    mock_format.return_value = "abcdef0123456789"
    assert ownca.get_hash_name == "abcdef0123456789"


@mock.patch("ownca.ownca.issue_cert")
@mock.patch("ownca.ownca.load_cert_files")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
def test_certificateauthority_already_exists_raises_invalidcafiles(
    mock_os,
    mock_file_data_status,
    mock_ownca_directory,
    mock__load_cert_keys,
    ownca_directory,
    fake_certificate,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = False
    mock_ownca_directory.return_value = ownca_directory

    mock__load_cert_keys.return_value = (fake_certificate, "key", "public_key")

    with pytest.raises(InvalidCAFiles):
        CertificateAuthority(
            common_name="fake-ca.com", ca_storage="FAKE_STORAGE"
        )


@mock.patch("ownca.ownca.issue_cert")
@mock.patch("ownca.ownca.load_cert_files")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
def test_certificateauthority_not_expected_current_ca_status(
    mock_os,
    mock_file_data_status,
    mock_ownca_directory,
    mock__load_cert_keys,
    ownca_directory,
    fake_certificate,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = "I Don't Know"
    mock_ownca_directory.return_value = ownca_directory

    mock__load_cert_keys.return_value = (fake_certificate, "key", "public_key")

    with pytest.raises(TypeError):
        CertificateAuthority(
            common_name="fake-ca.com", ca_storage="FAKE_STORAGE"
        )


@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
def test_certificateauthority__init__exc_no_common_name(
    mock_os, mock_file_data_status, mock_ownca_directory, ownca_directory
):
    mock_os.getcwd.return_value = "fake_dir"
    mock_file_data_status.return_value = sample_file_data_status_return
    mock_ownca_directory.return_value = ownca_directory

    with pytest.raises(TypeError):
        CertificateAuthority()


@mock.patch("ownca.ownca.ca_sign_csr")
@mock.patch("ownca.ownca.issue_csr")
@mock.patch("ownca.ownca.format_oids")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.os")
def test_test_certificateauthority_issue_certificate(
    mock_os,
    mock_keys,
    mock_store_file,
    mock_format_oids,
    mock_issue_csr,
    mock_ca_sign_csr,
    certificateauthority,
    fake_certificate,
    fake_csr,
    oids_sample,
):

    my_fake_ca = certificateauthority

    mock_format_oids.return_value = list(oids_sample.values())
    mock_os.path.isdir.return_value = False
    mock_os.mkdir.return_value = True
    mock_keys.generate.return_value = (
        "key",
        "key_string",
        "pem_key",
        "public_key",
    )
    mock_store_file.return_value = True
    mock_issue_csr.return_value = fake_csr
    mock_ca_sign_csr.return_value = fake_certificate

    my_fake_cert = my_fake_ca.issue_certificate(
        "host.fake-ca.com", oids=oids_sample
    )

    assert isinstance(my_fake_cert.get_certificate, classmethod)
    assert my_fake_cert.get_key == "key"
    assert my_fake_cert.get_key_string == "key_string"
    assert my_fake_cert.get_public_key == "public_key"
    assert my_fake_cert.get_common_name == "host.fake-ca.com"


@mock.patch("ownca.ownca.ca_sign_csr")
@mock.patch("ownca.ownca.issue_csr")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.os")
def test_test_certificateauthority_issue_certificate_without_oids(
    mock_os,
    mock_keys,
    mock_store_file,
    mock_issue_csr,
    mock_ca_sign_csr,
    certificateauthority,
    fake_certificate,
    fake_csr,
):

    my_fake_ca = certificateauthority

    mock_os.path.isdir.return_value = False
    mock_os.mkdir.return_value = True
    mock_keys.generate.return_value = (
        "key",
        "key_string",
        "pem_key",
        "public_key",
    )
    mock_store_file.return_value = True
    mock_issue_csr.return_value = fake_csr
    mock_ca_sign_csr.return_value = fake_certificate

    my_fake_cert = my_fake_ca.issue_certificate("host.fake-ca.com")

    assert isinstance(my_fake_cert.get_certificate, classmethod)
    assert my_fake_cert.get_key == "key"
    assert my_fake_cert.get_key_string == "key_string"
    assert my_fake_cert.get_public_key == "public_key"
    assert my_fake_cert.get_common_name == "host.fake-ca.com"


def test_test_certificateauthority_issue_certificate_invalid_hostname(
    certificateauthority
):

    my_fake_ca = certificateauthority

    with pytest.raises(TypeError) as excinfo:
        my_fake_ca.issue_certificate("host. fake-ca.com")

        assert "Invalid 'hostname'" in excinfo.value


@mock.patch("ownca.ownca.load_cert_files")
@mock.patch("ownca.ownca.os")
def test_test_certificateauthority_issue_certificate_existent(
    mock_os, mock__load_cert_keys, certificateauthority, fake_certificate
):

    my_fake_ca = certificateauthority

    mock_os.return_value = True
    mock__load_cert_keys.return_value = (
        fake_certificate,
        "key",
        "key_string",
        "public_key",
    )

    my_fake_cert = my_fake_ca.issue_certificate("host.fake-ca.com")

    assert isinstance(my_fake_cert.get_certificate, classmethod)
    assert my_fake_cert.get_key == "key"
    assert my_fake_cert.get_key_string == "key_string"
    assert my_fake_cert.get_public_key == "public_key"
    assert my_fake_cert.get_common_name == "host.fake-ca.com"
