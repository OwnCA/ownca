# -*- coding: utf-8 -*-
"""
Copyright (c) 2019-2020 Kairo de Araujo
"""
from unittest import mock
import pytest
from voluptuous.error import MultipleInvalid

from ownca.ownca import (
    _validate_owncacertdata,
    CertificateAuthority,
    OwncaCertData,
    format_oids,
    load_cert_files,
)
from ownca.exceptions import (
    OwnCAInvalidOID,
    OwnCAInvalidFiles,
    OwnCAInconsistentData,
    OwnCAInvalidDataStructure,
    OwnCAFatalError,
)

sample_file_data_status_return = {"key": True, "certificate": True}


@mock.patch("ownca.ownca.Schema")
def test__validate_owncacertdata(mock_Schema):

    mocked_schema = mock.MagicMock()
    mocked_schema.return_value = None
    mock_Schema.return_value = mocked_schema

    assert (
        _validate_owncacertdata(
            {
                "cert": "cert",
                "cert_bytes": "cert_bytes",
                "key": "key",
                "key_bytes": "key_bytes",
                "public_key": "public_key",
                "public_key_bytes": "public_key_bytes",
            }
        )
        is None
    )


@mock.patch("ownca.ownca.Schema")
def test__validate_owncacertdata_exception(mock_Schema):

    mocked_schema = mock.MagicMock()
    mocked_schema.side_effect = MultipleInvalid("x")
    mock_Schema.return_value = mocked_schema

    with pytest.raises(OwnCAInvalidDataStructure) as err:
        _validate_owncacertdata(
            {
                "cert": "cert",
                "cert_bytes": "cert_bytes",
                "key": "key",
                "key_bytes": "key_bytes",
                "public_key": "public_key",
                "public_key_bytes": "public_key_bytes",
            }
        )

        assert "OwncaKeyData: " in err.value


@mock.patch("ownca.ownca._validate_owncacertdata")
def test_owncacertdata(mock__validate_owncacertdata):

    mock__validate_owncacertdata.return_value = None
    result = OwncaCertData(
        {
            "cert": "cert",
            "cert_bytes": "cert_bytes",
            "key": "key",
            "key_bytes": "key_bytes",
            "public_key": "public_key",
            "public_key_bytes": "public_key_bytes",
        }
    )

    assert isinstance(result, OwncaCertData)
    assert result.cert == "cert"
    assert result.cert_bytes == "cert_bytes"
    assert result.key == "key"
    assert result.key_bytes == "key_bytes"
    assert result.public_key == "public_key"
    assert result.public_key_bytes == "public_key_bytes"


@mock.patch("ownca.ownca._validate_owncacertdata")
def test_owncacertdata_exception(mock__validate_owncacertdata):

    mock__validate_owncacertdata.side_effect = OwnCAInvalidDataStructure

    with pytest.raises(OwnCAInvalidDataStructure) as err:
        OwncaCertData(
            {
                "cert": "cert",
                "cert_bytes": "cert_bytes",
                "key": "key",
                "crl": "crl",
                "key_bytes": "key_bytes",
                "public_key": "public_key",
                "public_key_bytes": "public_key_bytes",
            }
        )

        assert "OwncaCertData:" in err.value


@mock.patch("ownca.ownca.x509")
def test_format_oids(mock_x509, oids_sample):

    mock_x509.NameAttribute.side_effect = list(oids_sample.values())
    result = format_oids(oids_sample)
    assert result == list(oids_sample.values())


def test_format_oids_non_string():

    with pytest.raises(TypeError):
        format_oids({"locality_name": 1})


def test_format_oids_bad_country_name():

    with pytest.raises(OwnCAInvalidOID) as excinfo:
        format_oids({"country_name": "Watopia"})
        assert "must be ISO 3166-1 (alfa-2)" in excinfo.value


def test_format_oids_empty_strings(oids_sample):
    for oid in oids_sample:
        oids_sample[oid] = ""
    result = format_oids(oids_sample)
    assert result == []


def test_format_oids_none_values(oids_sample):
    for oid in oids_sample:
        oids_sample[oid] = None
    result = format_oids(oids_sample)
    assert result == []


@mock.patch("ownca.ownca._validate_owncacertdata")
@mock.patch("ownca.ownca.serialization")
@mock.patch("ownca.ownca.x509")
@mock.patch("builtins.open")
def test_load_cert_files(
    mock_file,
    mock_x509,
    mock_serialization,
    mock_validate_owncacertdata_schema,
    fake_certificate,
):

    mock.mock_open(mock_file)
    mock_validate_owncacertdata_schema.return_value = None

    mocked_key = mock.MagicMock()
    mocked_key.__class__ = classmethod
    mocked_key.private_bytes.return_value = "Key"
    mock_x509.load_pem_x509_certificate.return_value = fake_certificate
    fake_certificate.public_bytes.return_value = "Cert"
    mock_serialization.load_pem_private_key.return_value = mocked_key
    mocked_public_key = mock.MagicMock()
    mocked_public_key.__class__ = classmethod
    mocked_public_key.public_bytes.return_value = b"ssh-rsa ..."
    mock_serialization.load_ssh_public_key.return_value = mocked_public_key

    result = load_cert_files(
        "fake-ca.com", "key_file", "public_key_file", "csr_file",
        "certificate_file", "crl_file"
    )

    assert isinstance(result.cert, classmethod)
    assert result.cert_bytes == "Cert"
    assert result.key_bytes == "Key"
    assert result.public_key_bytes == b"ssh-rsa ..."


@mock.patch("ownca.ownca._validate_owncacertdata")
@mock.patch("ownca.ownca.serialization")
@mock.patch("ownca.ownca.x509")
@mock.patch("builtins.open")
def test_load_cert_files_no_csr_files(
    mock_file,
    mock_x509,
    mock_serialization,
    mock_validate_owncacertdata_schema,
    fake_certificate,
):

    mock.mock_open(mock_file)
    mock_validate_owncacertdata_schema.return_value = None

    mocked_key = mock.MagicMock()
    mocked_key.__class__ = classmethod
    mocked_key.private_bytes.return_value = "Key"
    mock_x509.load_pem_x509_certificate.return_value = fake_certificate
    fake_certificate.public_bytes.return_value = "Cert"
    mock_serialization.load_pem_private_key.return_value = mocked_key
    mocked_public_key = mock.MagicMock()
    mocked_public_key.__class__ = classmethod
    mocked_public_key.public_bytes.return_value = b"ssh-rsa ..."
    mock_serialization.load_ssh_public_key.return_value = mocked_public_key

    result = load_cert_files(
        "fake-ca.com", "key_file", "public_key_file", "csr_file",
        "certificate_file", "crl_file"
    )

    assert isinstance(result.cert, classmethod)
    assert result.cert_bytes == "Cert"
    assert result.key_bytes == "Key"
    assert result.public_key_bytes == b"ssh-rsa ..."


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

    with pytest.raises(OwnCAInconsistentData) as excinfo:
        load_cert_files(
            "not-ca.com", "key_file", "public_key_file", "crl_file",
            "certificate_file", "crl_file"
        )

        assert "not-ca.com" in excinfo.value


@mock.patch("ownca.ownca.OwncaCertData")
@mock.patch("ownca.ownca.ca_crl")
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
    mock_ca_crl,
    mock_OwncaCertData,
    ownca_directory,
    fake_certificate,
    fake_crl,
    oids_sample,
    ownca_certdata,
    ownca_keydata,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = None
    mock_ownca_directory.return_value = ownca_directory
    mock_format_oids.return_value = list(oids_sample.values())
    mock_keys.generate.return_value = ownca_keydata
    mock_store_file.return_value = True
    mock_ca_crl.return_value = fake_crl
    mock_OwncaCertData.return_value = ownca_certdata

    mock_ca_certificate.return_value = fake_certificate

    ownca = CertificateAuthority(common_name="fake-ca.com", oids=oids_sample)

    assert isinstance(ownca.cert, classmethod)
    assert ownca.key == "key"
    assert ownca.key_bytes == "key_bytes"
    assert ownca.public_key == "public_key"
    assert ownca.public_key_bytes == "public_key_bytes"
    assert ownca.common_name == "fake-ca.com"

    mock_format.return_value = "abcdef0123456789"
    assert ownca.hash_name == "abcdef0123456789"


@mock.patch("ownca.ownca.issue_cert")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
def test_certificateauthority_certificate_failure(
    mock_os,
    mock_file_data_status,
    mock_ownca_directory,
    mock_keys,
    mock_store_file,
    mock_issue_cert,
    ownca_directory,
    fake_certificate,
    ownca_keydata,
    ownca_certdata,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = None
    mock_ownca_directory.return_value = ownca_directory
    mock_keys.generate.return_value = ownca_keydata
    mock_store_file.return_value = True
    mock_issue_cert.return_value = False

    with pytest.raises(OwnCAFatalError) as err:
        CertificateAuthority(
            common_name="fake-ca.com", ca_storage="FAKE_STORAGE"
        )

        assert "Failure to generate the certificate" in err.value


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
    ownca_certdata,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = True
    mock_ownca_directory.return_value = ownca_directory

    mock__load_cert_keys.return_value = ownca_certdata

    ownca = CertificateAuthority(
        common_name="fake-ca.com", ca_storage="FAKE_STORAGE"
    )

    assert isinstance(ownca.cert, classmethod)
    assert ownca.cert_bytes == "cert_bytes"
    assert ownca.key == "key"
    assert ownca.public_key == "public_key"
    assert ownca.common_name == "fake-ca.com"

    mock_format.return_value = "abcdef0123456789"
    assert ownca.hash_name == "abcdef0123456789"


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

    with pytest.raises(OwnCAInvalidFiles):
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
    ownca_certdata,
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = "I Don't Know"
    mock_ownca_directory.return_value = ownca_directory

    mock__load_cert_keys.return_value = ownca_certdata

    with pytest.raises(TypeError):
        CertificateAuthority(ca_storage="FAKE_STORAGE")


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


@mock.patch("ownca.ownca.OwncaCertData")
@mock.patch("ownca.ownca.ca_crl")
@mock.patch("ownca.ownca.ca_sign_csr")
@mock.patch("ownca.ownca.issue_csr")
@mock.patch("ownca.ownca.format_oids")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.os")
def test_certificateauthority_issue_certificate(
    mock_os,
    mock_keys,
    mock_store_file,
    mock_format_oids,
    mock_issue_csr,
    mock_ca_sign_csr,
    mock_ca_crl,
    mock_OwncaCertData,
    certificateauthority,
    fake_certificate,
    fake_csr,
    fake_crl,
    oids_sample,
    ownca_keydata,
    ownca_certdata,
):

    my_fake_ca = certificateauthority

    mock_format_oids.return_value = list(oids_sample.values())
    mock_os.path.isdir.return_value = False
    mock_os.mkdir.return_value = True
    mock_keys.generate.return_value = ownca_keydata
    mock_store_file.return_value = True
    mock_issue_csr.return_value = fake_csr
    mock_ca_crl.return_value = fake_crl
    mock_ca_sign_csr.return_value = fake_certificate
    mock_OwncaCertData.return_value = ownca_certdata

    my_fake_cert = my_fake_ca.issue_certificate(
        "host.fake-ca.com", oids=oids_sample
    )

    assert isinstance(my_fake_cert.cert, classmethod)
    assert my_fake_cert.cert_bytes == "cert_bytes"
    assert my_fake_cert.key == "key"
    assert my_fake_cert.key_bytes == "key_bytes"
    assert my_fake_cert.public_key == "public_key"
    assert my_fake_cert.public_key_bytes == "public_key_bytes"
    assert my_fake_cert.common_name == "host.fake-ca.com"


@mock.patch("ownca.ownca.OwncaCertData")
@mock.patch("ownca.ownca.ca_sign_csr")
@mock.patch("ownca.ownca.issue_csr")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.os")
def test_certificateauthority_issue_certificate_without_oids(
    mock_os,
    mock_keys,
    mock_store_file,
    mock_issue_csr,
    mock_ca_sign_csr,
    mock_OwncaCertData,
    certificateauthority,
    fake_certificate,
    fake_csr,
    ownca_keydata,
    ownca_certdata,
):

    my_fake_ca = certificateauthority

    mock_os.path.isdir.return_value = False
    mock_os.mkdir.return_value = True
    mock_keys.generate.return_value = ownca_keydata
    mock_store_file.return_value = True
    mock_issue_csr.return_value = fake_csr
    mock_ca_sign_csr.return_value = fake_certificate
    mock_OwncaCertData.return_value = ownca_certdata

    my_fake_cert = my_fake_ca.issue_certificate("host.fake-ca.com")

    assert isinstance(my_fake_cert.cert, classmethod)
    assert my_fake_cert.cert_bytes == "cert_bytes"
    assert my_fake_cert.key == "key"
    assert my_fake_cert.key_bytes == "key_bytes"
    assert my_fake_cert.public_key == "public_key"
    assert my_fake_cert.public_key_bytes == "public_key_bytes"
    assert my_fake_cert.common_name == "host.fake-ca.com"


@mock.patch("ownca.ownca.OwncaCertData")
@mock.patch("ownca.ownca.ca_sign_csr")
@mock.patch("ownca.ownca.issue_csr")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.os")
def test_test_certificateauthority_issue_certificate_invalid_oids(
    mock_os,
    mock_keys,
    mock_store_file,
    mock_issue_csr,
    mock_ca_sign_csr,
    mock_OwncaCertData,
    certificateauthority,
    fake_certificate,
    fake_csr,
    ownca_keydata,
    ownca_certdata,
):

    my_fake_ca = certificateauthority

    mock_os.path.isdir.return_value = False
    mock_os.mkdir.return_value = True
    mock_keys.generate.return_value = ownca_keydata
    mock_store_file.return_value = True
    mock_issue_csr.return_value = fake_csr
    mock_ca_sign_csr.return_value = fake_certificate
    mock_OwncaCertData.return_value = ownca_certdata

    with pytest.raises(OwnCAInvalidOID) as err:
        my_fake_ca.issue_certificate(
            "host.fake-ca.com", oids={"invalid_oid": "OID_INVALID"}
        )

        assert "invalid_oid" in err.value


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
    mock_os,
    mock__load_cert_keys,
    certificateauthority,
    fake_certificate,
    ownca_certdata,
):

    my_fake_ca = certificateauthority

    mock_os.return_value = True
    mock__load_cert_keys.return_value = ownca_certdata

    my_fake_cert = my_fake_ca.issue_certificate("host.fake-ca.com")

    assert isinstance(my_fake_cert.cert, classmethod)
    assert my_fake_cert.key == "key"
    assert my_fake_cert.key_bytes == "key_bytes"
    assert my_fake_cert.public_key == "public_key"
    assert my_fake_cert.common_name == "host.fake-ca.com"
