import pytest
from unittest import mock

from ownca.ownca import CertificateAuthority


@pytest.fixture
def ownca_directory():
    ownca_directory_return = {
        'certificate': False,
        'key': False,
        'public_key': False,
        'ca_home': 'fake_dir'
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
        "email_address": "kairo at ..."
    }

    return sample_oids


@pytest.fixture
def fake_certificate():

    fake_certificate = mock.MagicMock()
    fake_certificate.__class__ = classmethod
    fake_certificate.subject.rfc4514_string.return_value = "CN=fake-ca.com"

    return fake_certificate


@pytest.fixture
def fake_csr():
    fake_csr = mock.MagicMock()
    fake_csr.__class__ = classmethod
    fake_csr.public_bytes.return_value = "CSR"

    return fake_csr


@pytest.fixture()
@mock.patch("ownca.ownca.ca_certificate")
@mock.patch("ownca.ownca.store_file")
@mock.patch("ownca.ownca.keys")
@mock.patch("ownca.ownca.ownca_directory")
@mock.patch("ownca.ownca.file_data_status")
@mock.patch("ownca.ownca.os")
def certificateauthority(
    mock_os, mock_file_data_status, mock_ownca_directory,
    mock_keys, mock_store_file, mock_ca_certificate,
    ownca_directory, oids_sample, fake_certificate
):
    mock_os.getcwd.return_value = "FAKE_CA"
    mock_file_data_status.return_value = None
    mock_ownca_directory.return_value = ownca_directory

    mock_keys.generate.return_value = (
        "key", "private_key", "pem_key", "public_key"
    )

    mock_store_file.return_value = True

    mock_ca_certificate.return_value = fake_certificate

    return CertificateAuthority(common_name="fake-ca.com", oids=oids_sample)
