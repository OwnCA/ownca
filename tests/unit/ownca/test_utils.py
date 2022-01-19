# -*- coding: utf-8 -*-
"""
Copyright (c) 2019-2022 Kairo de Araujo
"""
from unittest import mock

import pytest

from ownca._constants import CA_CERTS_DIR, CA_PRIVATE_DIR
from ownca.utils import (CAStatus, _create_ownca_dir, file_data_status,
                         ownca_directory, store_file, validate_hostname)

ca_status = CAStatus()


def test_file_data_status():
    ca_status.key = True
    ca_status.certificate = True
    assert file_data_status(ca_status)


def test_file_data_status_case_false():
    ca_status.key = True
    ca_status.certificate = False
    assert file_data_status(ca_status) is False


def test_file_data_status_case_none():
    ca_status.key = False
    ca_status.certificate = False

    assert file_data_status(ca_status) is None


@mock.patch("ownca.utils.os")
def test__create_ownca_dir(mock_os):

    mock_os.mkdir.return_value = True
    assert _create_ownca_dir("test_dir") is None


@mock.patch("ownca.utils.os")
def test__create_ownca_dir_case_exceptions(mock_os):

    exceptions = [FileExistsError, OSError, FileNotFoundError]
    mock_os.path.isdir.return_value = False
    mock_os.mkdir.side_effect = exceptions

    for exception in exceptions:
        with pytest.raises(exception):
            _create_ownca_dir("test_dir")


@mock.patch("ownca.utils.os")
@mock.patch("ownca.utils.glob")
@mock.patch("ownca.utils._create_ownca_dir")
def test_ownca_directory(mock__create_ownca_dir, mock_glob, mock_os):

    # root ca_storage is ok.
    mock_os.path.isdir.return_value = False
    mock_os.mkdir.return_value = True

    mock_glob.return_value = [CA_CERTS_DIR, CA_PRIVATE_DIR]
    mock__create_ownca_dir.return_value = True

    assert ownca_directory("test_dir") == CAStatus(
        ca_type_intermediate=True,
        ca_home="test_dir",
        certificate=True,
        crl=True,
        csr=True,
        key=True,
        public_key=True,
    )


@mock.patch("ownca.utils.os")
@mock.patch("builtins.open")
def test_store_file(mock_open, mock_os):
    mock_os.path.isfile.return_value = False
    mock_os.chmod.return_value = True
    mock_open.return_file = True

    assert store_file(b"data", "test_dir", False, None)


@mock.patch("ownca.utils.os")
@mock.patch("builtins.open")
def test_store_file_case_oserror(mock_open, mock_os):
    mock_os.path.isfile.return_value = False
    mock_open.side_effect = OSError

    with pytest.raises(OSError):
        assert store_file(b"data", "test_dir", False, 0o600)


@mock.patch("ownca.utils.os")
@mock.patch("builtins.open")
def test_store_file_case_file_exists(mock_open, mock_os):
    mock_os.path.isfile.return_value = True
    mock_open.return_file = True

    with pytest.raises(FileExistsError):
        assert store_file(b"data", "test_dir", False, 0o600)


def test_validate_hostname():

    assert validate_hostname("myserver")
    assert validate_hostname("myserver.com")


def test_validate_hostname_case_invalid_type():

    assert validate_hostname(1) is False
    assert validate_hostname(True) is False
    assert validate_hostname(0.1) is False


def test_validate_hostname_case_invalid_size():

    assert validate_hostname("a" * 250 + " .com") is False


def test_validate_hostname_case_invalid_string_chars():

    assert validate_hostname("#*#($#$&(") is False
