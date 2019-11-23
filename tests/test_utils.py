#
# Copyright (c) 2019 Kairo de Araujo
#
import pytest
from unittest import mock

from ownca.utils import (
    file_data_status, _create_ownca_dir, validate_hostname
)

ca_status = {
    "key": True,
    "certificate": True
}


def test_file_data_status():
    ca_status["key"] = True
    ca_status["certificate"] = True
    assert file_data_status(ca_status)


def test_file_data_status_case_false():
    ca_status["key"] = True
    ca_status["certificate"] = True

    assert file_data_status(ca_status)

    ca_status["certificate"] = False
    assert file_data_status(ca_status) is False


def test_file_data_status_case_none():
    ca_status["key"] = False
    ca_status["certificate"] = False

    assert file_data_status(ca_status) is None


@mock.patch("ownca.utils.os")
def test__create_ownca_dir(mock_os):

    mock_os.mkdir.return_value = True
    assert _create_ownca_dir("test_dir")


@mock.patch("ownca.utils.os")
def test__create_ownca_dir_case_exceptions(mock_os):

    exceptions = [
        FileExistsError,
        OSError,
        FileNotFoundError
    ]
    mock_os.mkdir.side_effect = exceptions

    for exception in exceptions:
        with pytest.raises(exception):
            _create_ownca_dir("test_dir")


def test_validate_hostname():

    assert validate_hostname("myserver")
    assert validate_hostname("myserver.com")


def test_validate_hostname_case_invalid_type():

    assert validate_hostname(1) is False
    assert validate_hostname(True) is False
    assert validate_hostname(0.1) is False


def test_validate_hostname_case_invalid_size():

    assert validate_hostname("a"*250 + " .com") is False


def test_validate_hostname_case_invalid_string_chars():

    assert validate_hostname("#*#($#$&(") is False
