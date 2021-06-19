#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018-2021 Kairo de Araujo
"""

from glob import glob
import os
import re

from ._constants import (
    CA_CERT,
    CA_CERTS_DIR,
    CA_CSR,
    CA_CRL,
    CA_KEY,
    CA_PUBLIC_KEY,
    CA_PRIVATE_DIR,
    HOSTNAME_REGEX,
)
from .exceptions import OwnCAIntermediate


def file_data_status(ca_status):
    """
    Verify the CA status based in the existent files.

    :param ca_status: current ``ca_status`` file dictionary:
        ``ownca.utils.ownca_directory``
    :type ca_status: dict, required

    :return: True, False or None
    :rtype: bool/None
    """
    key = ca_status.get("key")
    cert = ca_status.get("certificate")
    csr = ca_status.get("csr")

    # this check if the CA has the key and certificates files in disk
    # if both are true, means the health status is True
    if key == cert and key is True:
        return True

    # if certificate and key does not match and one of then are True, is not ok
    elif key != cert and key or cert:
        if csr:
            raise OwnCAIntermediate("Intermediate CA Missing the certificate.")

        return False

    # in that case, the system has not a CA configured.
    else:
        return None


def _create_ownca_dir(ownca_dir):
    """
    Creates the CA directory.

    :param ownca_dir: :string: full path directory for ownca
    :return: bool
    """
    try:
        if not os.path.isdir(ownca_dir):
            os.mkdir(ownca_dir)

    except (FileExistsError, OSError, FileNotFoundError) as err:
        raise err


def ownca_directory(ca_storage):
    """
    Validates and manage CA storage directory and subfolders structure files.

    :param ca_storage: CA storage
    :type ca_storage: string, required
    :return: dict with state of ownca storage files
    :rtype: dict

    .. highlight:: python
    .. code-block:: python

        {
            "certificate": bool,
            "crl": bool,
            "key": bool,
            "public_key": bool,
            "ca_home": None or str,
        }

    """
    if "CA_test".lower() in ca_storage.lower() and not os.getenv("TEST_MODE"):
        raise ValueError(
            f"Not allowed {ca_storage}. Please do not use a name that "
            + "contains 'ca_test'"
        )

    ownca_status = {
        "type": "Certificate Authority",
        "ca_home": None,
        "certificate": False,
        "crl": False,
        "csr": False,
        "key": False,
        "public_key": False,
    }

    if not os.path.isdir(ca_storage):
        os.mkdir(ca_storage)

    ownca_subdirs = [CA_CERTS_DIR, CA_PRIVATE_DIR]
    current_subdirs = glob(f"{ca_storage}/*")

    for ownca_subdir in ownca_subdirs:
        ca_storage_sub_dir = os.path.join(ca_storage, ownca_subdir)
        if ca_storage_sub_dir not in current_subdirs:
            ownca_status["ca_home"] = "Inconsistent!"
            _create_ownca_dir(ca_storage_sub_dir)

    ownca_status["ca_home"] = ca_storage

    if os.path.isfile(os.path.join(ca_storage, CA_CERT)):
        ownca_status["certificate"] = True

    if os.path.isfile(os.path.join(ca_storage, CA_CSR)):
        ownca_status["csr"] = True
        ownca_status["type"] = "Intermediate Certificate Authority"

    if os.path.isfile(os.path.join(ca_storage, CA_CRL)):
        ownca_status["crl"] = True

    if os.path.isfile(os.path.join(ca_storage, CA_KEY)):
        ownca_status["key"] = True

    if os.path.isfile(os.path.join(ca_storage, CA_PUBLIC_KEY)):
        ownca_status["public_key"] = True

    return ownca_status


def store_file(file_data, file_path, permission=None, force=False):
    """
    Stores (write) files in the storage

    :param file_data: the file data
    :type file_data: str, required
    :param file_path: the file absolute path
    :type file_path: str, required
    :param permission: operating-system mode bitfield
    :type permission: int, optional
    :return: bool
    :rtype: boolean
    """
    if os.path.isfile(file_path) and force is False:
        raise FileExistsError(f"{file_path} already exists.")

    try:
        with open(file_path, "w") as f:
            f.write(file_data.decode("utf-8"))

        if permission:
            os.chmod(file_path, permission)

    except OSError as err:
        raise err

    return True


def validate_hostname(hostname):
    """
    Validates if the hostname follows the common Internet rules for FQDN

    :param hostname: string hostname
    :type hostname: sting, required
    :return: bool
    :rtype: bool
    """

    if type(hostname) is not str:
        return False

    if len(hostname) < 1 or len(hostname) > 253:
        return False

    ldh_re = re.compile(f"{HOSTNAME_REGEX}", re.IGNORECASE)

    return all(ldh_re.match(x) for x in hostname.split("."))
