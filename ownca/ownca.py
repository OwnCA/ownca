#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018-2022 Kairo de Araujo
"""

import datetime
import os
import re
import warnings

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import (_RSAPrivateKey,
                                                      _RSAPublicKey)
from cryptography.hazmat.backends.openssl.x509 import (
    _CertificateRevocationList, _RevokedCertificate)
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from voluptuous import Any, MultipleInvalid, Schema

from ._constants import (CA_CERT, CA_CERTS_DIR, CA_CRL, CA_CSR, CA_KEY,
                         CA_PUBLIC_KEY, COUNTRY_REGEX, HOSTNAME_REGEX, OIDS)
from .crypto import keys
from .crypto.certs import ca_crl, ca_sign_csr, issue_cert, issue_csr
from .exceptions import (OwnCAInvalidDataStructure, OwnCAFatalError,
                         OwnCAInconsistentData, OwnCAIntermediate,
                         OwnCAInvalidCertificate, OwnCAInvalidFiles,
                         OwnCAInvalidOID)
from .utils import (file_data_status, ownca_directory, store_file,
                    validate_hostname)


def _validate_owncacertdata(data):
    """
    Validates the OwnCA data structure

    :param data: Certificate data
    :type data: dict
    :return : None
    :raises: ``exceptions.OwnCAInvalidDataStructure``

    """
    cert_schema = Schema(
        {
            "cert": Any(None, x509.Certificate),
            "cert_bytes": Any(None, bytes),
            "csr": Any(None, x509.CertificateSigningRequest),
            "csr_bytes": Any(None, bytes),
            "key": Any(None, _RSAPrivateKey),
            "key_bytes": Any(None, bytes),
            "public_key": _RSAPublicKey,
            "public_key_bytes": bytes,
            "crl": Any(None, _CertificateRevocationList),
            "crl_bytes": Any(None, bytes),
        }
    )

    try:
        cert_schema(data)

    except MultipleInvalid as err:
        raise OwnCAInvalidDataStructure("OwncaKeyData :" + str(err))


class OwncaCertData(object):
    """
    Generates Ownca Certificate Data Structure

    :param data: Certificate Data

       .. highlight:: python
       .. code-block:: python

        {
           "cert": cryptography.x509.Certificate,
           "cert_bytes": bytes,
           "csr": ``cryptography.x509._CertificateSigningRequest``
           "csr_bytes: bytes,
           "key": cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey,
           "key_bytes": bytes,
           "public_key":
            cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey,
           "public_key_bytes": bytes,
           "crl":
            cryptography.hazmat.backends.openssl.rsa._RSAPublicKey,
            "crl_bytes": bytes
        }
    :type data: dict

    :return: OwncaCertData
    :rtype: ``ownca.ownca.OwncaCertData``
    :raises: ``exceptions.OwnCAInvalidDataStructure``
    """

    def __init__(self, data):
        try:
            _validate_owncacertdata(data)

        except OwnCAInvalidDataStructure as err:
            raise err

        self.__dict__ = data
        self.data = data

    @property
    def cert(self):
        """
        Method to get the certificate

        :return: certificate
        :rtype: ``cryptography.x509.Certificate``
        """
        return self.data["cert"]

    @property
    def cert_bytes(self):
        """
        Method to get the certificate in ``bytes``

        :return: certificate
        :rtype: bytes
        """
        return self.data["cert_bytes"]

    @property
    def csr(self):
        """
        Method to get the certificate signing request if an Intermediate CA

        :return: csr
        :rtype: ``cryptography.x509._CertificateSigningRequest``
        """
        return self.data.get("csr")

    @property
    def csr_bytes(self):
        """
        Method to get the certificate signing request in bytes

        :return: csr
        :rtype: bytes
        """
        return self.data.get("csr_bytes")

    @property
    def key(self):
        """
        Method to get the key

        :return: key
        :rtype: ``cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey``
        """
        return self.data["key"]

    @property
    def key_bytes(self):
        """
        Method to get the key in ``bytes``

        :return: key
        :rtype: bytes
        """
        return self.data["key_bytes"]

    @property
    def public_key(self):
        """
        Method to get the public key

        :return: key
        :rtype: ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
        """
        return self.data["public_key"]

    @property
    def public_key_bytes(self):
        """
        Method to get the public key in ``bytes``

        :return: public key
        :rtype: bytes
        """
        return self.data["public_key_bytes"]

    @property
    def crl(self):
        """
        Method to get the certificate revocation list (crl)

        :return: certificate revocation list (crl)
        :rtype:
        ``cryptography.hazmat.backends.openssl.x509.\
        _CertificateRevocationList``
        """
        return self.data["crl"]

    @property
    def crl_bytes(self):
        """
        Method to get the certificate revocation list (crl)

        :return: certificate revocation list (crl)
        :rtype: bytes
        """
        return self.data["crl_bytes"]


def format_oids(oids_parameters):
    """
    Format dictionary OIDs to ``cryptography.x509.oid.NameOID`` object list

    :param oids_parameters: CA Object Identifiers (OIDs).
        The are typically seen in X.509 names.
        Allowed keys/values:
        ``'country_name': str (two letters)``,
        ``'locality_name': str``,
        ``'state_or_province': str``,
        ``'street_address': str``,
        ``'organization_name': str``,
        ``'organization_unit_name': str``,
        ``'email_address': str``,
    :type oids_parameters: dict, required
    :return: ``cryptography.x509.oid.NameOID`` object list
    :rtype: object ``cryptography.x509.oid.NameOID`` object list
    """
    oids = list()
    for oid in oids_parameters:
        if oid in OIDS:
            current_oid = oids_parameters[oid]
            if not current_oid:
                continue

            if type(current_oid) is not str:
                raise TypeError(f"'{oid}' must be str")

            if oid == "country_name":
                # country name ISO 3166-1 (alfa-2)
                if not re.match(COUNTRY_REGEX, current_oid):
                    raise OwnCAInvalidOID(
                        f"'{oid}' must be ISO 3166-1 (alfa-2)"
                    )

                else:
                    oids.append(
                        x509.NameAttribute(NameOID.COUNTRY_NAME, current_oid)
                    )

            elif oid == "locality_name":
                oids.append(
                    x509.NameAttribute(NameOID.LOCALITY_NAME, current_oid)
                )

            elif oid == "state_or_province":
                oids.append(
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, current_oid
                    )
                )

            elif oid == "street_address":
                oids.append(
                    x509.NameAttribute(NameOID.STREET_ADDRESS, current_oid)
                )

            elif oid == "organization_name":
                oids.append(
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, current_oid)
                )

            elif oid == "organization_unit_name":
                oids.append(
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, current_oid
                    )
                )

            elif oid == "email_address":
                oids.append(
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, current_oid)
                )

        else:
            raise OwnCAInvalidOID(
                f"The '{oid}' is Invalid. Allowed OIDs: {', '.join(OIDS)}."
            )

    return oids


def load_cert_files(
    common_name,
    key_file,
    public_key_file,
    csr_file,
    certificate_file,
    crl_file,
):
    """Loads the certificate, keys and revoked list files from storage

    :param common_name: Common Name for CA
    :type common_name: str, required when there is no CA
    :param key_file: key file full path
    :type key_file: str, required
    :param public_key_file: public key file full path
    :type public_key_file: str, required
    :param csr_file: certificate signing request file full path
    :type csr_file: str, required
    :param certificate_file: certificate file full path
    :type certificate_file: str, required
    :param crl_file: certificate revocation list file full path
    :type key_file: str, required

    :return: ``OwncaCertData``
    :raises: ``OwnCAInconsistentData``
    """

    # certificate signing request (if ICA)
    try:
        with open(csr_file, "rb") as csr_f:
            csr_data = csr_f.read()

        csr = x509.load_pem_x509_csr(csr_data, default_backend())
        csr_bytes = csr.public_bytes(encoding=serialization.Encoding.PEM)

    except FileNotFoundError:
        csr = None
        csr_bytes = None

    # certificate

    try:
        with open(certificate_file, "rb") as cert_f:
            cert_data = cert_f.read()

        certificate = x509.load_pem_x509_certificate(
            cert_data, default_backend()
        )
        current_cn_name = (
            certificate.subject.rfc4514_string().split("CN=")[-1].split(",")[0]
        )
        certificate_bytes = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    except FileNotFoundError:
        certificate = None
        certificate_bytes = None

    if common_name is not None and common_name != current_cn_name:
        raise OwnCAInconsistentData(
            "Initialized CN name does not match with current existent "
            + f"common_name: {current_cn_name}"
        )

    # key
    try:
        with open(key_file, "rb") as key_f:
            key_data = key_f.read()

        key = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )

        key_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    except FileNotFoundError:
        key = None
        key_bytes = None

    with open(public_key_file, "rb") as pub_key_f:
        pub_key_data = pub_key_f.read()

    public_key = serialization.load_ssh_public_key(
        pub_key_data, backend=default_backend()
    )

    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )

    # certificate revocation list (crl)
    # if there is not crl file it is created (backward compatible)
    try:
        with open(crl_file, "rb") as crl_f:
            crl_data = crl_f.read()

        crl = x509.load_pem_x509_crl(crl_data, default_backend())
        crl_bytes = crl.public_bytes(encoding=serialization.Encoding.PEM)

    except FileNotFoundError:
        if certificate is None:
            crl = None
            crl_bytes = None

        else:
            crl = ca_crl(
                ca_cert=certificate, ca_key=key, common_name=common_name
            )
            crl_bytes = crl.public_bytes(encoding=serialization.Encoding.PEM)

    return OwncaCertData(
        {
            "cert": certificate,
            "cert_bytes": certificate_bytes,
            "csr": csr,
            "csr_bytes": csr_bytes,
            "key": key,
            "key_bytes": key_bytes,
            "public_key": public_key,
            "public_key_bytes": public_key_bytes,
            "crl": crl,
            "crl_bytes": crl_bytes,
        }
    )


class CertificateAuthority:
    """The primary Python OWNCA class.

    This class initializes the Certificate Authority (CA).

    :param ca_storage: path where CA files and hosts files are stored. Default
        is the current directory (``os.getcwd()``)
    :type ca_storage: str, required when there is no CA
    :param common_name: Common Name for CA
    :type common_name: str, required when there is no CA
    :param dns_names: List of DNS names
    :type dns_names: list of strings, optional
    :param intermediate: Intermediate Certificate Authority mode
    :type intermediate: bool, default False
    :param oids: CA Object Identifiers (OIDs). The are typically seen
        in X.509 names.
        Allowed keys/values:
        ``'country_name': str (two letters)``,
        ``'locality_name': str``,
        ``'state_or_province': str``,
        ``'street_address': str``,
        ``'organization_name': str``,
        ``'organization_unit_name': str``,
        ``'email_address': str``,
    :type oids: dict, optional, all keys are optional
    :param public_exponent: Public Exponent
    :type public_exponent: int, default: 65537
    :param key_size: Key size
    :type key_size: int, default: 2048
    """

    def __init__(
        self,
        ca_storage=None,
        common_name=None,
        intermediate=False,
        maximum_days=825,
        **kwargs,
    ):
        """Constructor method"""

        public_exponent = kwargs.get("public_exponent", 65537)
        key_size = kwargs.get("key_size", 2048)

        if "oids" in kwargs:
            # TODO: Fox Issue #4
            warnings.warn(
                "The OIDS will be ignored ot CA. It is NOT working. Issue #4"
                + "Check out https://github.com/OwnCA/ownca/issues/4 ."
            )
            # self.oids = format_oids(kwargs["oids"])
            self.oids = list()

        else:
            self.oids = list()

        self._common_name = common_name
        if not ca_storage:
            self.ca_storage = os.getcwd()

        else:
            self.ca_storage = ca_storage

        try:
            self.current_ca_status = file_data_status(self.status)

        except OwnCAIntermediate:
            self.current_ca_status = True
            cert_data = self.initialize()
            self._update(cert_data)

            return

        if self.current_ca_status is True:
            cert_data = self.initialize()
            self._update(cert_data)

            current_cn_object = self._certificate.subject.rfc4514_string()
            self._common_name = current_cn_object.split("CN=")[-1]

        else:
            if self._common_name is None or type(self._common_name) is not str:
                raise TypeError(
                    "'common_name' is required parameter as string when "
                    + "there is no CA available."
                )

            cert_data = self.initialize(
                common_name=common_name,
                maximum_days=maximum_days,
                intermediate=intermediate,
                public_exponent=public_exponent,
                key_size=key_size,
            )
            self._update(cert_data)

    @property
    def status(self):
        """
        This method give the CA storage status

        :return: dict ``ownca.utils.ownca_directory``

        .. highlight:: python
        .. code-block:: python

            {
                "type": "Certificate Authority" or
                    "Intermediate Certificate Authority",
                "certificate": bool,
                "crl": bool,
                "csr": bool,
                "key": bool,
                "public_key": bool,
                "ca_home": None or str,
            }
        """
        return ownca_directory(self.ca_storage)

    @property
    def type(self):
        """
        This method give the Certificate Authority type
        'Certificate Authority' or 'Intermediate Certificate Authority'

        :return: str
        """
        if self.status.ca_type_intermediate is True:
            return "Intermediate Certificate Authority"
        else:
            return "Certificate Authority"

    @property
    def crl(self):
        """Get CA certificate revocation list (crl)

        :return: certificate class
        :rtype: class, ``cryptography.hazmat.backends.openssl.x509.\
            _CertificateRevocationList``
        """

        return self._crl

    @property
    def crl_bytes(self):
        """Get CA certificate revocation list (crl)

        :return: certificate class
        :rtype: bytes
        """

        return self._crl_bytes

    @property
    def csr(self):
        """Get CA Certificate Signing Request

        :return: certificate class
        :rtype: class, ``cryptography.hazmat.backends.openssl.x509.\
            _CertificateSigningRequest``
        """

        return self._csr

    @property
    def csr_bytes(self):
        """Get CA Certificate Signing Request in bytes

        :return: certificate class
        :rtype: bytes
        """

        return self._csr_bytes

    @property
    def cert(self):
        """Get CA certificate

        :return: certificate class
        :rtype: class,
            ``cryptography.hazmat.backends.openssl.x509.Certificate``
        """
        if (
            self._certificate is None
            and self.type == "Intermediate Certificate Authority"
        ):
            raise OwnCAIntermediate(
                "Intermediate Certificate Authority has not a signed "
                + "certificate file in CA Storage"
            )

        return self._certificate

    @property
    def cert_bytes(self):
        """Get CA certificate in bytes

        :return: certificate
        :rtype: bytes,
        """

        return self._certificate_bytes

    @property
    def key(self):
        """Get CA RSA Private key

        :return: RSA Private Key class
        :rtype: class,
            ``cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey``
        """
        return self._key

    @property
    def key_bytes(self):
        """Get CA RSA Private key in bytes

        :return: RSA Private Key
        :rtype: bytes
        """
        return self._key_bytes

    @property
    def public_key(self):
        """Get CA RSA Public key

        :return: RSA Public Key class
        :rtype: class,
            ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
        """
        return self._public_key

    @property
    def public_key_bytes(self):
        """Get CA RSA Public key in bytes

        :return: RSA Public Key class
        :rtype: bytes
        """
        return self._public_key_bytes

    @property
    def common_name(self):
        """
        Get CA common name

        :return: CA common name
        :rtype: str
        """

        return self._common_name

    @property
    def hash_name(self):
        """
        Get the CA hash name

        :return: CA hash name
        :rtype: str
        """

        return format(
            self._certificate._backend._lib.X509_NAME_hash(
                self._certificate._backend._lib.X509_get_issuer_name(
                    self._certificate._x509
                )
            ),
            "x",
        )

    @property
    def certificates(self):
        """
        Get the CA list of issued/managed certificates

        :return: List of certificates (default is host/domain)
        :rtype: list
        """

        host_cert_dir = os.path.join(self.ca_storage, CA_CERTS_DIR)
        certificate_list = list()

        for content in os.listdir(host_cert_dir):
            if not os.path.isdir(os.path.join(host_cert_dir, content)):
                continue
            certificate_list.append(content)

        return certificate_list

    def _update(self, cert_data):
        """
        Update certificate data in the instance.

        :param cert_data:
        :return: True
        """

        self._certificate = cert_data.cert
        self._certificate_bytes = cert_data.cert_bytes
        self._csr = cert_data.csr
        self._csr_bytes = cert_data.csr_bytes
        self._key = cert_data.key
        self._key_bytes = cert_data.key_bytes
        self._public_key = cert_data.public_key
        self._public_key_bytes = cert_data.public_key_bytes
        self._crl = cert_data.crl
        self._crl_bytes = cert_data.crl_bytes

    def initialize(
        self,
        common_name=None,
        dns_names=None,
        intermediate=False,
        maximum_days=825,
        public_exponent=65537,
        key_size=2048,
    ):
        """
        Initialize the Certificate Authority (CA)

        :param common_name: CA Common Name (CN)
        :type common_name: str, required
        :param dns_names: List of DNS names
        :type dns_names: list of strings, optional
        :param maximum_days: Certificate maximum days duration
        :type maximum_days: int, default: 825
        :param public_exponent: Public Exponent
        :type public_exponent: int, default: 65537
        :param intermediate: Intermediate Certificate Authority mode
        :type intermediate: bool, default False
        :param key_size: Key size
        :type key_size: int, default: 2048

        :return: tuple with CA certificate, CA Key and CA Public key
        :rtype: tuple (
            ``cryptography.x509.Certificate``,
            ``cryptography.hazmat.backends.openssl.rsa``,
            string public key
            )
        """

        private_ca_key_file = os.path.join(self.ca_storage, CA_KEY)
        public_ca_key_file = os.path.join(self.ca_storage, CA_PUBLIC_KEY)
        certificate_file = os.path.join(self.ca_storage, CA_CERT)
        csr_file = os.path.join(self.ca_storage, CA_CSR)
        crl_file = os.path.join(self.ca_storage, CA_CRL)

        if self.current_ca_status is True:
            cert_data = load_cert_files(
                common_name=common_name,
                key_file=private_ca_key_file,
                public_key_file=public_ca_key_file,
                csr_file=csr_file,
                certificate_file=certificate_file,
                crl_file=crl_file,
            )

            return cert_data

        elif self.current_ca_status is False:
            raise OwnCAInvalidFiles(self.status)

        elif self.current_ca_status is None:
            key = keys.generate(
                public_exponent=public_exponent, key_size=key_size
            )

            store_file(key.key_bytes, private_ca_key_file, False, None)
            store_file(key.public_key_bytes, public_ca_key_file, False, None)

            if intermediate is True:
                csr = issue_csr(
                    key=key.key,
                    common_name=common_name,
                    dns_names=dns_names,
                    oids=self.oids,
                )
                csr_bytes = csr.public_bytes(
                    encoding=serialization.Encoding.PEM
                )

                store_file(csr_bytes, csr_file, False, None)

                cert_data = OwncaCertData(
                    {
                        "cert": None,
                        "cert_bytes": None,
                        "csr": csr,
                        "csr_bytes": csr_bytes,
                        "key": key.key,
                        "key_bytes": key.key_bytes,
                        "public_key": key.public_key,
                        "public_key_bytes": key.public_key_bytes,
                        "crl": None,
                        "crl_bytes": None,
                    }
                )

                return cert_data

            certificate = issue_cert(
                self.oids,
                maximum_days=maximum_days,
                key=key.key,
                pem_public_key=key.public_key,
                common_name=common_name,
                dns_names=dns_names,
            )

            if not certificate:
                raise OwnCAFatalError(self.status)

            else:
                crl = ca_crl(
                    certificate,
                    ca_key=key.key,
                    common_name=common_name,
                )

                crl_bytes = crl.public_bytes(
                    encoding=serialization.Encoding.PEM
                )

                store_file(crl_bytes, crl_file, False, None)

                certificate_bytes = certificate.public_bytes(
                    encoding=serialization.Encoding.PEM
                )

                store_file(certificate_bytes, certificate_file, False, None)

                cert_data = OwncaCertData(
                    {
                        "cert": certificate,
                        "cert_bytes": certificate_bytes,
                        "key": key.key,
                        "key_bytes": key.key_bytes,
                        "public_key": key.public_key,
                        "public_key_bytes": key.public_key_bytes,
                        "crl": crl,
                        "crl_bytes": crl_bytes,
                    }
                )

                self._common_name = common_name
                self._update(cert_data)

                return cert_data

    def issue_certificate(
        self,
        hostname,
        maximum_days=825,
        common_name=None,
        dns_names=None,
        oids=None,
        public_exponent=65537,
        key_size=2048,
    ):
        """
        Issues a new certificate signed by the CA

        :param hostname: Hostname
        :type hostname: str, required
        :param maximum_days: Certificate maximum days duration
        :type maximum_days: int, default: 825
        :param common_name: Common Name (CN) when loading existent certificate
        :type common_name: str, optional
        :param dns_names: List of DNS names
        :type dns_names: list of strings, optional
        :param oids: CA Object Identifiers (OIDs). The are typically seen
            in X.509 names.
            Allowed keys/values:
            ``'country_name': str (two letters)``,
            ``'locality_name': str``,
            ``'state_or_province': str``,
            ``'street_address': str``,
            ``'organization_name': str``,
            ``'organization_unit_name': str``,
            ``'email_address': str``,
        :type oids: dict, optional, all keys are optional
        :param public_exponent: Public Exponent
        :type public_exponent: int, default: 65537
        :param key_size: Key size
        :type key_size: int, default: 2048
        :return: host object
        :rtype: ``ownca.ownca.HostCertificate``
        """
        if not validate_hostname(hostname):
            raise TypeError(
                "Invalid 'hostname'. Hostname must to be a string following "
                + f"the hostname rules r'{HOSTNAME_REGEX}'"
            )

        host_cert_dir = os.path.join(self.ca_storage, CA_CERTS_DIR, hostname)
        host_key_path = os.path.join(host_cert_dir, f"{hostname}.pem")
        host_public_path = os.path.join(host_cert_dir, f"{hostname}.pub")
        host_csr_path = os.path.join(host_cert_dir, f"{hostname}.csr")
        host_cert_path = os.path.join(host_cert_dir, f"{hostname}.crt")
        crl_file = os.path.join(self.ca_storage, CA_CRL)

        files = {
            "certificate": host_cert_path,
            "key": host_key_path,
            "public_key": host_public_path,
        }

        if common_name is None:
            common_name = hostname

        if os.path.isdir(host_cert_dir):
            cert_data = load_cert_files(
                common_name=common_name,
                key_file=host_key_path,
                public_key_file=host_public_path,
                csr_file=host_csr_path,
                certificate_file=host_cert_path,
                crl_file=crl_file,
            )

        else:
            os.mkdir(host_cert_dir)
            key_data = keys.generate(
                public_exponent=public_exponent, key_size=key_size
            )

            store_file(key_data.key_bytes, host_key_path, False, 0o600)
            store_file(
                key_data.public_key_bytes, host_public_path, False, None
            )

            if oids:
                oids = format_oids(oids)

            else:
                oids = list()

            csr = issue_csr(
                key=key_data.key,
                common_name=common_name,
                dns_names=dns_names,
                oids=oids,
            )

            store_file(
                csr.public_bytes(encoding=serialization.Encoding.PEM),
                host_csr_path,
                False,
                None,
            )

            certificate = ca_sign_csr(
                self.cert,
                self.key,
                csr,
                key_data.public_key,
                maximum_days=maximum_days,
            )
            certificate_bytes = certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            )

            store_file(certificate_bytes, host_cert_path, False, None)

            cert_data = OwncaCertData(
                {
                    "cert": certificate,
                    "cert_bytes": certificate_bytes,
                    "key": key_data.key,
                    "key_bytes": key_data.key_bytes,
                    "public_key": key_data.public_key,
                    "public_key_bytes": key_data.public_key_bytes,
                    "crl": self.crl,
                    "crl_bytes": self.crl_bytes,
                }
            )

        host = HostCertificate(common_name, files, cert_data)

        return host

    def load_certificate(self, hostname):
        """
        Loads an existent certificate.

        :param hostname: Hostname (common name)
        :type hostname: str, required
        :return: host object
        :rtype: ``ownca.ownca.HostCertificate``
        """
        host_cert_dir = os.path.join(self.ca_storage, CA_CERTS_DIR, hostname)
        if not os.path.isdir(host_cert_dir):
            raise OwnCAInvalidCertificate(
                f"The certificate does not exist for '{hostname}'."
            )

        return self.issue_certificate(hostname)

    def revoke_certificate(self, hostname, common_name=None):
        """
        Revokes an existent certificate owned by CA. It also updates the CA
        Certificate Revoked List.

        :param hostname: Hostname
        :type hostname: str, required
        :param common_name: Common Name (CN) when loading existent certificate
        :type common_name: str, optional
        :return: CA object
        :rtype: ``ownca.ownca.CertificateAuthority``
        """
        if not validate_hostname(hostname):
            raise TypeError(
                "Invalid 'hostname'. Hostname must to be a string following "
                + f"the hostname rules r'{HOSTNAME_REGEX}'"
            )

        certificate = self.load_certificate(hostname)

        if certificate.revoked:
            return None

        host_cert_dir = os.path.join(self.ca_storage, CA_CERTS_DIR, hostname)
        host_key_path = os.path.join(host_cert_dir, f"{hostname}.pem")
        host_csr_path = os.path.join(host_cert_dir, f"{hostname}.csr")
        host_public_path = os.path.join(host_cert_dir, f"{hostname}.pub")
        host_cert_path = os.path.join(host_cert_dir, f"{hostname}.crt")
        crl_file = os.path.join(self.ca_storage, CA_CRL)

        if common_name is None:
            common_name = hostname

        if not os.path.isdir(host_cert_dir):
            raise OwnCAInvalidCertificate(
                f"The certificate does not exist for '{hostname}'."
            )

        cert_data = load_cert_files(
            common_name=common_name,
            key_file=host_key_path,
            public_key_file=host_public_path,
            csr_file=host_csr_path,
            certificate_file=host_cert_path,
            crl_file=crl_file,
        )
        certificates_revoke = [revoked for revoked in self.crl]
        revoke_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(cert_data.cert.serial_number)
            .revocation_date(datetime.datetime.today())
            .build(default_backend())
        )

        certificates_revoke.append(revoke_cert)

        crl = ca_crl(
            self.cert,
            ca_key=self.key,
            common_name=common_name,
            certificates_revoke=certificates_revoke,
        )

        crl_bytes = crl.public_bytes(encoding=serialization.Encoding.PEM)

        ca_cert = OwncaCertData(
            {
                "cert": self.cert,
                "cert_bytes": self.cert_bytes,
                "key": self.key,
                "key_bytes": self.key_bytes,
                "public_key": self.public_key,
                "public_key_bytes": self.public_key_bytes,
                "crl": crl,
                "crl_bytes": crl_bytes,
            }
        )

        store_file(crl_bytes, crl_file, True, None)

        self._update(ca_cert)

    def sign_csr(self, csr, csr_public_key, maximum_days=825):
        """
        Signs an Certificate Sigining Request and generates the certificates.

        :param hostname: Hostname
        :type hostname: str, required
        :param csr: Certificate Signing Request Object
        :param csr: class, ``cryptography.hazmat.backends.openssl.x509.\
        _CertificateSigningRequest``
        :type csr_public_key: RSA Public Key class
        :rtype: class,
            ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
        :param maximum_days: Certificate maximum days duration
        :type maximum_days: int, default: 825
        :return: host object
        :rtype: ``ownca.ownca.CertificateAuthority``
        """
        csr_subject = csr.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        if csr_subject is not None or len(csr_subject) == 1:
            common_name = csr_subject[0].value

        csr_public_key_bytes = csr_public_key.public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        csr_bytes = csr.public_bytes(encoding=serialization.Encoding.PEM)
        host_cert_dir = os.path.join(
            self.ca_storage, CA_CERTS_DIR, common_name
        )

        certificate = ca_sign_csr(
            self.cert, self.key, csr, csr_public_key, maximum_days=maximum_days
        )

        os.mkdir(host_cert_dir)
        host_public_path = os.path.join(host_cert_dir, f"{common_name}.pub")
        host_csr_path = os.path.join(host_cert_dir, f"{common_name}.csr")
        host_cert_path = os.path.join(host_cert_dir, f"{common_name}.crt")

        store_file(csr_public_key_bytes, host_public_path, False, None)

        certificate_bytes = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

        store_file(certificate_bytes, host_cert_path, False, None)
        store_file(csr_bytes, host_csr_path, False, None)

        cert_data = OwncaCertData(
            {
                "cert": certificate,
                "cert_bytes": certificate_bytes,
                "key": None,
                "key_bytes": None,
                "public_key": csr_public_key,
                "public_key_bytes": csr_public_key_bytes,
                "crl": self.crl,
                "crl_bytes": self.crl_bytes,
            }
        )

        files = {
            "certificate": host_cert_path,
            "key": None,
            "public_key": host_public_path,
        }

        host = HostCertificate(common_name, files, cert_data)

        return host


class HostCertificate:
    """
    This class provide the host certificate methods.

    :param common_name: Host CN (Common Name), FQDN standard is required.
    :type common_name: str, required
    :param files: files path (certificate, key and public key) from host

        .. highlight:: python
        .. code-block:: python


            {
                "certificate": str,
                "key": str,
                "public_key": str,
            }

    :type files: dict, required
    :param cert_data: certificate data ``ownca.OwncaCertData``
    :type cert_data: object, required
    """

    def __init__(self, common_name, files, cert_data):
        """Host Certificate constructor method"""

        self._common_name = common_name
        self._files = files
        self.cert_data = cert_data
        self._revoked = (
            self.cert_data.crl.get_revoked_certificate_by_serial_number(
                self.cert_data.cert.serial_number
            )
        )

    @property
    def cert(self):
        """Get certificate

        :return: certificate object
        :rtype: object,
            ``cryptography.hazmat.backends.openssl.x509.Certificate``
        """

        return self.cert_data.cert

    @property
    def cert_bytes(self):
        """Get certificate in bytes

        :return: certificate
        :rtype: bytes,
        """

        return self.cert_data.cert_bytes

    @property
    def csr(self):
        """Get Certificate Signing Request

        :return: certificate class
        :rtype: class, ``cryptography.hazmat.backends.openssl.x509.\
            _CertificateSigningRequest``
        """

        return self.cert_data.csr

    @property
    def csr_bytes(self):
        """Get Certificate Signing Request in bytes

        :return: certificate class
        :rtype: bytes
        """

        return self.cert_data.csr_bytes

    @property
    def key(self):
        """Get RSA Private key

        :return: RSA Private Key class
        :rtype: object,
            ``cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey``
        """
        return self.cert_data.key

    @property
    def key_bytes(self):
        """Get RSA Private key in bytes

        :return: RSA Private Key
        :rtype: bytes
        """
        return self.cert_data.key_bytes

    @property
    def public_key(self):
        """Get RSA Public key

        :return: RSA Public Key class
        :rtype: object,
            ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
        """
        return self.cert_data.public_key

    @property
    def public_key_bytes(self):
        """Get RSA Public key in bytes

        :return: RSA Public Key class
        :rtype: bytes
        """
        return self.cert_data.public_key_bytes

    @property
    def common_name(self):
        """
        Get common name

        :return: common name
        :rtype: str
        """

        return self._common_name

    @property
    def revoked(self):
        """
        Get revoked state

        :return: True when revoked and False when valid.
        :rtype: str
        """
        if type(self._revoked) == _RevokedCertificate:

            return True

        else:

            return False
