#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018, 2019 Kairo de Araujo
"""


from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
import os
import re
import uuid


from ._constants import (
    CA_CERT,
    CA_CERTS_DIR,
    CA_KEY,
    CA_PUBLIC_KEY,
    COUNTRY_REGEX,
    HOSTNAME_REGEX,
    OIDS
)
from .exceptions import InconsistentCertificateData, InvalidCAFiles, InvalidOID
from .utils import (
    ownca_directory,
    file_data_status,
    validate_hostname,
    store_file,
)


def format_oids(oids_parameters):
    """
    Format dictionary OIDs to ``cryptography.x509.oid.NameOID`` object list

    :param oids_parameters: oids ``CertificateAuthority``
    :type oids_parameters: dict, required
    :return: ``cryptography.x509.oid.NameOID`` object list
    :rtype: object ``cryptography.x509.oid.NameOID`` object list
    """

    oids = list()
    for oid in OIDS:
        if oid in oids_parameters:
            current_oid = oids_parameters[oid]
            if type(current_oid) is not str:
                raise TypeError(f"\'{oid}\' must be str")

            if oid == "country_name":
                # country name ISO 3166-1 (alfa-2)
                if not re.match(COUNTRY_REGEX, current_oid):
                    raise InvalidOID(f"\'{oid}\' must be ISO 3166-1 (alfa-2)")

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

    return oids


class CertificateAuthority:
    """The primary Python OWNCA class.

    This class initializes the Certificate Authority (CA).


    :param ca_storage: path where CA files and hosts files are stored. Default
        is None ``os.getcwd()``
    :type ca_storage: str, required when there is no CA
    :param common_name: Common Name for CA
    :type common_name: str, required when there is no CA
    :param dns_names: List of DNS names
    :type dns_names: list of strings, optional
    :param oids: CA Object Identifiers (OIDs). The are typically seen in
        X.509 names.
        Allowed keys/values:
        ``'country_name': str (two letters)``,
        ``'locality_name': str``,
        ``'state_or_province': str``,
        ``'street_address': str``,
        ``'organization_name': str``,
        ``'organization_unit_name': str``,
        ``'email_address': str``,
    :type oids: dict, optional, all keys are optional
    """

    def __init__(self, ca_storage=None, common_name=None, **kwargs):
        """Constructor method"""

        if "oids" in kwargs:
            self.oids = format_oids(kwargs["oids"])

        else:
            self.oids = list()

        self._common_name = common_name
        if not ca_storage:
            self.ca_storage = os.getcwd()

        else:
            self.ca_storage = ca_storage

        self.current_ca_status = file_data_status(self.status)

        if self.current_ca_status is True:

            self._certificate, self._key, self._public_key = self.initialize()
            current_cn_object = self._certificate.subject.rfc4514_string()
            self._common_name = current_cn_object.split("CN=")[-1]

        else:
            if self._common_name is None or type(self._common_name) is not str:
                raise TypeError(
                    "'common_name' is required parameter as string when "
                    + "there is no CA available."
                )

            self._certificate, self._key, self._public_key = self.initialize(
                common_name=common_name
            )

    @property
    def status(self):
        """
        This method give the CA storage status

        :return: dict ``_utils.ownca_directory``

        .. highlight:: python
        .. code-block:: python

            {
                'certificate': bool,
                "key": bool,
                "public_key": bool,
                "ca_home": None or str,
            }
        """
        return ownca_directory(self.ca_storage)

    @property
    def get_certificate(self):
        """Get CA certificate

        :return: certificate class
        :rtype: class,
            ``cryptography.hazmat.backends.openssl.x509.Certificate``
        """

        return self._certificate

    @property
    def get_key(self):
        """Get CA RSA Private key

        :return: RSA Private Key class
        :rtype: class,
            ``cryptography.hazmat.backends.openssl.rsa.RSAPrivateKey``
        """
        return self._key

    @property
    def get_public_key(self):
        """Get CA RSA Public key

        :return: RSA Public Key class
        :rtype: class,
            ``cryptography.hazmat.backends.openssl.rsa.RSAPublicKey``
        """
        return self._public_key

    @property
    def get_common_method(self):
        """
        Get CA common name

        :return: CA common name
        :rtype: str
        """

        return self._common_name

    @staticmethod
    def generate_key(public_exponent=65537, key_size=2048):
        """
        Generates Private and Public keys

        :param public_exponent: Public Exponent
        :type public_exponent: int, optional, Default: 65537
        :param key_size: Key size
        :type key_size: int, optional, Default: 2048
        :return: RSA Private Key class, Private key bytes,
            RSA Public Key classes, Public key bytes
        :rtype: tuple, (
            ``cryptography.hazmat.backends.openssl.rsa.RSAPrivateKey``,
            Private key bytes,
            ``cryptography.hazmat.backends.openssl.rsa.RSAPublicKey``,
            Public key bytes
            )
        """
        key = rsa.generate_private_key(
            backend=default_backend(),
            public_exponent=public_exponent,
            key_size=key_size,
        )

        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        pem_public_key = key.public_key()

        public_key = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )

        return key, private_key, pem_public_key, public_key

    def _ca_certificate(
        self,
        maximum_days=None,
        key=None,
        pem_public_key=None,
        common_name=None,
        dns_names=None,
        host=False,
    ):

        if maximum_days is None or 1 < maximum_days > 3096:
            raise ValueError("Value is required: Minimum 1, Maximum 3096")
        self.oids.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

        one_day = datetime.timedelta(1, 0, 0)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name(self.oids))
        if host:
            builder = builder.issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, self._common_name
                        )
                    ]
                )
            )
        else:
            builder = builder.issuer_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
                )
            )
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(
            datetime.datetime.today() + (one_day * maximum_days)
        )
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(pem_public_key)

        if dns_names is not None:
            if type(dns_names) is not list:
                raise TypeError("dns_names require a list of strings.")

            if len(dns_names) != 0:
                if all(isinstance(item, str) for item in dns_names):
                    x509_dns_names = []
                    for dns_name in dns_names:
                        x509_dns_names.append(x509.DNSName(dns_name))
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(x509_dns_names),
                        critical=False,
                    )

                else:
                    raise TypeError("All DNS Names must to be string values.")

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

        certificate = builder.sign(
            private_key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        if isinstance(certificate, x509.Certificate):
            return certificate

        else:
            return False

    def _csr(self, key=None, common_name=None, dns_names=None, oids=None):

        csr_builder = x509.CertificateSigningRequestBuilder()

        oids.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        csr_builder = csr_builder.subject_name(x509.Name(oids))

        if dns_names is not None:
            if type(dns_names) is not list:
                raise TypeError("dns_names require a list of strings.")

            if len(dns_names) != 0:
                if all(isinstance(item, str) for item in dns_names):
                    x509_dns_names = []
                    for dns_name in dns_names:
                        x509_dns_names.append(x509.DNSName(dns_name))
                    csr_builder = csr_builder.add_extension(
                        x509.SubjectAlternativeName(x509_dns_names),
                        critical=False,
                    )

                else:
                    raise TypeError("All DNS Names must to be string values.")

        csr_builder = csr_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        csr = csr_builder.sign(
            private_key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        if isinstance(csr, x509.CertificateSigningRequest):
            return csr

        else:
            return False

    def _ca_sign_csr(self, csr, key, maximum_days=None):
        if maximum_days is None or 1 < maximum_days > 3096:
            raise ValueError("Value is required: Minimum 1, Maximum 3096")
        one_day = datetime.timedelta(1, 0, 0)

        certificate = x509.CertificateBuilder()
        certificate = certificate.subject_name(csr.subject)
        certificate = certificate.issuer_name(self._certificate.subject)
        certificate = certificate.public_key(csr.public_key())
        certificate = certificate.serial_number(uuid.uuid4().int)
        certificate = certificate.not_valid_before(
            datetime.datetime.today() - one_day
        )
        certificate = certificate.not_valid_after(
            datetime.datetime.today() + (one_day * maximum_days)
        )
        certificate = certificate.add_extension(
            extension=x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False,
            ),
            critical=True,
        )
        certificate = certificate.add_extension(
            extension=x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        certificate = certificate.add_extension(
            extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(
                key.public_key()
            ),
            critical=False,
        )
        certificate = certificate.sign(
            private_key=self._key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        if isinstance(certificate, x509.Certificate):
            return certificate

        else:
            return False

    @staticmethod
    def _write_csr_crt(**kwargs):
        try:
            certificate = kwargs["certificate"]
            certificate_file = kwargs["certificate_file"]

        except KeyError as err:
            raise err

        with open(certificate_file, "wb") as f:
            f.write(
                certificate.public_bytes(encoding=serialization.Encoding.PEM)
            )

    @staticmethod
    def _load_cert_keys(**kwargs):
        try:
            common_name = kwargs["common_name"]
            key_file = kwargs["key_file"]
            public_key_file = kwargs["public_key_file"]
            certificate_file = kwargs["certificate_file"]

        except KeyError as err:
            missed_key = str(err).split(": ")[-1]
            raise KeyError(f"The missing parameter {missed_key} is required.")

        with open(certificate_file, "rb") as cert_f:
            cert_data = cert_f.read()

        certificate = x509.load_pem_x509_certificate(
            cert_data, default_backend()
        )

        current_cn_name = certificate.subject.rfc4514_string().split("CN=")[-1]

        if common_name is not None and common_name != current_cn_name:
            raise InconsistentCertificateData(
                "Initialized CN name does not match with current existent "
                + f"common_name: {current_cn_name}"
            )

        with open(key_file, "rb") as key_f:
            key_data = key_f.read()

        key = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )

        with open(public_key_file, "rb") as pub_key_f:
            pub_key_data = pub_key_f.read()

        public_key = serialization.load_ssh_public_key(
            pub_key_data, backend=default_backend()
        )

        return certificate, key, public_key

    def initialize(
        self,
        common_name=None,
        dns_names=None,
        maximum_days=30,
        public_exponent=65537,
        key_size=2048,
        force=False,
        **kwargs,
    ):
        """
        Initialize the Certificate Authority (CA)

        :param common_name: CA Common Name (CN)
        :type common_name: str, required
        :param dns_names:
        :param maximum_days:
        :param public_exponent:
        :param key_size:
        :param force:
        :param kwargs:
        :return:
        """
        private_ca_key_file = f"{self.ca_storage}/{CA_KEY}"
        public_ca_key_file = f"{self.ca_storage}/{CA_PUBLIC_KEY}"
        certificate_file = f"{self.ca_storage}/{CA_CERT}"

        if self.current_ca_status:
            return self._load_cert_keys(
                common_name=common_name,
                key_file=private_ca_key_file,
                public_key_file=public_ca_key_file,
                certificate_file=certificate_file,
            )

        elif self.current_ca_status is False:
            raise InvalidCAFiles(self.status)

        elif self.current_ca_status is None:
            if common_name is None or type(common_name) is not str:
                raise TypeError(
                    "'common_name' is required parameter as string when "
                    + "there is no CA available."
                )

            key, private_key, pem_public_key, public_key = self.generate_key(
                public_exponent=public_exponent, key_size=key_size
            )

            store_file(private_key, private_ca_key_file, permission=0o600)
            store_file(public_key, public_ca_key_file)

            certificate = self._ca_certificate(
                maximum_days=maximum_days,
                key=key,
                pem_public_key=pem_public_key,
                common_name=common_name,
                dns_names=dns_names,
            )

            if certificate:
                store_file(
                    certificate.public_bytes(
                        encoding=serialization.Encoding.PEM
                    ),
                    certificate_file,
                )

            self._common_name = common_name
            self._key = key
            self._certificate = certificate
            self._public_key = public_key

            return self._certificate, self._key, self._public_key

        else:
            raise TypeError(self.status)

    def issue_certificate(
        self, hostname, maximum_days=30, common_name=None, dns_names=None,
        oids=None
    ):

        if not validate_hostname(hostname):
            raise TypeError(
                "Invalid 'hostname'. Hostname must to be a string following "
                + f"the hostname rules r'{HOSTNAME_REGEX}'"
            )

        host_cert_dir = f"{self.ca_storage}/{CA_CERTS_DIR}/{hostname}"
        host_key_path = f"{host_cert_dir}/{hostname}.pem"
        host_public_path = f"{host_cert_dir}/{hostname}.pub"
        host_csr_path = f"{host_cert_dir}/{hostname}.csr"
        host_cert_path = f"{host_cert_dir}/{hostname}.crt"

        files = {
            "certificate": host_cert_path,
            "key": host_key_path,
            "public_key": host_public_path,
        }

        if common_name is None:
            common_name = hostname

        if os.path.isdir(host_cert_dir):
            certificate, host_key, host_public_key = self._load_cert_keys(
                common_name=common_name,
                key_file=host_key_path,
                public_key_file=host_public_path,
                certificate_file=host_cert_path,
            )

        else:
            os.mkdir(host_cert_dir)

            key, host_key, host_pem_public_key, host_public_key = (
                self.generate_key()
            )

            store_file(host_key, host_key_path, permission=0o600)
            store_file(host_public_key, host_public_path)

            if oids:
                oids = format_oids(oids)

            else:
                oids = list()

            csr = self._csr(
                key=key, common_name=common_name, dns_names=dns_names,
                oids=oids
            )

            store_file(
                csr.public_bytes(encoding=serialization.Encoding.PEM),
                host_csr_path,
            )

            certificate = self._ca_sign_csr(
                csr, key, maximum_days=maximum_days
            )

            store_file(
                certificate.public_bytes(encoding=serialization.Encoding.PEM),
                host_cert_path,
            )

        host = HostCertificate(
            common_name, files, certificate, host_key, host_public_key
        )

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
    :param certificate: certificate data ``self._ca_sign_certificate`` from
        ``cryptography.hazmat.backends.openssl.x509.Certificate``
    :type certificate: class, required
    :param key: private pem key bytes
    :type key: bytes, required
    :param public_key: public key bytes
    :type public_key: bytes, required
    """

    def __init__(self, common_name, files, certificate, key, public_key):
        """HostCertificate constructor method"""

        self._common_name = common_name
        self._files = files
        self._certificate = certificate
        self._key = key
        self._public_key = public_key

    @property
    def get_certificate(self):
        """Get host certificate"""

        return self._certificate

    @property
    def get_key(self):
        """Get host key"""

        return self._key

    @property
    def get_public_key(self):
        """Get host public_key"""

        return self._public_key

    @property
    def get_common_method(self):
        """Get host common name"""

        return self._common_name
