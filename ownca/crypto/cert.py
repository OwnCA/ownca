from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
import uuid


def ca_certificate(
        oids,
        maximum_days=None,
        key=None,
        pem_public_key=None,
        ca_common_name=None,
        common_name=None,
        dns_names=None,
        host=False,
):
    if maximum_days is None or 1 < maximum_days > 3096:
        raise ValueError("Value is required: Minimum 1, Maximum 3096")
    oids.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    one_day = datetime.timedelta(1, 0, 0)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name(oids))
    if host:
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, ca_common_name
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


def issue_csr(key=None, common_name=None, dns_names=None, oids=None):
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
        x509.BasicConstraints(ca=True, path_length=None), critical=False
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


def ca_sign_csr(ca_cert, ca_key, csr, key, maximum_days=None):
    if maximum_days is None or 1 < maximum_days > 3096:
        raise ValueError("Value is required: Minimum 1, Maximum 3096")
    one_day = datetime.timedelta(1, 0, 0)

    certificate = x509.CertificateBuilder()
    certificate = certificate.subject_name(csr.subject)
    certificate = certificate.issuer_name(ca_cert.subject)
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
        extension=x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    certificate = certificate.add_extension(
        extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(
            key.public_key()
        ),
        critical=False,
    )
    certificate = certificate.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    if isinstance(certificate, x509.Certificate):
        return certificate

    else:
        return False
