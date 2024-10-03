# OwnCA - Python Certificate Authority Management

[![Build Status](https://github.com/OwnCA/ownca/workflows/Tests/badge.svg)](https://github.com/OwnCA/ownca/actions?query=workflow%3ATests)
[![Documentation Status](https://readthedocs.org/projects/ownca/badge/?version=latest)](https://ownca.readthedocs.io/en/latest/?badge=latest)
[![codecov](https://codecov.io/gh/OwnCA/ownca/branch/master/graph/badge.svg)](https://codecov.io/gh/OwnCA/ownca)
[![PyPI Version](https://img.shields.io/pypi/v/ownca.svg)](https://pypi.python.org/pypi/ownca)
[![PyPI Downloads](https://img.shields.io/pypi/dm/ownca)](https://pypistats.org/packages/ownca)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

### THIS PROJECT IS OPEN FOR MAINTAINERS

> Development on the OwnCA project has stagnated for a while.
> For that reason, I'm opening the organization to new maintainers who will have the proper permissions to jumpstart development.
>
> Those willing to join, contact me by email with the subject `[OwnCA Maintainer] <your name>` and please let me know what
> motivates you to join in such a role.

---

OwnCA is a Python library that simplifies the creation, management, and distribution of digital certificates. It acts as a full Certificate Authority (CA) for managing all your certificates and can automate the process of generating secure SSL/TLS certificates for servers and clients.

## Features

- Create and manage your own Certificate Authority (CA)
- Issue and revoke certificates for servers and clients
- Automatically sign certificate requests (CSRs)
- Easy-to-use Python API for automating certificate creation

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Creating a Certificate Authority](#creating-a-certificate-authority)
  - [Generating Server Certificates](#generating-server-certificates)
  - [Generating Client Certificates](#generating-client-certificates)
  - [Revoking Certificates](#revoking-certificates)
- [Configuration](#configuration)
- [Development](#development)
  - [Preparing the Environment](#preparing-the-environment)
  - [Installing & Enabling Pre-commit](#installing--enabling-pre-commit)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- Python 3.6 or higher
- `cryptography` library (used for cryptographic functions)

```bash
pip install ownca
```

## Quick Start

### Creating a Certificate Authority

To initialize a Certificate Authority (CA), you need to specify a storage path and a common name (CN) for your CA. The `CertificateAuthority` class handles the generation of CA keys and certificates.

```python
from ownca import CertificateAuthority

# Initialize the CA
ca = CertificateAuthority(
    ca_storage="/etc/my-ca",
    common_name="my-ca",
    maximum_days=365  # Valid for one year
)
print("CA has been created.")
```

This will generate a CA certificate and private key, which will be used to sign certificates for your servers and clients.

### Generating Server Certificates

For each server in your service that needs SSL/TLS certificates, you can issue a server certificate as follows:

```python
nodes = ["server1", "server2", "server3"]

for node in nodes:
    ca.issue_certificate(
        hostname=node,
        common_name=f"{node}.example.com",  # Adjust with your actual domain
        dns_names=[f"{node}.example.com"],
        maximum_days=365
    )
    print(f"Certificate for {node} issued.")
```

Each server will have its own certificate stored in `/etc/my-ca/certs/`.

### Generating Client Certificates

Client certificates are needed for secure client-server communication. Here’s how you can generate client certificates:

```python
client_common_name = "my-client"
ca.issue_certificate(
    hostname=client_common_name,
    common_name=client_common_name,
    dns_names=[client_common_name],
    maximum_days=180  # Valid for 6 months
)
print("Client certificate has been issued.")
```

### Revoking Certificates

In case you need to revoke a certificate (e.g., a server has been decommissioned), use the following:

```python
ca.revoke_certificate("server1")
print("Certificate for server1 has been revoked.")
```

## Configuration

- **Certificate Authority Storage**: All certificates and keys are stored in the directory specified in the `ca_storage` parameter.
- **Maximum Certificate Validity**: The `maximum_days` parameter determines how long certificates are valid (e.g., 365 days for one year).
- **DNS Names**: Ensure to pass appropriate DNS names while issuing certificates to secure multiple domains.

Example directory structure:

```
/etc/my-ca/
├── certs/
│   ├── server1/
│   │   ├── server1.crt
│   │   ├── server1.pem
│   │   └── server1.pub
├── ca.crt
├── ca_key.pem
└── ca_key.pub
```

## Development

### Preparing the Environment

```shell
git clone git@github.com:OwnCA/ownca.git
cd ownca
pipenv shell
pipenv install -d
```

In case you have macOS M1:

```shell
pip uninstall cryptography cffi
LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi cryptography rust --no-binary :all:
```

### Installing & Enabling Pre-commit

To automatically run checks before you commit your changes, you should install the git hook scripts with **pre-commit**:

```shell
pre-commit install
pre-commit autoupdate
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

To contribute:

1. Fork this repository
2. Create a new branch
3. Commit your changes
4. Submit a pull request

For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.