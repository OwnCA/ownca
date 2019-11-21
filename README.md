# Python OwnCA

Python OwnCA allows you to handle a Certificate Authority (CA), using existent 
keys and certificates or generate a new set of certificate for your CA.

Python OwnCA also issues certificates for hosts, also the possibility to revoke
existent certificates is possible.

## Installation

pip install ownca

```pycon
>> from ownca import CertificateAuthority
>> 
>> ca = CertificateAuthority(ownca_home="/etc/ssl/CA", ca="My Own CA")
>> ca_certificate = ca.get_ca_certificate()
>> myserver = ca.generate_host_certificate("myserver", dns_names=["myserver.com", "ssl.myserver.com"]
>> myserver.get_key()
>> myserver.get_certificates()
```

