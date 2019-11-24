#
# Copyright (c) 2019 Kairo de Araujo
#
import pytest

from ownca.ownca import CertificateAuthority


class TestCertificateAuthority:

    with pytest.raises(TypeError):
        assert CertificateAuthority() == (
            "'common_name' is required parameter as string when there is no CA"
            "available."
        )

    test_oids = {
        "country_name": "BR",
        "locality_name": "Uba",
        "state_or_province": "Minas Gerais",
        "street_address": "Rua Agostinho Martins de Oliveira",
        "organization_name": "First home",
        "organization_unit_name": "Good memories",
        "email_address": "kairo at gmail.com"
    }

    with pytest.raises(TypeError):
        assert CertificateAuthority() == (
            "'common_name' is required parameter as string when there is no CA"
            "available."
        )
