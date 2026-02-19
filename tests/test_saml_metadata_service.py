import json

from services.saml_metadata_service import parse_metadata_xml, validate_attribute_mapping


def test_validate_attribute_mapping_accepts_valid_mapping():
    mapping = json.dumps(
        [
            {
                "source_field": "email",
                "saml_name": "email",
                "required": True,
                "multi_valued": False,
                "transform": "identity",
            },
            {
                "source_field": "events",
                "saml_name": "groups",
                "required": False,
                "multi_valued": True,
                "transform": "identity",
            },
        ]
    )

    valid, error = validate_attribute_mapping(mapping)
    assert valid is True
    assert error is None


def test_validate_attribute_mapping_accepts_name_split_transforms():
    mapping = [
        {
            "source_field": "legal_name",
            "saml_name": "firstName",
            "required": True,
            "multi_valued": False,
            "transform": "first_word",
        },
        {
            "source_field": "legal_name",
            "saml_name": "lastName",
            "required": True,
            "multi_valued": False,
            "transform": "rest_words",
        },
    ]

    valid, error = validate_attribute_mapping(mapping)
    assert valid is True
    assert error is None


def test_validate_attribute_mapping_rejects_duplicate_names():
    mapping = [
        {
            "source_field": "email",
            "saml_name": "email",
            "required": True,
            "multi_valued": False,
            "transform": "identity",
        },
        {
            "source_field": "preferred_name",
            "saml_name": "email",
            "required": False,
            "multi_valued": False,
            "transform": "identity",
        },
    ]

    valid, error = validate_attribute_mapping(mapping)
    assert valid is False
    assert "Duplicate saml_name" in error


def test_parse_metadata_xml_extracts_core_fields_and_certs():
    xml = """
    <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://sp.example.com/metadata\">
      <md:SPSSODescriptor AuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">
        <md:KeyDescriptor use=\"signing\">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>ABCDEF123456</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sp.example.com/acs\" index=\"0\" isDefault=\"true\"/>
        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://sp.example.com/slo\"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>
    """

    parsed = parse_metadata_xml(xml)

    assert parsed["saml_entity_id"] == "https://sp.example.com/metadata"
    assert parsed["saml_acs_url"] == "https://sp.example.com/acs"
    assert parsed["saml_slo_url"] == "https://sp.example.com/slo"
    assert parsed["saml_require_signed_authn_request"] is True
    assert json.loads(parsed["saml_sp_signing_certs_json"]) == ["ABCDEF123456"]
