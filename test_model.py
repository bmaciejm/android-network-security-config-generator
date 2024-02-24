import unittest

from model import *


class MyTestCase(unittest.TestCase):

    def test_pin_created_correctly(self):
        pin = Pin("pindigest")
        self.assertEqual(pin.pin, "pindigest")
        self.assertEqual(pin.digest, "SHA-256")

        parent = Et.Element("pin-set")

        pin.collect(parent)

        digest = parent.find("pin").attrib["digest"]
        self.assertEqual(digest, "SHA-256")
        self.assertTrue(parent.find("pin").text == "pindigest")

    def test_pin_set_created_correctly(self):
        pin_set = PinSet(expiration="10-11-2026")
        self.assertEqual(pin_set.expiration, "10-11-2026")

        pin1 = Pin("pindigest")
        pin2 = Pin("pindigest2")

        pin_set.add_pin(pin1)
        pin_set.add_pin(pin2)

        self.assertEqual(len(pin_set.pins), 2)
        self.assertEqual(pin_set.pins[0], pin1)
        self.assertEqual(pin_set.pins[1], pin2)

        parent = Et.Element("domain-config")
        pin_set.collect(parent)

        pin_set_element = parent.find("pin-set")

        self.assertEqual(pin_set_element.attrib["expiration"], "10-11-2026")

        pins = pin_set_element.findall("pin")

        first_pin = pins[0]
        second_pin = pins[1]

        self.assertEqual(len(pins), 2)
        self.assertEqual(first_pin.text, "pindigest")
        self.assertEqual(second_pin.text, "pindigest2")

    def test_certificates_created_correctly(self):
        certificates = Certificates("user", override_pins=True)

        self.assertEqual(certificates.src, "user")
        self.assertEqual(certificates.override_pins, True)

        parent = Et.Element("trust-anchors")
        certificates.collect(parent)

        certificates_element = parent.find("certificates")

        self.assertEqual(certificates_element.attrib["src"], "user")
        self.assertEqual(certificates_element.attrib["overridePins"], "true")

    def test_trust_anchors_created_correctly(self):
        trust_anchors = TrustAnchors()
        self.assertEqual(len(trust_anchors.certificates), 0)

        certificates1 = Certificates("user")
        certificates2 = Certificates("system", True)

        trust_anchors.add_certificate(certificates1)
        trust_anchors.add_certificate(certificates2)

        self.assertEqual(len(trust_anchors.certificates), 2)

        parent = Et.Element("domain-config")

        trust_anchors.collect(parent)

        trust_anchors = parent.find("trust-anchors")

        certificates_elements = trust_anchors.findall("certificates")

        self.assertEqual(len(certificates_elements), 2)
        self.assertEqual(certificates_elements[0].attrib["src"], "user")
        self.assertEqual(certificates_elements[1].attrib["src"], "system")

    def test_domain_created_correctly(self):
        domain = Domain("www.example.com", include_subdomains=True)
        self.assertEqual(domain.domain, "www.example.com")
        self.assertEqual(domain.include_subdomains, True)

        parent = Et.Element("domain-config")

        domain.collect(parent)

        domain_element = parent.find("domain")

        self.assertEqual(domain_element.attrib["includeSubdomains"], "true")
        self.assertEqual(domain_element.text, "www.example.com")

    def test_domain_config_created_correctly(self):
        domain_config = DomainConfig(cleartext_traffic_permitted=True)

        self.assertEqual(domain_config.cleartext_traffic_permitted, True)
        self.assertEqual(len(domain_config.domain_configs), 0)
        self.assertEqual(len(domain_config.domains), 0)
        self.assertEqual(domain_config.trust_anchors, None)
        self.assertEqual(domain_config.pin_set, None)

        domain = Domain("www.example.com", True)
        trust_anchors = TrustAnchors()
        trust_anchors.add_certificate(Certificates("user"))
        pin_set = PinSet()
        pin_set.add_pin(Pin("pindigest"))

        inner_domain_config = DomainConfig()
        inner_domain_config.add_domain(Domain("www.inner.com", False))

        domain_config.add_domain(domain)
        domain_config.add_trust_anchors(trust_anchors)
        domain_config.add_pin_set(pin_set)
        domain_config.add_domain_config(inner_domain_config)

        self.assertEqual(len(domain_config.domains), 1)
        self.assertEqual(domain_config.domains[0], domain)
        self.assertEqual(len(domain_config.domain_configs), 1)
        self.assertEqual(domain_config.domain_configs[0], inner_domain_config)
        self.assertEqual(domain_config.pin_set, pin_set)

        parent = Et.Element("network-security-config")

        domain_config.collect(parent)

        domain_config_element = parent.find("domain-config")

        self.assertEqual(len(domain_config_element.findall("domain")), 1)
        self.assertEqual(len(domain_config_element.findall("trust-anchors")), 1)
        self.assertEqual(len(domain_config_element.findall("pin-set")), 1)
        self.assertEqual(len(domain_config_element.findall("domain-config")), 1)

    def test_debug_overrides_created_correctly(self):
        debug_overrides = DebugOverrides()

        self.assertNotEqual(debug_overrides.trust_anchor, None)

        certificate = Certificates("user")

        debug_overrides.add_certificate(certificate)

        self.assertEqual(len(debug_overrides.trust_anchor.certificates), 1)
        self.assertEqual(debug_overrides.trust_anchor.certificates[0], certificate)

        parent = Et.Element("network-security-config")

        debug_overrides.collect(parent)

        debug_overrides_element = parent.find("debug-overrides")

        trust_anchor_element = debug_overrides_element.find("trust-anchors")

        certificates_elements = trust_anchor_element.findall("certificates")

        self.assertEqual(len(certificates_elements), 1)
        self.assertEqual(certificates_elements[0].attrib["src"], "user")

    def test_base_config_created_correctly(self):
        base_config = BaseConfig(cleartext_traffic_permitted=True)
        self.assertEqual(base_config.cleartext_traffic, True)
        self.assertNotEqual(base_config.trust_anchor, None)

        certificate = Certificates("system")

        base_config.add_certificate(certificate)

        parent = Et.Element("network-security-config")

        self.assertEqual(len(base_config.trust_anchor.certificates), 1)
        self.assertEqual(base_config.trust_anchor.certificates[0], certificate)

        base_config.collect(parent)

        base_config = parent.find("base-config")
        trust_anchor = base_config.find("trust-anchors")
        certificates = trust_anchor.findall("certificates")

        self.assertEqual(base_config.attrib["cleartextTrafficPermitted"], "true")
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0].attrib["src"], "system")

    def test_network_config_created_correctly(self):
        network_config = NetworkSecConfig()
        self.assertEqual(network_config.cleartext_traffic_permitted, False)
        self.assertEqual(network_config.base_config, None)
        self.assertEqual(len(network_config.domain_configs), 0)
        self.assertEqual(network_config.debug_overrides, None)

        base_config = BaseConfig(cleartext_traffic_permitted=True)
        certificate = Certificates("system")

        network_config.add_base_config(base_config)

        self.assertEqual(network_config.base_config, base_config)

        base_config.add_certificate(certificate)

        domain_config = DomainConfig(cleartext_traffic_permitted=True)

        domain = Domain("www.example.com", True)
        trust_anchors = TrustAnchors()
        trust_anchors.add_certificate(Certificates("user"))
        pin_set = PinSet()
        pin_set.add_pin(Pin("pindigest"))

        domain_config.add_domain(domain)
        domain_config.add_trust_anchors(trust_anchors)
        domain_config.add_pin_set(pin_set)

        network_config.add_domain_config(domain_config)

        self.assertEqual(len(network_config.domain_configs), 1)
        self.assertEqual(network_config.domain_configs[0], domain_config)

        debug_overrides = DebugOverrides()

        certificate = Certificates("user")

        debug_overrides.add_certificate(certificate)

        network_config.add_debug_overrides(debug_overrides)

        self.assertEqual(network_config.debug_overrides, debug_overrides)

        network_config_element = network_config.collect()

        self.assertEqual(len(network_config_element.findall("debug-overrides")), 1)
        self.assertEqual(len(network_config_element.findall("base-config")), 1)
        self.assertEqual(len(network_config_element.findall("domain-config")), 1)


if __name__ == '__main__':
    unittest.main()
