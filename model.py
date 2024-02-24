import xml.etree.cElementTree as Et


class NetworkSecConfig:

    def __init__(self, cleartext_traffic_permitted=False):
        self.cleartext_traffic_permitted = cleartext_traffic_permitted
        self.base_config = None
        self.domain_configs = []
        self.debug_overrides = None

    def add_base_config(self, base_config):
        self.base_config = base_config

    def add_domain_config(self, domain_config):
        self.domain_configs.append(domain_config)

    def add_debug_overrides(self, overrides):
        self.debug_overrides = overrides

    def collect(self):
        if self.cleartext_traffic_permitted:
            root = Et.Element("network-security-config", cleartextTrafficPermitted="true")
        else:
            root = Et.Element("network-security-config")

        if self.base_config is not None:
            self.base_config.collect(root)
        for domain in self.domain_configs:
            domain.collect(root)
        if self.debug_overrides is not None:
            self.debug_overrides.collect(root)

        return root


class BaseConfig:

    def __init__(self, cleartext_traffic_permitted=False):
        self.cleartext_traffic = cleartext_traffic_permitted
        self.trust_anchor = TrustAnchors()

    def add_certificate(self, certificate):
        self.trust_anchor.add_certificate(certificate)

    def collect(self, parent):
        if self.cleartext_traffic:
            base_config = Et.SubElement(parent, "base-config", cleartextTrafficPermitted="true")
        else:
            base_config = Et.SubElement(parent, "base-config")
        self.trust_anchor.collect(base_config)
        return base_config


class DebugOverrides:
    def __init__(self):
        self.trust_anchor = TrustAnchors()

    def add_certificate(self, certificate):
        self.trust_anchor.add_certificate(certificate)

    def collect(self, parent):
        debug_overrides = Et.SubElement(parent, "debug-overrides")
        self.trust_anchor.collect(debug_overrides)
        return debug_overrides


class DomainConfig:

    def __init__(self, cleartext_traffic_permitted=False):
        self.cleartext_traffic_permitted = cleartext_traffic_permitted
        self.domains = []
        self.trust_anchors = None
        self.pin_set = None
        self.domain_configs = []

    def add_domain(self, domain):
        self.domains.append(domain)

    def add_trust_anchors(self, trust_anchors):
        self.trust_anchors = trust_anchors

    def add_pin_set(self, pin_set):
        self.pin_set = pin_set

    def add_domain_config(self, domain_config):
        self.domain_configs.append(domain_config)

    def collect(self, parent):
        domain_config = Et.SubElement(parent, "domain-config",
                                      cleartextTrafficPermitted=f"{str(self.cleartext_traffic_permitted).lower()}")

        for domain in self.domains:
            domain.collect(domain_config)

        if self.pin_set is not None:
            self.pin_set.collect(domain_config)
        if self.trust_anchors is not None:
            self.trust_anchors.collect(domain_config)

        for inner_domain_config in self.domain_configs:
            inner_domain_config.collect(domain_config)

        return domain_config


class PinSet:

    def __init__(self, expiration=None):
        self.pins = []
        self.expiration = expiration

    def add_pin(self, pin):
        self.pins.append(pin)

    def collect(self, parent):
        if not self.pins:
            return None

        if self.expiration is None:
            pin_set = Et.SubElement(parent, "pin-set")
        else:
            pin_set = Et.SubElement(parent, "pin-set", expiration=f"{self.expiration}")
        for pin in self.pins:
            pin.collect(pin_set)
        return pin_set


class Domain:

    def __init__(self, domain, include_subdomains):
        self.domain = domain
        self.include_subdomains = include_subdomains

    def collect(self, parent):
        domain = Et.SubElement(parent, "domain",
                               includeSubdomains=f"{str(self.include_subdomains).lower()}").text = f"{self.domain}"
        return domain


class TrustAnchors:

    def __init__(self):
        self.certificates = []

    def add_certificate(self, certificate):
        self.certificates.append(certificate)

    def collect(self, parent):
        anchors = Et.SubElement(parent, "trust-anchors")
        for cert in self.certificates:
            cert.collect(anchors)
        return anchors


class Certificates:

    def __init__(self, src, override_pins=False):
        self.src = src
        self.override_pins = override_pins

    def collect(self, parent):
        if self.override_pins:
            certificates = Et.SubElement(parent, "certificates", src=f"{self.src}",
                                         overridePins=f"{str(self.override_pins).lower()}")
        else:
            certificates = Et.SubElement(parent, "certificates", src=f"{self.src}")
        return certificates


class Pin:

    def __init__(self, pin):
        self.pin = pin
        self.digest = "SHA-256"

    def collect(self, parent):
        pin = Et.SubElement(parent, "pin", digest=f"{self.digest}").text = f"{self.pin}"
        return pin
