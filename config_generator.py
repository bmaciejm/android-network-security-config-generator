import os
import sys

from colorama import Fore

from model import NetworkSecConfig, BaseConfig, Certificates, DomainConfig, Domain, PinSet, Pin, TrustAnchors, \
    DebugOverrides
import xml.etree.cElementTree as Et

BOLD = '\033[1m'
END = '\033[0m'


def hook(exception, *args):
    if exception is KeyboardInterrupt:
        print(Fore.RESET)
        exit()


def colored_input(text: str, color):
    sys.excepthook = hook
    user_input = input(text + color)
    print(Fore.RESET, end="", flush=True)
    sys.excepthook = sys.__excepthook__
    return user_input


def greenize(text):
    return f"{Fore.GREEN}{text}{Fore.RESET}"


def boldize(text):
    return f"{BOLD}{text}{END}"


def question_mark():
    return f"{greenize("?")}"


def cleartext_traffic(what):
    global_cleartext_traffic = colored_input(
        f"{question_mark()} {boldize(f"Do you want to enable cleartext traffic for {what}?")} (y/{boldize("N")}) ",
        Fore.CYAN)
    return global_cleartext_traffic.strip().lower() == "y"


def generate_trust_anchors():
    print(f"Available trust anchors options are: {boldize("\"user\", \"system\", \"@raw/{your_resource}\"")}")
    return colored_input("Enter trust anchors for secure connections: ", Fore.CYAN).replace(",", "")


def generate_domain_config():
    cleartext_traffic_on_domain = cleartext_traffic("DomainConfig")
    domain_config = DomainConfig(cleartext_traffic_on_domain)

    adding_domains = True
    while adding_domains:
        domain_name = colored_input(f"{question_mark()} {boldize("What domain do you want to add to pin for?")} ",
                                    Fore.CYAN)

        domain_include_subdomains = colored_input(
            f"{question_mark()} {boldize(f"Do you want include subdomains as well?")} ({boldize("Y")}/n) ", Fore.CYAN)

        domain = Domain(domain_name.strip(), domain_include_subdomains.strip().lower() != "n")

        domain_config.add_domain(domain)
        adding_domains = colored_input(
            f"{question_mark()} {boldize("Is there another domain you want to add?")} (y/{boldize("N")}) ",
            Fore.CYAN).strip().lower() == "y"

    trust_anchors_decision = colored_input(
        f"{question_mark()} {boldize("Do you want to provide trust anchors?")} ({boldize("Y")}/n) ", Fore.CYAN)

    if trust_anchors_decision.strip().lower() != "n":
        certificates = generate_trust_anchors().split()
        trust_anchors = TrustAnchors()
        for certificate in certificates:
            trust_anchors.add_certificate(Certificates(certificate))
        domain_config.add_trust_anchors(trust_anchors)

    pin_set_decision = colored_input(
        f"{question_mark()} {boldize(f"Do you want to add pin set ({greenize("https://developer.android.com/privacy-and-security/security-config#pin-set")})?")} ({boldize("Y")}/n) ",
        Fore.CYAN)

    if pin_set_decision.strip().lower() != "n":
        expiration_date = colored_input(
            f"{question_mark()} {boldize("First set expiration date for pin set or leave blank if pins should not expire:")} ",
            Fore.CYAN)
        if expiration_date:
            pin_set = PinSet(expiration=expiration_date)
        else:
            pin_set = PinSet()

        adding_pins = True
        while adding_pins:
            pin = Pin(colored_input(
                f"{boldize("Let's add a pin, it should be base64 encoded digest of X.509 SubjectPublicKeyInfo (SPKI)")}: ",
                Fore.CYAN))
            pin_set.add_pin(pin)
            adding_pins = colored_input(
                f"{question_mark()} {boldize("Do you want to add another pin?")} y/{boldize("N")} ",
                Fore.CYAN).strip().lower() == "y"
        domain_config.add_pin_set(pin_set)

    print("")
    adding_inner_domains = True
    inner_domain_decision = colored_input(
        f"{question_mark()} {boldize("Do you want to add nested domain config?")} (y/{boldize("N")}) ", Fore.CYAN)

    if inner_domain_decision.strip().lower() == "y":
        while adding_inner_domains:
            print("")
            print("Adding inner domain config...")
            inner_domain = generate_domain_config()
            domain_config.add_domain_config(inner_domain)

            adding_inner_domains = colored_input(
                f"{question_mark()} {boldize("Do you want to add another nested domain config?")} y/{boldize("N")} ",
                Fore.CYAN).strip().lower() == "y"
            if not adding_inner_domains:
                print("Leaving inner domain config...")

    return domain_config


def main():
    print("Welcome to the NetworkConfigGenerator!")
    print("")
    print("I will guide you through NetworkSecurityConfiguration generation.")
    print(
        f"Full config's documentation can be found here: \n{Fore.GREEN}https://developer.android.com/privacy-and-security/security-config{Fore.RESET}")

    print("")

    print(
        f"First, start with the basics -> Cleartext traffic ({greenize("https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted")})")
    global_cleartext_traffic = cleartext_traffic("whole app")

    if global_cleartext_traffic:
        config = NetworkSecConfig(True)
    else:
        config = NetworkSecConfig()

    print("")
    print(
        f"Next we'll setup BaseConfig ({greenize("https://developer.android.com/privacy-and-security/security-config#base-config")}).")

    # SECTION BASE CONFIG
    base_config_decision = colored_input(
        f"{question_mark()} {boldize("Do you want to add it")}? ({boldize("Y")}/n) ",
        Fore.CYAN)

    if base_config_decision.strip().lower() != "n":
        base_config_cleartext_traffic = cleartext_traffic("BaseConfig")

        print("")
        print(
            f"We will setup trust anchors for BaseConfig ({greenize("https://developer.android.com/privacy-and-security/security-config#trust-anchors")}).")

        certificates = generate_trust_anchors().split()

        base_config = BaseConfig(base_config_cleartext_traffic)
        for certificate in certificates:
            base_config.add_certificate(Certificates(certificate))
        config.add_base_config(base_config)

    print("")
    add_domains = colored_input(
        f"{question_mark()} {boldize("Do you want to add domain configs?")} ({boldize("Y")}/n) ",
        Fore.CYAN).strip().lower() != "n"
    print("")
    print(
        f"So, next we'll add all domain configs for pinning ({greenize("https://developer.android.com/privacy-and-security/security-config#domain-config")}).")
    print("")

    # SECTION DOMAIN CONFIGS
    all_domain_configs_added = False

    while not all_domain_configs_added and add_domains:
        domain_config = generate_domain_config()

        all_domain_configs_added = colored_input(
            f"{question_mark()} {boldize("Do you want to add another domain config?")} ({boldize("Y")}/n) ",
            Fore.CYAN).strip().lower() == "n"
        config.add_domain_config(domain_config)

    # SECTION DEBUG OVERRIDES
    print("")
    debug_overrides_decision = colored_input(
        f"{question_mark()} {boldize(f"Last question, do you want to add overrides for debug ({greenize("https://developer.android.com/privacy-and-security/security-config#TrustingDebugCa")})?")} ({boldize("Y")}/n) ",
        Fore.CYAN)

    if debug_overrides_decision.strip().lower() != "n":
        print("We'll setup trust anchors for Debug Overrides.")

        certificates = generate_trust_anchors().split()

        overrides = DebugOverrides()
        for certificate in certificates:
            overrides.add_certificate(Certificates(certificate))
        config.add_debug_overrides(overrides)

    file_path = colored_input(
        f"{question_mark()} {boldize("Great! Provide filepath where you want this config to be saved")}: ", Fore.CYAN)

    while not file_path:
        colored_input(f"{boldize("Without filepath config cannot be saved, provide one: ")}", Fore.CYAN)

    # section generate
    root_base = config.collect()
    tree = Et.ElementTree(root_base)
    Et.indent(tree, space='\t')
    tree.write(file_path, encoding="utf-8", xml_declaration=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
