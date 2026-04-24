#!/usr/bin/env python3
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


API_BASE = "https://api.cloudflare.com/client/v4"
HELP_EPILOG = """Examples:
  python3 mtls_cli.py zones
  python3 mtls_cli.py certificates --account-id ACCOUNT_ID
  python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem
  python3 mtls_cli.py associations --zone-name example.com --mtls-certificate-id CERT_ID
  python3 mtls_cli.py replace-associations --zone-name example.com --mtls-certificate-id CERT_ID --hostnames app.example.com api.example.com
"""
ZONES_EPILOG = """Examples:
  python3 mtls_cli.py zones
"""
CERTIFICATES_EPILOG = """Examples:
  python3 mtls_cli.py certificates --account-id ACCOUNT_ID
"""
UPLOAD_CERTIFICATE_EPILOG = """Examples:
  python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem
  python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem --name my-ca
"""
ASSOCIATIONS_EPILOG = """Examples:
  python3 mtls_cli.py associations --zone-name example.com --mtls-certificate-id CERT_ID
  python3 mtls_cli.py associations --zone-id ZONE_ID --mtls-certificate-id CERT_ID
"""
REPLACE_ASSOCIATIONS_EPILOG = """Examples:
  python3 mtls_cli.py replace-associations --zone-name example.com --mtls-certificate-id CERT_ID --hostnames app.example.com api.example.com
  python3 mtls_cli.py replace-associations --zone-id ZONE_ID --hostnames app.example.com api.example.com
"""
CERTIFICATE_ASSOCIATIONS_EPILOG = """Examples:
  python3 mtls_cli.py certificate-associations --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
"""
DELETE_CERTIFICATE_EPILOG = """Examples:
  python3 mtls_cli.py delete-certificate --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
"""


class HelpFormatter(argparse.RawTextHelpFormatter):
    pass


def load_dotenv() -> None:
    paths = [Path.cwd() / ".env", Path(__file__).resolve().with_name(".env")]
    seen = set()

    for env_path in paths:
        if env_path in seen or not env_path.is_file():
            continue
        seen.add(env_path)

        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or key in os.environ:
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]

            os.environ[key] = value


def require_value(value: str, message: str) -> str:
    value = (value or "").strip()
    if not value:
        raise SystemExit(message)
    return value


def parse_hostnames(values: list[str]) -> list[str]:
    hostnames = []
    for raw_value in values:
        for item in str(raw_value).split(","):
            item = item.strip()
            if item:
                hostnames.append(item)
    return hostnames


def api_request(api_token: str, method: str, path: str, verify: bool, params=None, body=None):
    url = f"{API_BASE}{path}"
    if params:
        filtered = {key: value for key, value in params.items() if value not in (None, "")}
        if filtered:
            url = f"{url}?{urllib.parse.urlencode(filtered, doseq=True)}"

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
        method=method,
    )

    context = ssl.create_default_context() if verify else ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(request, context=context, timeout=30.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        response_text = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Cloudflare HTTP error: {exc.code} {response_text}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Cloudflare request error: {exc.reason}") from exc

    if not payload.get("success"):
        errors = payload.get("errors") or []
        details = "; ".join(
            f"{item.get('code', 'error')}: {item.get('message', 'no message')}"
            for item in errors
        ) or "Cloudflare returned an unsuccessful response."
        raise SystemExit(f"Cloudflare API error: {details}")

    return payload.get("result")


def list_zones(api_token: str, verify: bool) -> list[dict]:
    zones = []
    page = 1

    while True:
        result = api_request(
            api_token,
            "GET",
            "/zones",
            verify,
            params={"page": page, "per_page": 50, "order": "name", "direction": "asc"},
        ) or []
        if not result:
            break
        zones.extend(result)
        if len(result) < 50:
            break
        page += 1

    return zones


def resolve_zone_id(api_token: str, verify: bool, zone_id: str, zone_name: str) -> tuple[str, str]:
    zone_id = (zone_id or "").strip()
    zone_name = (zone_name or "").strip()

    if bool(zone_id) == bool(zone_name):
        raise SystemExit("Provide exactly one of --zone-id or --zone-name.")

    if zone_id:
        zone = api_request(api_token, "GET", f"/zones/{zone_id}", verify)
        return zone["id"], zone["name"]

    for zone in list_zones(api_token, verify):
        if str(zone.get("name") or "").strip().lower() == zone_name.lower():
            return zone["id"], zone["name"]

    raise SystemExit(f"Zone '{zone_name}' was not found among the zones accessible to the token.")


def print_zones(zones: list[dict]) -> None:
    if not zones:
        print("No zones found.")
        return

    print(f"{'ZONE ID':<36} {'STATUS':<10} NAME")
    for zone in zones:
        print(f"{zone.get('id', ''):<36} {zone.get('status', ''):<10} {zone.get('name', '')}")


def print_certificates(certificates: list[dict]) -> None:
    if not certificates:
        print("No mTLS certificates found.")
        return

    print(f"{'CERTIFICATE ID':<36} {'TYPE':<16} {'CA':<4} {'EXPIRES':<21} NAME")
    for certificate in certificates:
        ca = "Yes" if certificate.get("ca") else "No"
        print(
            f"{certificate.get('id', ''):<36} "
            f"{certificate.get('type', ''):<16} "
            f"{ca:<4} "
            f"{certificate.get('expires_on', ''):<21} "
            f"{certificate.get('name', '')}"
        )


def print_certificate(certificate: dict) -> None:
    print(f"Certificate ID: {certificate.get('id', '-')}")
    print(f"Name: {certificate.get('name', '-')}")
    print(f"Type: {certificate.get('type', '-')}")
    print(f"CA: {'Yes' if certificate.get('ca') else 'No'}")
    print(f"Issuer: {certificate.get('issuer', '-')}")
    print(f"Serial Number: {certificate.get('serial_number', '-')}")
    print(f"Uploaded On: {certificate.get('uploaded_on', '-')}")
    print(f"Updated At: {certificate.get('updated_at', '-')}")
    print(f"Expires On: {certificate.get('expires_on', '-')}")


def print_hostnames(hostnames: list[str]) -> None:
    if not hostnames:
        print("No hostname associations found.")
        return

    for hostname in hostnames:
        print(hostname)


def print_certificate_services(items: list[dict]) -> None:
    if not items:
        print("No active certificate associations found.")
        return

    print(f"{'SERVICE':<24} STATUS")
    for item in items:
        print(f"{item.get('service', ''):<24} {item.get('status', '')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage Cloudflare mTLS certificates and hostname associations.",
        epilog=HELP_EPILOG,
        formatter_class=HelpFormatter,
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv("CLOUDFLARE_API_TOKEN", "").strip(),
        help="Cloudflare API token. Also accepts CLOUDFLARE_API_TOKEN.",
    )
    parser.add_argument("--insecure", action="store_true", help="Ignore SSL validation.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    zones_parser = subparsers.add_parser(
        "zones",
        help="List zones accessible to the token.",
        epilog=ZONES_EPILOG,
        formatter_class=HelpFormatter,
    )
    zones_parser.add_argument("--name-contains", default="", help="Optional text filter for zone names.")

    certificates_parser = subparsers.add_parser(
        "certificates",
        help="List certificates.",
        epilog=CERTIFICATES_EPILOG,
        formatter_class=HelpFormatter,
    )
    certificates_parser.add_argument("--account-id", required=True, help="Cloudflare account ID.")

    certificate_parser = subparsers.add_parser(
        "certificate",
        help="Get one certificate.",
        formatter_class=HelpFormatter,
    )
    certificate_parser.add_argument("--account-id", required=True, help="Cloudflare account ID.")
    certificate_parser.add_argument("--mtls-certificate-id", required=True, help="mTLS certificate ID.")

    upload_parser = subparsers.add_parser(
        "upload-certificate",
        help="Upload a PEM bundle.",
        epilog=UPLOAD_CERTIFICATE_EPILOG,
        formatter_class=HelpFormatter,
    )
    upload_parser.add_argument("--account-id", required=True, help="Cloudflare account ID.")
    upload_parser.add_argument("--bundle", required=True, help="Path to the PEM bundle file.")
    upload_parser.add_argument("--name", default="", help="Optional certificate name.")
    upload_parser.add_argument("--leaf", action="store_true", help="Upload as a leaf certificate.")

    associations_parser = subparsers.add_parser(
        "associations",
        help="List hostname associations.",
        epilog=ASSOCIATIONS_EPILOG,
        formatter_class=HelpFormatter,
    )
    associations_parser.add_argument("--zone-id", default="", help="Cloudflare zone ID.")
    associations_parser.add_argument("--zone-name", default="", help="Zone name. Example: example.com")
    associations_parser.add_argument("--mtls-certificate-id", default="", help="mTLS certificate ID.")

    replace_parser = subparsers.add_parser(
        "replace-associations",
        help="Replace hostname associations.",
        epilog=REPLACE_ASSOCIATIONS_EPILOG,
        formatter_class=HelpFormatter,
    )
    replace_parser.add_argument("--zone-id", default="", help="Cloudflare zone ID.")
    replace_parser.add_argument("--zone-name", default="", help="Zone name. Example: example.com")
    replace_parser.add_argument("--mtls-certificate-id", default="", help="mTLS certificate ID.")
    replace_parser.add_argument("--hostnames", nargs="+", required=True, help="Hostnames separated by space.")

    certificate_associations_parser = subparsers.add_parser(
        "certificate-associations",
        help="List certificate associations.",
        epilog=CERTIFICATE_ASSOCIATIONS_EPILOG,
        formatter_class=HelpFormatter,
    )
    certificate_associations_parser.add_argument("--account-id", required=True, help="Cloudflare account ID.")
    certificate_associations_parser.add_argument("--mtls-certificate-id", required=True, help="mTLS certificate ID.")

    delete_parser = subparsers.add_parser(
        "delete-certificate",
        help="Delete one certificate.",
        epilog=DELETE_CERTIFICATE_EPILOG,
        formatter_class=HelpFormatter,
    )
    delete_parser.add_argument("--account-id", required=True, help="Cloudflare account ID.")
    delete_parser.add_argument("--mtls-certificate-id", required=True, help="mTLS certificate ID.")

    return parser


def main() -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    api_token = require_value(args.api_token, "Provide --api-token or set CLOUDFLARE_API_TOKEN.")
    verify = not args.insecure

    if args.command == "zones":
        zones = list_zones(api_token, verify)
        filter_text = args.name_contains.strip().lower()
        if filter_text:
            zones = [zone for zone in zones if filter_text in str(zone.get("name") or "").lower()]
        print_zones(zones)
        return 0

    if args.command == "certificates":
        certificates = api_request(
            api_token,
            "GET",
            f"/accounts/{args.account_id}/mtls_certificates",
            verify,
            params={"per_page": 50},
        ) or []
        print_certificates(certificates)
        return 0

    if args.command == "certificate":
        certificate = api_request(
            api_token,
            "GET",
            f"/accounts/{args.account_id}/mtls_certificates/{args.mtls_certificate_id}",
            verify,
        )
        print_certificate(certificate)
        return 0

    if args.command == "upload-certificate":
        bundle_path = Path(args.bundle)
        if not bundle_path.is_file():
            raise SystemExit(f"Bundle file not found: {bundle_path}")

        body = {
            "ca": not args.leaf,
            "certificates": bundle_path.read_text(encoding="utf-8"),
        }
        if args.name.strip():
            body["name"] = args.name.strip()

        certificate = api_request(
            api_token,
            "POST",
            f"/accounts/{args.account_id}/mtls_certificates",
            verify,
            body=body,
        )
        print("Certificate uploaded successfully:")
        print_certificate(certificate)
        return 0

    if args.command == "certificate-associations":
        items = api_request(
            api_token,
            "GET",
            f"/accounts/{args.account_id}/mtls_certificates/{args.mtls_certificate_id}/associations",
            verify,
            params={"per_page": 50},
        ) or []
        print_certificate_services(items)
        return 0

    if args.command == "delete-certificate":
        certificate = api_request(
            api_token,
            "DELETE",
            f"/accounts/{args.account_id}/mtls_certificates/{args.mtls_certificate_id}",
            verify,
        )
        print("Certificate deleted successfully:")
        print_certificate(certificate)
        return 0

    zone_id, zone_name = resolve_zone_id(api_token, verify, args.zone_id, args.zone_name)

    if args.command == "associations":
        params = {}
        if args.mtls_certificate_id.strip():
            params["mtls_certificate_id"] = args.mtls_certificate_id.strip()
        result = api_request(
            api_token,
            "GET",
            f"/zones/{zone_id}/certificate_authorities/hostname_associations",
            verify,
            params=params,
        )
        print(f"Zone: {zone_name} ({zone_id})")
        print_hostnames(list(result.get("hostnames") or []))
        return 0

    if args.command == "replace-associations":
        hostnames = parse_hostnames(args.hostnames)
        if not hostnames:
            raise SystemExit("Provide at least one hostname in --hostnames.")

        body = {"hostnames": hostnames}
        if args.mtls_certificate_id.strip():
            body["mtls_certificate_id"] = args.mtls_certificate_id.strip()

        result = api_request(
            api_token,
            "PUT",
            f"/zones/{zone_id}/certificate_authorities/hostname_associations",
            verify,
            body=body,
        )
        print(f"Zone: {zone_name} ({zone_id})")
        print("Hostname associations updated successfully:")
        print_hostnames(list(result.get("hostnames") or []))
        return 0

    raise SystemExit(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
