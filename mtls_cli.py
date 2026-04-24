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
from typing import Any


API_BASE = "https://api.cloudflare.com/client/v4"
HELP_EPILOG = """Examples:
  python3 mtls_cli.py zones
  python3 mtls_cli.py certificates --account-id ACCOUNT_ID
  python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem --name my-ca
  python3 mtls_cli.py associations --zone-name example.com --mtls-certificate-id CERT_ID
  python3 mtls_cli.py replace-associations --zone-name example.com --mtls-certificate-id CERT_ID --hostnames app.example.com api.example.com
  python3 mtls_cli.py certificate-associations --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID

Credentials:
  - the script accepts --api-token
  - it also accepts CLOUDFLARE_API_TOKEN
  - it also loads a .env file automatically
"""
ZONES_EPILOG = """Examples:
  python3 mtls_cli.py zones
"""
CERTIFICATES_EPILOG = """Examples:
  python3 mtls_cli.py certificates --account-id ACCOUNT_ID
  python3 mtls_cli.py certificates --account-id ACCOUNT_ID --type custom
"""
UPLOAD_CERTIFICATE_EPILOG = """Examples:
  python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem
  python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem --name my-ca
"""
ASSOCIATIONS_EPILOG = """Examples:
  python3 mtls_cli.py associations --zone-name example.com --mtls-certificate-id CERT_ID
  python3 mtls_cli.py associations --zone-id ZONE_ID

Zone selection:
  Provide exactly one of --zone-id or --zone-name.
"""
REPLACE_ASSOCIATIONS_EPILOG = """Examples:
  python3 mtls_cli.py replace-associations --zone-name example.com --mtls-certificate-id CERT_ID --hostnames app.example.com api.example.com
  python3 mtls_cli.py replace-associations --zone-id ZONE_ID --hostnames service.example.com

Notes:
  - this replaces the full hostname association list for the target certificate
  - provide exactly one of --zone-id or --zone-name
"""
CERTIFICATE_ASSOCIATIONS_EPILOG = """Examples:
  python3 mtls_cli.py certificate-associations --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
"""
DELETE_CERTIFICATE_EPILOG = """Examples:
  python3 mtls_cli.py delete-certificate --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
"""


class HelpFormatter(argparse.RawTextHelpFormatter):
    pass


class CloudflareAPIError(RuntimeError):
    pass


class CloudflareHTTPError(RuntimeError):
    def __init__(self, status_code: int, response_text: str):
        super().__init__(f"{status_code} {response_text}")
        self.status_code = status_code
        self.response_text = response_text


class CloudflareRequestError(RuntimeError):
    pass


class CloudflareClient:
    def __init__(self, api_token: str, verify: bool):
        self.api_token = api_token
        self.verify = verify
        self.ssl_context = ssl.create_default_context() if verify else ssl._create_unverified_context()

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{API_BASE}{path}"
        filtered_params = {
            key: value
            for key, value in (params or {}).items()
            if value is not None and value != ""
        }
        if filtered_params:
            url = f"{url}?{urllib.parse.urlencode(filtered_params, doseq=True)}"

        payload = None
        if json_body is not None:
            payload = json.dumps(json_body).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            },
            method=method,
        )

        try:
            with urllib.request.urlopen(request, context=self.ssl_context, timeout=30.0) as response:
                raw_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            raise CloudflareHTTPError(exc.code, response_text) from exc
        except urllib.error.URLError as exc:
            raise CloudflareRequestError(str(exc.reason)) from exc

        if not raw_body:
            return None

        return json.loads(raw_body)


def load_dotenv() -> None:
    candidate_paths = [Path.cwd() / ".env", Path(__file__).resolve().with_name(".env")]
    seen_paths: set[Path] = set()

    for env_path in candidate_paths:
        if env_path in seen_paths or not env_path.is_file():
            continue
        seen_paths.add(env_path)

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
            if not key or key in os.environ:
                continue

            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]

            os.environ[key] = value


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
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for API requests.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    zones_parser = subparsers.add_parser(
        "zones",
        help="List zones accessible to the token.",
        description="List the zones accessible to the current token.",
        epilog=ZONES_EPILOG,
        formatter_class=HelpFormatter,
    )
    zones_parser.add_argument(
        "--name-contains",
        default="",
        help="Optional case-insensitive filter for zone names.",
    )

    certificates_parser = subparsers.add_parser(
        "certificates",
        help="List mTLS certificates for an account.",
        description="List mTLS certificates uploaded to an account.",
        epilog=CERTIFICATES_EPILOG,
        formatter_class=HelpFormatter,
    )
    add_account_id_argument(certificates_parser)
    certificates_parser.add_argument(
        "--type",
        default="",
        help="Optional certificate type filter. Examples: custom, gateway_managed, access_managed.",
    )

    certificate_parser = subparsers.add_parser(
        "certificate",
        help="Get a single mTLS certificate.",
        description="Fetch a single mTLS certificate by ID.",
        formatter_class=HelpFormatter,
    )
    add_account_id_argument(certificate_parser)
    add_certificate_id_argument(certificate_parser)

    import_parser = subparsers.add_parser(
        "upload-certificate",
        aliases=["import-bundle"],
        help="Upload a CA bundle as an mTLS certificate.",
        description="Upload a PEM bundle to Cloudflare mTLS Certificate Management.",
        epilog=UPLOAD_CERTIFICATE_EPILOG,
        formatter_class=HelpFormatter,
    )
    add_account_id_argument(import_parser)
    import_parser.add_argument("--bundle", required=True, help="Path to a PEM bundle file.")
    import_parser.add_argument("--name", default="", help="Optional human-readable certificate name.")
    import_parser.add_argument(
        "--leaf",
        action="store_true",
        help="Upload as a leaf certificate. Default behavior uploads as CA.",
    )

    associations_parser = subparsers.add_parser(
        "associations",
        help="List hostname associations for a zone.",
        description="List hostname associations for a zone and optional mTLS certificate ID.",
        epilog=ASSOCIATIONS_EPILOG,
        formatter_class=HelpFormatter,
    )
    add_zone_selection_arguments(associations_parser)
    associations_parser.add_argument(
        "--mtls-certificate-id",
        default="",
        help="Optional certificate ID. If omitted, Cloudflare uses the active managed CA.",
    )
    associations_parser.add_argument(
        "--hostnames",
        nargs="+",
        default=[],
        help="Optional hostnames to verify against the current association list.",
    )

    set_associations_parser = subparsers.add_parser(
        "replace-associations",
        aliases=["set-associations"],
        help="Replace hostname associations for a zone.",
        description="Replace the hostname association list for a zone and certificate.",
        epilog=REPLACE_ASSOCIATIONS_EPILOG,
        formatter_class=HelpFormatter,
    )
    add_zone_selection_arguments(set_associations_parser)
    set_associations_parser.add_argument(
        "--mtls-certificate-id",
        default="",
        help="Optional certificate ID. If omitted, Cloudflare uses the active managed CA.",
    )
    set_associations_parser.add_argument(
        "--hostnames",
        nargs="+",
        required=True,
        help="Hostnames to associate. Accepts space-separated and comma-separated values.",
    )

    services_parser = subparsers.add_parser(
        "certificate-associations",
        aliases=["services"],
        help="List Cloudflare services using a certificate.",
        description="List active associations between an mTLS certificate and Cloudflare services.",
        epilog=CERTIFICATE_ASSOCIATIONS_EPILOG,
        formatter_class=HelpFormatter,
    )
    add_account_id_argument(services_parser)
    add_certificate_id_argument(services_parser)

    delete_parser = subparsers.add_parser(
        "delete-certificate",
        help="Delete an mTLS certificate from an account.",
        description="Delete an mTLS certificate if it is no longer in use.",
        epilog=DELETE_CERTIFICATE_EPILOG,
        formatter_class=HelpFormatter,
    )
    add_account_id_argument(delete_parser)
    add_certificate_id_argument(delete_parser)

    return parser


def add_account_id_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--account-id", required=True, help="Cloudflare account ID.")


def add_certificate_id_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mtls-certificate-id", required=True, help="mTLS certificate ID.")


def add_zone_selection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--zone-id", default="", help="Cloudflare zone ID.")
    parser.add_argument("--zone-name", default="", help="Zone name. Example: example.com")


def require_value(value: str, message: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise SystemExit(message)
    return normalized


def parse_csv_arguments(values: list[str]) -> list[str]:
    parsed_values: list[str] = []
    for raw_value in values:
        for item in str(raw_value).split(","):
            normalized = item.strip()
            if normalized:
                parsed_values.append(normalized)
    return parsed_values


def make_client(api_token: str, verify: bool) -> CloudflareClient:
    return CloudflareClient(api_token=api_token, verify=verify)


def api_request(client: CloudflareClient, method: str, path: str, **kwargs: Any) -> Any:
    payload = client.request(
        method,
        path,
        params=kwargs.get("params"),
        json_body=kwargs.get("json"),
    )
    if not payload.get("success"):
        errors = payload.get("errors") or []
        details = "; ".join(
            f"{item.get('code', 'error')}: {item.get('message', 'no message')}"
            for item in errors
        ) or "Cloudflare returned an unsuccessful response."
        raise CloudflareAPIError(details)
    return payload.get("result")


def list_zones(client: CloudflareClient, name_contains: str = "") -> list[dict[str, Any]]:
    zones: list[dict[str, Any]] = []
    page = 1
    normalized_filter = name_contains.strip().lower()

    while True:
        result = api_request(
            client,
            "GET",
            "/zones",
            params={
                "page": page,
                "per_page": 50,
                "order": "name",
                "direction": "asc",
            },
        )
        if not result:
            break
        zones.extend(result)
        if len(result) < 50:
            break
        page += 1

    if normalized_filter:
        zones = [
            zone
            for zone in zones
            if normalized_filter in str(zone.get("name") or "").strip().lower()
        ]
    return zones


def resolve_zone(client: CloudflareClient, zone_id: str, zone_name: str) -> dict[str, str]:
    normalized_zone_id = zone_id.strip()
    normalized_zone_name = zone_name.strip()
    selectors = sum([bool(normalized_zone_id), bool(normalized_zone_name)])
    if selectors != 1:
        raise SystemExit("Provide exactly one of --zone-id or --zone-name.")

    if normalized_zone_id:
        zone = api_request(client, "GET", f"/zones/{normalized_zone_id}")
        return {"id": zone["id"], "name": zone["name"]}

    zones = list_zones(client)
    matches = [
        zone for zone in zones if str(zone.get("name") or "").strip().lower() == normalized_zone_name.lower()
    ]
    if not matches:
        raise SystemExit(f"Zone '{normalized_zone_name}' was not found among the zones accessible to the token.")
    if len(matches) > 1:
        raise SystemExit(f"More than one zone named '{normalized_zone_name}' was found.")
    return {"id": matches[0]["id"], "name": matches[0]["name"]}


def list_certificates(client: CloudflareClient, account_id: str, certificate_type: str = "") -> list[dict[str, Any]]:
    certificates: list[dict[str, Any]] = []
    page = 1
    params: dict[str, Any] = {"per_page": 50}
    if certificate_type.strip():
        params["type"] = certificate_type.strip()

    while True:
        params["page"] = page
        result = api_request(
            client,
            "GET",
            f"/accounts/{account_id}/mtls_certificates",
            params=params,
        )
        if not result:
            break
        certificates.extend(result)
        if len(result) < 50:
            break
        page += 1

    return certificates


def get_certificate(client: CloudflareClient, account_id: str, mtls_certificate_id: str) -> dict[str, Any]:
    return api_request(
        client,
        "GET",
        f"/accounts/{account_id}/mtls_certificates/{mtls_certificate_id}",
    )


def import_bundle(
    client: CloudflareClient,
    account_id: str,
    bundle_path: str,
    name: str,
    is_ca: bool,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    if not bundle.is_file():
        raise SystemExit(f"Bundle file was not found: {bundle}")

    payload: dict[str, Any] = {
        "ca": is_ca,
        "certificates": bundle.read_text(encoding="utf-8"),
    }
    normalized_name = name.strip()
    if normalized_name:
        payload["name"] = normalized_name

    return api_request(
        client,
        "POST",
        f"/accounts/{account_id}/mtls_certificates",
        json=payload,
    )


def delete_certificate(client: CloudflareClient, account_id: str, mtls_certificate_id: str) -> dict[str, Any]:
    return api_request(
        client,
        "DELETE",
        f"/accounts/{account_id}/mtls_certificates/{mtls_certificate_id}",
    )


def list_hostname_associations(
    client: CloudflareClient,
    zone_id: str,
    mtls_certificate_id: str,
) -> list[str]:
    params: dict[str, Any] = {}
    if mtls_certificate_id.strip():
        params["mtls_certificate_id"] = mtls_certificate_id.strip()
    result = api_request(
        client,
        "GET",
        f"/zones/{zone_id}/certificate_authorities/hostname_associations",
        params=params,
    )
    return list(result.get("hostnames") or [])


def replace_hostname_associations(
    client: CloudflareClient,
    zone_id: str,
    mtls_certificate_id: str,
    hostnames: list[str],
) -> list[str]:
    payload: dict[str, Any] = {"hostnames": hostnames}
    if mtls_certificate_id.strip():
        payload["mtls_certificate_id"] = mtls_certificate_id.strip()
    result = api_request(
        client,
        "PUT",
        f"/zones/{zone_id}/certificate_authorities/hostname_associations",
        json=payload,
    )
    return list(result.get("hostnames") or [])


def list_certificate_services(
    client: CloudflareClient,
    account_id: str,
    mtls_certificate_id: str,
) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    page = 1

    while True:
        result = api_request(
            client,
            "GET",
            f"/accounts/{account_id}/mtls_certificates/{mtls_certificate_id}/associations",
            params={"page": page, "per_page": 50},
        )
        if not result:
            break
        services.extend(result)
        if len(result) < 50:
            break
        page += 1

    return services


def format_bool(value: Any) -> str:
    return "Yes" if bool(value) else "No"


def print_zones(zones: list[dict[str, Any]]) -> None:
    if not zones:
        print("No zones found.")
        return
    print(f"{'ZONE ID':<36} {'STATUS':<10} NAME")
    for zone in zones:
        print(f"{zone.get('id', ''):<36} {zone.get('status', ''):<10} {zone.get('name', '')}")


def print_certificates(certificates: list[dict[str, Any]]) -> None:
    if not certificates:
        print("No mTLS certificates found.")
        return
    print(f"{'CERTIFICATE ID':<36} {'TYPE':<16} {'CA':<4} {'EXPIRES':<21} NAME")
    for certificate in certificates:
        print(
            f"{certificate.get('id', ''):<36} "
            f"{certificate.get('type', ''):<16} "
            f"{format_bool(certificate.get('ca')):<4} "
            f"{certificate.get('expires_on', ''):<21} "
            f"{certificate.get('name', '')}"
        )


def print_certificate(certificate: dict[str, Any]) -> None:
    print(f"Certificate ID: {certificate.get('id', '-')}")
    print(f"Name: {certificate.get('name', '-')}")
    print(f"Type: {certificate.get('type', '-')}")
    print(f"CA: {format_bool(certificate.get('ca'))}")
    print(f"Issuer: {certificate.get('issuer', '-')}")
    print(f"Serial Number: {certificate.get('serial_number', '-')}")
    print(f"Signature: {certificate.get('signature', '-')}")
    print(f"Uploaded On: {certificate.get('uploaded_on', '-')}")
    print(f"Updated At: {certificate.get('updated_at', '-')}")
    print(f"Expires On: {certificate.get('expires_on', '-')}")


def print_hostnames(hostnames: list[str]) -> None:
    if not hostnames:
        print("No hostname associations found.")
        return
    for index, hostname in enumerate(hostnames, start=1):
        print(f"{index:>2}. {hostname}")


def print_service_associations(services: list[dict[str, Any]]) -> None:
    if not services:
        print("No active Cloudflare service associations found.")
        return
    print(f"{'SERVICE':<24} STATUS")
    for service in services:
        print(f"{service.get('service', ''):<24} {service.get('status', '')}")


def verify_requested_hostnames(current_hostnames: list[str], requested_hostnames: list[str]) -> None:
    normalized_current = set(current_hostnames)
    for hostname in requested_hostnames:
        if hostname in normalized_current:
            print(f"[ok] {hostname} is associated.")
        else:
            print(f"[missing] {hostname} is not associated.")


def main() -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    api_token = require_value(args.api_token, "Provide --api-token or set CLOUDFLARE_API_TOKEN.")
    verify = not args.insecure

    try:
        client = make_client(api_token, verify=verify)

        if args.command == "zones":
            print_zones(list_zones(client, args.name_contains))
            return 0

        if args.command == "certificates":
            certificates = list_certificates(client, args.account_id, args.type)
            print_certificates(certificates)
            return 0

        if args.command == "certificate":
            certificate = get_certificate(client, args.account_id, args.mtls_certificate_id)
            print_certificate(certificate)
            return 0

        if args.command in {"upload-certificate", "import-bundle"}:
            certificate = import_bundle(
                client,
                args.account_id,
                args.bundle,
                args.name,
                is_ca=not args.leaf,
            )
            print("mTLS certificate uploaded successfully:")
            print_certificate(certificate)
            return 0

        if args.command == "delete-certificate":
            certificate = delete_certificate(client, args.account_id, args.mtls_certificate_id)
            print("mTLS certificate deleted successfully:")
            print_certificate(certificate)
            return 0

        if args.command in {"certificate-associations", "services"}:
            services = list_certificate_services(client, args.account_id, args.mtls_certificate_id)
            print_service_associations(services)
            return 0

        zone = resolve_zone(client, args.zone_id, args.zone_name)

        if args.command == "associations":
            hostnames = list_hostname_associations(client, zone["id"], args.mtls_certificate_id)
            print(f"Zone: {zone['name']} ({zone['id']})")
            if args.mtls_certificate_id.strip():
                print(f"mTLS Certificate ID: {args.mtls_certificate_id.strip()}")
            print_hostnames(hostnames)
            requested_hostnames = parse_csv_arguments(args.hostnames)
            if requested_hostnames:
                verify_requested_hostnames(hostnames, requested_hostnames)
            return 0

        if args.command in {"replace-associations", "set-associations"}:
            hostnames = parse_csv_arguments(args.hostnames)
            if not hostnames:
                raise SystemExit("Provide at least one hostname in --hostnames.")
            updated_hostnames = replace_hostname_associations(
                client,
                zone["id"],
                args.mtls_certificate_id,
                hostnames,
            )
            print(f"Zone: {zone['name']} ({zone['id']})")
            if args.mtls_certificate_id.strip():
                print(f"mTLS Certificate ID: {args.mtls_certificate_id.strip()}")
            print("Hostname associations updated successfully:")
            print_hostnames(updated_hostnames)
            return 0

        raise SystemExit(f"Unsupported command: {args.command}")
    except CloudflareHTTPError as exc:
        print(f"Cloudflare HTTP error: {exc.status_code} {exc.response_text}", file=sys.stderr)
        return 1
    except CloudflareRequestError as exc:
        print(f"Cloudflare request error: {exc}", file=sys.stderr)
        return 1
    except CloudflareAPIError as exc:
        print(f"Cloudflare API error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
