# Cloudflare mTLS CLI

Python CLI for managing Cloudflare mTLS certificates and hostname associations.

## Overview

The script can:

- list zones accessible to the token
- list mTLS certificates for an account
- fetch a single certificate by ID
- upload a PEM bundle to Cloudflare mTLS Certificate Management
- list hostname associations for a zone
- replace hostname associations for a zone
- list Cloudflare services currently using a certificate
- delete a certificate when it is no longer in use

## Requirements

- Python 3
- no third-party runtime dependency

## Installation

No package install is required for runtime if you already have Python 3 available.

If needed, you can still use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Debian/Ubuntu systems, if `venv` is missing:

```bash
sudo apt update
sudo apt install python3-venv
```

## Token Permissions

Recommended permissions:

- `Zone - Zone: Read`
- `Zone - SSL and Certificates: Read`
- `Zone - SSL and Certificates: Write`
- `Account - SSL and Certificates: Read`
- `Account - SSL and Certificates: Write`

Recommended token scope:

- include the target account for mTLS certificate management
- include the target zone for hostname association management
- if you use `zones` or `--zone-name`, the token also needs access to read those zones

## Configuration

The script accepts credentials from:

1. command-line arguments
2. environment variables
3. a `.env` file

Supported variables:

- `CLOUDFLARE_API_TOKEN`

### `.env` file

Create a `.env` file in the project root:

```dotenv
CLOUDFLARE_API_TOKEN="your_api_token_here"
```

### Environment variables

Or define the variable in your shell or container:

```bash
export CLOUDFLARE_API_TOKEN="your_api_token_here"
```

## Usage

General syntax:

```bash
python3 mtls_cli.py <command> [options]
```

Terminal help:

```bash
python3 mtls_cli.py --help
python3 mtls_cli.py upload-certificate --help
python3 mtls_cli.py associations --help
python3 mtls_cli.py replace-associations --help
```

## Commands

### `zones`

Lists the zones accessible to the token.

Examples:

```bash
python3 mtls_cli.py zones
python3 mtls_cli.py zones --name-contains example
```

### `certificates`

Lists the mTLS certificates in an account.

Examples:

```bash
python3 mtls_cli.py certificates --account-id ACCOUNT_ID
python3 mtls_cli.py certificates --account-id ACCOUNT_ID --type custom
```

### `certificate`

Fetches a single certificate by ID.

Examples:

```bash
python3 mtls_cli.py certificate --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
```

### `upload-certificate`

Uploads a PEM bundle to the account mTLS certificate store.

Examples:

```bash
python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem
python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem --name my-ca
```

### `associations`

Lists hostname associations for a zone. You can use either `--zone-id` or `--zone-name`.

Examples:

```bash
python3 mtls_cli.py associations --zone-name example.com --mtls-certificate-id CERT_ID
python3 mtls_cli.py associations --zone-id ZONE_ID
```

### `replace-associations`

Replaces the full hostname association list for the target zone and certificate.

Examples:

```bash
python3 mtls_cli.py replace-associations --zone-name example.com --mtls-certificate-id CERT_ID --hostnames app.example.com api.example.com
python3 mtls_cli.py replace-associations --zone-id ZONE_ID --hostnames service.example.com
```

### `certificate-associations`

Lists active Cloudflare services currently using a certificate.

Examples:

```bash
python3 mtls_cli.py certificate-associations --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
```

### `delete-certificate`

Deletes a certificate from the account if it is no longer associated with active services.

Examples:

```bash
python3 mtls_cli.py delete-certificate --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
```
