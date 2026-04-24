# Cloudflare mTLS CLI

Python CLI for managing Cloudflare mTLS certificates and hostname associations.

## Overview

The script can:

- list zones accessible to the token
- list certificates
- get one certificate
- upload a PEM bundle
- list hostname associations
- replace hostname associations
- list certificate associations
- delete a certificate

## Requirements

- Python 3
- no third-party runtime dependency

## Installation

No package install is required for runtime if you already have Python 3 available.

If needed:

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

- include the target account
- include the target zone
- if you use `zones` or `--zone-name`, the token also needs zone read access

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
```

### `certificates`

Lists the mTLS certificates in an account.

Examples:

```bash
python3 mtls_cli.py certificates --account-id ACCOUNT_ID
```

### `certificate`

Gets one certificate by ID.

Examples:

```bash
python3 mtls_cli.py certificate --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
```

### `upload-certificate`

Uploads a PEM bundle.

Examples:

```bash
python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem
python3 mtls_cli.py upload-certificate --account-id ACCOUNT_ID --bundle ca.pem --name my-ca
```

### `associations`

Lists hostname associations for a zone.

Examples:

```bash
python3 mtls_cli.py associations --zone-name example.com --mtls-certificate-id CERT_ID
```

### `replace-associations`

Replaces the hostname association list for a zone.

Examples:

```bash
python3 mtls_cli.py replace-associations --zone-name example.com --mtls-certificate-id CERT_ID --hostnames app.example.com api.example.com
```

### `certificate-associations`

Lists certificate associations.

Examples:

```bash
python3 mtls_cli.py certificate-associations --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
```

### `delete-certificate`

Deletes a certificate.

Examples:

```bash
python3 mtls_cli.py delete-certificate --account-id ACCOUNT_ID --mtls-certificate-id CERT_ID
```
