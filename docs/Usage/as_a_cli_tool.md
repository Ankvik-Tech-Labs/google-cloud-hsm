# 🔐 Google HSM Ethereum CLI Tool

A command-line interface for managing Ethereum keys and signing operations using Google Cloud HSM.

## 📋 Prerequisites

Before using the CLI tool, ensure you have:

1. Google Cloud project with KMS enabled
2. Required environment variables set up:
   ```bash
   export GOOGLE_CLOUD_PROJECT="your-project-id"
   export GOOGLE_CLOUD_REGION="us-east1"
   export KEY_RING="eth-keyring"
   export KEY_NAME="eth-key"
   export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account.json"
   ```

## 🛠️ Installation

Install the package using pip:

```bash
pip install web3-google-hsm
```

## 📚 Commands

### Key Generation

Generate a new Ethereum signing key in Google Cloud HSM:

```bash
# Using environment variables
web3-google-hsm generate

# Or specify explicitly
web3-google-hsm generate \
  --project-id my-project \
  --location us-east1 \
  --keyring eth-keyring \
  --key-id eth-key-1 \
  --retention-days 365

web3-google-hsm generate --project-id hsm-testing-445507 --location nam10 --keyring eth-keyring --key-id cli_key
```

Options:
- `--project-id`: Google Cloud project ID (env: GOOGLE_CLOUD_PROJECT)
- `--location`: Cloud KMS location (env: GOOGLE_CLOUD_REGION)
- `--keyring`: Name of the key ring (env: KEY_RING)
- `--key-id`: ID for the new key (env: KEY_NAME)
- `--retention-days`: Days to retain key versions (default: 365)

Example output:
```
✅ Created Ethereum signing key: projects/my-project/locations/us-east1/keyRings/eth-keyring/cryptoKeys/eth-key-1
🔑 Ethereum address: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
```

### Message Signing

Sign a message using your HSM key:

```bash
# Sign a simple message
web3-google-hsm sign "Hello Ethereum!" --account 0x742d35Cc6634C0532925a3b844Bc454e4438f44e

# Sign a hex message
web3-google-hsm sign "0x4d7920686578206d657373616765" --account 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
```

Arguments:
- `message`: The message to sign (text or hex)
- `--account, -a`: Ethereum address of the signing account

Example output:
```
✅ Message signed successfully!
📝 Message: Hello Ethereum!
🔏 Signature: 0x4d7920686578206d657373616765000000000000000000000000000000000000
📊 Components:
  v: 27
  r: 0x1b7e9c7c039d8f4688a743b0c5c0e509209e6f200d956bf7f4e89f5ad330c135
  s: 0x0d27e9c7c039d8f4688a743b0c5c0e509209e6f200d956bf7f4e89f5ad330c13
```

## ⚙️ Environment Variables

The CLI tool supports the following environment variables:

| Variable | Description | Used In |
|----------|-------------|---------|
| `GOOGLE_CLOUD_PROJECT` | Google Cloud project ID | generate |
| `GOOGLE_CLOUD_REGION` | Cloud KMS location | generate |
| `KEY_RING` | Name of the key ring | generate |
| `KEY_NAME` | Name of the key | generate |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON | all commands |

## 🔍 Common Issues and Solutions

1. **Account Mismatch Error**
   ```
   ❌ Account mismatch: 0x742d... != 0x123...
   ```
   Solution: Verify that the `--account` parameter matches the address of your HSM key.

2. **Authentication Error**
   ```
   ❌ Error: Request had invalid authentication credentials
   ```
   Solution: Check your `GOOGLE_APPLICATION_CREDENTIALS` environment variable.

3. **Missing Environment Variables**
   ```
   ❌ Error: Field cannot be empty or whitespace
   ```
   Solution: Ensure all required environment variables are set or provide values via command-line options.

## 🔐 Security Best Practices

1. Always keep your Google Cloud service account key secure
2. Use appropriate IAM roles and permissions
3. Regularly rotate your keys using the `--retention-days` option
4. Verify signatures after signing
5. Always check that the signing address matches your expected address
