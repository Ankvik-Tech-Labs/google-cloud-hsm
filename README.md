# web3-google-hsm


<div align="center" markdown>

| Feature       | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Technology    | [![Python](https://img.shields.io/badge/Python-3776AB.svg?style=flat&logo=Python&logoColor=white)](https://www.python.org/) [![Hatch project](https://img.shields.io/badge/%F0%9F%A5%9A-Hatch-4051b5.svg)](https://github.com/pypa/hatch) [![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-2088FF.svg?style=flat&logo=GitHub-Actions&logoColor=white)](https://github.com/features/actions) [![Pytest](https://img.shields.io/badge/Pytest-0A9EDC.svg?style=flat&logo=Pytest&logoColor=white)](https://github.com/Ankvik-Tech-Labs/web3-google-hsmweb3-google-hsm/actions/workflows/tests.yml/badge.svg)                                                                                                                                                                                                                                                                                 |
| Type Checking | [![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff) [![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| CI/CD         | [![Release](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/build.yml/badge.svg)](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/build.yml) [![Tests](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/tests.yml/badge.svg)](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/tests.yml) [![Labeler](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/labeler.yml/badge.svg)](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/labeler.yml) [![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit) [![codecov](https://codecov.io/gh/Ankvik-Tech-Labs/web3-google-hsm/graph/badge.svg?token=CK69S336BL)](https://codecov.io/gh/Ankvik-Tech-Labs/web3-google-hsm) |
| Docs          | [![Docs](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/documentation.yml/badge.svg)](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/actions/workflows/build.yml)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Package       | [![PyPI - Version](https://img.shields.io/pypi/v/web3-google-hsm.svg)](https://pypi.org/project/web3-google-hsm/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/web3-google-hsm)](https://pypi.org/project/web3-google-hsm/) [![PyPI - License](https://img.shields.io/pypi/l/web3-google-hsm)](https://pypi.org/project/web3-google-hsm/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Meta          | [![GitHub license](https://img.shields.io/github/license/Ankvik-Tech-Labs/web3-google-hsm?&color=1573D5)](https://github.com/Ankvik-Tech-Labs/web3-google-hsm/blob/main/LICENSE) [![GitHub last commit](https://img.shields.io/github/last-commit/Ankvik-Tech-Labs/web3-google-hsm?style=flat&color=1573D5)](https://github.com/Ankvik-Tech-Labs/web3-google-hsmweb3-google-hsm/commits/main) [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Ankvik-Tech-Labs/web3-google-hsm?style=flat&color=1573D5)](https://github.com/Ankvik-Tech-Labs/web3-google-hsmweb3-google-hsm/graphs/commit-activity) [![GitHub top language](https://img.shields.io/github/languages/top/Ankvik-Tech-Labs/web3-google-hsm?style=flat&color=1573D5)](https://github.com/Ankvik-Tech-Labs/web3-google-hsmweb3-google-hsm)                                                               |

</div>

---

# Description

A Python library for using `Google Cloud HSM` services to sign Ethereum transactions.

# Features

- Cloud HSM integration for secure key management.
- Support for web3-google-hsm (extensible to other providers).
- Type-safe configuration using Pydantic.


# Installation

- Install using `pip`
```py
pip install web3-google-hsm
```

# Usage

## Environment Setup

### Google Cloud HSM Key

Make sure you have created a key of type `ec-sign-secp256k1-sha256`
in the Google cloud console. Which will look something like the following

![gcp_hsm_key](media/gcp_hsm_key.png)

### Required Environment Variables

Before using this library, you need to set up the following environment variables:

```plaintext
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_REGION=us-east1
KEY_RING=eth-keyring
KEY_NAME=eth-key
GOOGLE_APPLICATION_CREDENTIALS=path/to/your/service-account.json
```

### Bash
```bash
# Add to ~/.bashrc or ~/.bash_profile
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_REGION="us-east1"
export KEY_RING="eth-keyring"
export KEY_NAME="eth-key"
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account.json"

# Apply changes
source ~/.bashrc  # or source ~/.bash_profile
```

### Zsh
```zsh
# Add to ~/.zshrc
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_REGION="us-east1"
export KEY_RING="eth-keyring"
export KEY_NAME="eth-key"
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account.json"

# Apply changes
source ~/.zshrc
```

### Fish
```bash
# Add to ~/.config/fish/config.fish
set -x GOOGLE_CLOUD_PROJECT "your-project-id"
set -x GOOGLE_CLOUD_REGION "us-east1"
set -x KEY_RING "eth-keyring"
set -x KEY_NAME "eth-key"
set -x GOOGLE_APPLICATION_CREDENTIALS "path/to/your/service-account.json"
set -x INFURA_KEY "your-infura-key"
set -x WEB3_PROVIDER_URI "https://mainnet.infura.io/v3/$INFURA_KEY"

# Apply changes
source ~/.config/fish/config.fish
```

### Using .env File
You can also create a `.env` file in your project root:

```plaintext
# .env
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_REGION=us-east1
KEY_RING=eth-keyring
KEY_NAME=eth-key
GOOGLE_APPLICATION_CREDENTIALS=path/to/your/service-account.json
```

Then load it in your Python code:
```python
from dotenv import load_dotenv
load_dotenv()
```

### Environment Variable Descriptions

- `GOOGLE_CLOUD_PROJECT`: Your Google Cloud project ID
- `GOOGLE_CLOUD_REGION`: The region where your KMS resources are located (e.g., us-east1, europe-west1)
- `KEY_RING`: The name of your KMS key ring
- `KEY_NAME`: The name of your KMS key
- `GOOGLE_APPLICATION_CREDENTIALS`: Path to your Google Cloud service account JSON key file

### Verifying Setup

You can verify your environment setup with:

```python
from web3_google_hsm.config import BaseConfig

try:
    config = BaseConfig()
    print("Environment configured successfully!")
    print(f"Project ID: {config.project_id}")
    print(f"Region: {config.location_id}")
except ValueError as e:
    print(f"Configuration error: {e}")
```


---

For more information see the following links.

**Documentation**: <a href="https://Aviksaikat.github.io/web3-google-hsm/" target="_blank">https://Aviksaikat.github.io/web3-google-hsm/</a>

**Source Code**: <a href="https://github.com/Ankvik-Tech-Labs/web3-google-hsm" target="_blank">https://github.com/Ankvik-Tech-Labs/web3-google-hsm</a>

---

<details close>
<summary>Development</summary>
<br>


## Development

### Setup environment

We use [Hatch](https://hatch.pypa.io/latest/install/) to manage the development environment and production build. Ensure it's installed on your system.

### Run unit tests

You can run all the tests with:

```bash
hatch run test
```

### Format the code

Execute the following command to apply linting and check typing:

```bash
hatch run lint
```

### Publish a new version

You can bump the version, create a commit and associated tag with one command:

```bash
hatch version patch
```

```bash
hatch version minor
```

```bash
hatch version major
```

Your default Git text editor will open so you can add information about the release.

When you push the tag on GitHub, the workflow will automatically publish it on PyPi and a GitHub release will be created as draft.

## Serve the documentation

You can serve the Mkdocs documentation with:

```bash
hatch run docs-serve
```

It'll automatically watch for changes in your code.


</details>


## License

This project is licensed under the terms of the BSD license.
