"""CLI interface for web3-google-hsm."""

import typer
from rich.console import Console

from web3_google_hsm.accounts.gcp_kms_account import GCPKmsAccount
from web3_google_hsm.config import BaseConfig

console = Console()
app = typer.Typer(help="🔐 Web3 Google HSM CLI tools for Ethereum key management and signing.")


@app.command()
def generate(
    project_id: str = typer.Option(
        ...,
        envvar="GOOGLE_CLOUD_PROJECT",
        help="Google Cloud project ID",
    ),
    location: str = typer.Option(
        ...,
        envvar="GOOGLE_CLOUD_REGION",
        help="Cloud KMS location (e.g. us-east1)",
    ),
    keyring: str = typer.Option(
        ...,
        envvar="KEY_RING",
        help="Name of the key ring",
    ),
    key_id: str = typer.Option(
        ...,
        envvar="KEY_NAME",
        help="ID for the new key",
    ),
    retention_days: int = typer.Option(
        365,
        help="Days to retain key versions",
    ),
) -> None:
    """🔑 Generate a new Ethereum signing key in Cloud HSM."""
    try:
        # Create the key
        key = GCPKmsAccount.create_eth_key(
            project_id=project_id,
            location_id=location,
            key_ring_id=keyring,
            key_id=key_id,
            retention_days=retention_days,
        )
        console.print(f"[green]✅ Created Ethereum signing key:[/green] {key.name}")

        # Initialize account to display the Ethereum address
        config = BaseConfig(
            project_id=project_id,
            location_id=location,
            key_ring_id=keyring,
            key_id=key_id,
        )
        account = GCPKmsAccount(config=config)
        console.print(f"[blue]🔑 Ethereum address:[/blue] {account.address}")

    except Exception as e:
        console.print(f"[red]❌ Error:[/red] {e!s}")
        raise typer.Exit(1) from e


@app.command()
def sign(
    message: str = typer.Argument(
        ...,
        help="Message to sign",
    ),
    account: str = typer.Option(
        ...,
        "--account",
        "-a",
        help="Ethereum address of the signing account",
    ),
) -> None:
    """📝 Sign a message using a Cloud HSM key."""
    try:
        # Initialize from environment variables
        config = BaseConfig.from_env()
        signer = GCPKmsAccount(config=config)

        # Verify the account matches
        if signer.address.lower() != account.lower():
            console.print(f"[red]❌ Account mismatch:[/red] {signer.address} != {account}")
            raise typer.Exit(1)

        # Sign the message
        signature = signer.sign_message(message)

        console.print("[green]✅ Message signed successfully![/green]")
        console.print(f"[blue]📝 Message:[/blue] {message}")
        console.print(f"[blue]🔏 Signature:[/blue] {signature.to_hex()}")
        console.print("[blue]📊 Components:[/blue]")
        console.print(f"  v: {signature.v}")
        console.print(f"  r: 0x{signature.r.hex()}")
        console.print(f"  s: 0x{signature.s.hex()}")

    except Exception as e:
        console.print(f"[red]❌ Error:[/red] {e!s}")
        raise typer.Exit(1) from e


def cli() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    cli()
