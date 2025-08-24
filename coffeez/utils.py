"""
Coffeez Utilities

This module provides utility functions for cryptocurrency operations and email sending:
- TRX price fetching from external APIs
- Unique payment amount generation for donation tracking
- Transaction verification on the TRON blockchain
- DKIM-signed email sending

These utilities are essential for the donation/payment flow.
"""

import requests
import secrets
import smtplib
import dkim
import email.utils
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def get_trx_price_usd():
    """
    Fetch the current TRX to USD exchange rate.
    
    Uses the CryptoCompare API to get real-time TRX pricing.
    This is essential for calculating how much TRX users need
    to send for their desired USD donation amount.
    
    Returns:
        float: Current TRX price in USD, or None if fetch fails
        
    Note:
        Has a 10-second timeout to prevent hanging requests.
        Failures are logged but don't raise exceptions.
    """
    url = "https://min-api.cryptocompare.com/data/price?fsym=TRX&tsyms=USD"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error for bad responses
        data = response.json()
        usd = data.get("USD")
        return float(usd) if usd is not None else None
    except Exception as e:
        print(f"Error fetching TRX price: {e}")
        return None


def generate_unique_trx_amount(usd_amount):
    """
    Generate a unique TRX amount for donation tracking.
    
    Creates a slightly randomized TRX amount based on the USD value.
    The randomization allows the system to identify specific transactions
    by looking for the exact amount on the blockchain.
    
    Args:
        usd_amount: Target donation amount in USD dollars
        
    Returns:
        float: Unique TRX amount rounded to 6 decimal places
        
    Note:
        Adds 0.0001 to 0.1 TRX of entropy to the base amount.
        This ensures each donation has a unique trackable amount.
    """
    trx_price_usd = get_trx_price_usd()
    base_amount = usd_amount / trx_price_usd
    entropy_int = secrets.randbelow(100001) + 100  # 100-100100 range
    entropy = entropy_int / 1_000_000  # Convert to decimal TRX amount (0.0001-0.1001 TRX)
    unique_amount = base_amount + entropy
    return round(unique_amount, 6)


def check_for_exact_donation(address, amount):
    """
    Check if an exact donation amount has been received by an address.

    Queries the TRON blockchain to verify if a specific
    TRX amount has been sent to the given address. This is used to
    automatically detect and confirm donations.

    Args:
        address: TRX wallet address to check for incoming transactions
        amount: Exact TRX amount to look for in recent transactions

    Returns:
        str: Transaction ID if exact amount found, None otherwise

    Note:
        Only checks the last 10 transactions for performance.
        Dynamically selects Shasta testnet or mainnet API based on environment.
    """
    base_url = "https://api.shasta.trongrid.io" if os.environ.get('DJANGO_DEBUG', 'False') == 'True' else "https://api.trongrid.io"
    url = f"{base_url}/v1/accounts/{address}/transactions"
    params = {"only_to": "true", "limit": 10}
    response = requests.get(url, params=params)
    data = response.json()
    
    for tx in data.get('data', []):
        contract = tx.get("raw_data", {}).get("contract", [{}])[0]
        if contract.get("type") == "TransferContract":
            # Convert from SUN units (1 TRX = 1,000,000 SUN) to TRX
            value = int(contract["parameter"]["value"]["amount"]) / 1_000_000
            # Use small tolerance for floating point comparison
            if abs(value - amount) < 0.000001:
                return tx["txID"]
    return None


def send_dkim_email(subject, message, to_email, from_email, dkim_selector, dkim_domain, dkim_key_path, smtp_host, smtp_port, smtp_user, smtp_pass):
    # Build message
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg['Date'] = email.utils.formatdate()
    msg['Message-ID'] = email.utils.make_msgid(domain=dkim_domain)
    msg.attach(MIMEText(message, "plain"))

    # DKIM signing
    headers = [b"To", b"From", b"Subject", b"Date", b"Message-ID"]
    with open(dkim_key_path, "rb") as fh:
        dkim_private = fh.read()
    sig = dkim.sign(
        message=msg.as_bytes(),
        selector=dkim_selector.encode(),
        domain=dkim_domain.encode(),
        privkey=dkim_private,
        include_headers=headers,
    )
    msg["DKIM-Signature"] = sig.decode().lstrip("DKIM-Signature: ")

    # Send via SMTP
    with smtplib.SMTP_SSL(smtp_host, smtp_port) as s:
        s.login(smtp_user, smtp_pass)
        s.sendmail(from_email, to_email, msg.as_string())
