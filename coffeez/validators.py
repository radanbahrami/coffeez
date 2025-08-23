"""
Coffeez Validators

This module provides custom validation functions for the Coffeez application:
- File size validation for uploaded images
- TRX cryptocurrency wallet address validation
- Username validation with security and UX considerations

All validators raise Django ValidationError on invalid input.
"""

from django.core.exceptions import ValidationError
import re


def validate_file_size(file):
    """
    Validate that uploaded file size is within acceptable limits.
    
    Ensures uploaded files (primarily profile pictures) don't exceed
    the maximum allowed size to prevent storage abuse and improve
    performance.
    
    Args:
        file: Django UploadedFile object to validate
        
    Raises:
        ValidationError: If file size exceeds 512 KB limit
    """
    max_size_kb = 512
    if file.size > max_size_kb * 1024:
        raise ValidationError(f"File size cannot exceed {max_size_kb} KB.")


def validate_trx_wallet_address(wallet_address):
    """
    Validate TRX (TRON) cryptocurrency wallet address format.
    
    TRX wallet addresses must start with 'T' and be exactly 34 characters
    long with alphanumeric characters only. This prevents invalid addresses
    from being stored and ensures donations can be processed correctly.
    
    Args:
        wallet_address: String to validate as TRX wallet address
        
    Raises:
        ValidationError: If address doesn't match TRX format requirements
    """
    # TRX wallet addresses typically start with a T and are 34 characters long
    if not re.match(r'^T[a-zA-Z0-9]{33}$', wallet_address):
        raise ValidationError("Invalid TRX wallet address.")


def validate_username(value):
    """
    Validate creator usernames with security and UX considerations.

    Comprehensive username validation that prevents:
    - Email addresses and URLs that could confuse users
    - Reserved system/admin terms that could be misleading
    - Very short usernames that may be ambiguous
    - Usernames that could impersonate staff or system accounts
    
    This validator is essential for maintaining platform integrity and
    preventing social engineering attacks through misleading usernames.

    Args:
        value: Username string to validate
        
    Raises:
        ValidationError: If username violates any validation rules
        
    Rules enforced:
    - Reject values that look like email addresses or URLs (contain '@' or '.' or start with http/www)
    - Reject common reserved account names that imply staff/system roles (admin, support, root, www, api, etc.)
    - Reject short values to avoid ambiguous usernames (minimum 4 characters)
    - Reject usernames that embed reserved keywords
    """
    if not value or not isinstance(value, str):
        raise ValidationError("Invalid username.")

    v = value.strip()
    v_lower = v.lower()

    # Basic checks: no emails or URLs that could confuse users
    if '@' in v_lower or v_lower.startswith('http') or v_lower.startswith('www') or '.' in v_lower:
        raise ValidationError("Usernames cannot contain '@', '.' or look like URLs or email addresses.")

    # Disallow extremely short usernames to avoid ambiguity
    if len(v) < 4:
        raise ValidationError("Usernames must be at least 4 characters long.")

    # Comprehensive list of reserved words that would be misleading if used as usernames
    # These terms could confuse users or enable social engineering attacks
    reserved = {
        # Core administrative and system roles
        'admin', 'administrator', 'superuser', 'root', 'system', 'sysadmin', 'staff', 'operator',
        'owner', 'manager', 'team', 'teamlead', 'moderator', 'moderators', 'support', 'help', 'helpdesk',

        # Contact and communication endpoints
        'contact', 'webmaster', 'postmaster', 'hostmaster', 'mail', 'email', 'inbox', 'info', 'office',

        # Financial and security-related terms
        'security', 'abuse', 'billing', 'payments', 'payment', 'invoice', 'invoices', 'checkout', 'pay',
        'deposit', 'withdraw', 'transactions', 'transaction', 'tx', 'wallet', 'wallets', 'balance',

        # Authentication and account management flows
        'signup', 'register', 'login', 'logout', 'auth', 'authorize', 'oauth', 'verify', 'verification',
        'confirm', 'confirmation', 'reset', 'forgot', 'activate', 'activation', 'settings', 'preferences',

        # Technical infrastructure and API endpoints
        'api', 'apis', 'status', 'health', 'metrics', 'monitor', 'monitoring', 'dev', 'developer',
        'developers', 'staging', 'demo', 'test', 'testing', 'sandbox', 'internal', 'backend', 'frontend',

        # Platform and vendor names that could be misleading
        'www', 'web', 'site', 'home', 'homepage', 'blog', 'news', 'newsletter', 'shop', 'store', 'marketplace',

        # Development and code hosting platforms
        'git', 'github', 'gitlab', 'bitbucket', 'docker', 'kubernetes', 'k8s',

        # Generic terms that could be ambiguous or misleading
        'users', 'user', 'username', 'profile', 'account', 'accounts', 'member', 'members', 'guest',
        'anonymous', 'none', 'null', 'undefined'
    }

    # Reject exact matches (case-insensitive) with reserved terms
    if v_lower in reserved:
        raise ValidationError("This username is unavailable.")

    # Reject usernames that clearly embed reserved keywords as separate tokens
    # e.g., "support_123", "admin-xyz", "user_admin", "test-account"
    for r in reserved:
        if r and (v_lower.startswith(r + '-') or v_lower.startswith(r + '_') or v_lower.endswith('-' + r) or v_lower.endswith('_' + r)):
            raise ValidationError("This username is unavailable.")

    # Reject if reserved keyword appears separated by non-alphanumeric characters
    # This catches patterns like "my.admin.account" or "user@support"
    if re.search(r'(^|[^a-z0-9])(' + '|'.join(re.escape(x) for x in reserved) + r')([^a-z0-9]|$)', v_lower):
        raise ValidationError("This username is unavailable.")
