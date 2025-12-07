"""
Custom exception classes for llm-fs-tools.
"""


class SecurityError(Exception):
    """
    Raised when a security policy violation is detected.
    
    This includes:
    - Path traversal attempts
    - Access to blocked files/patterns
    - Files outside allowed roots
    - Symlink attacks
    - TOCTOU violations
    """
    pass


class ValidationError(Exception):
    """
    Raised when validation fails (non-security related).
    """
    pass
