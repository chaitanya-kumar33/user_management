##################### Test hashing functionality with very long passwords

def test_hashing_very_long_password():
    """Ensure hashing works correctly with a very long password."""
    long_password = "a" * 10000  # Password with 10,000 characters
    hashed_password = hash_password(long_password)
    assert isinstance(hashed_password, str) and hashed_password.startswith('$2b$')

##################### Test password verification with very long passwords

def test_verification_very_long_password():
    """Ensure password verification works correctly with a very long password."""
    long_password = "a" * 10000  # Password with 10,000 characters
    hashed_password = hash_password(long_password)
    assert verify_password(long_password, hashed_password) is True

##################### Test hashing functionality with non-ASCII characters

def test_hashing_non_ascii_password():
    """Ensure hashing works correctly with a password containing non-ASCII characters."""
    special_password = "pässwörd"
    hashed_password = hash_password(special_password)
    assert isinstance(hashed_password, str) and hashed_password.startswith('$2b$')

##################### Test password verification with non-ASCII characters

def test_verification_non_ascii_password():
    """Ensure password verification works correctly with a password containing non-ASCII characters."""
    special_password = "pässwörd"
    hashed_password = hash_password(special_password)
    assert verify_password(special_password, hashed_password) is True
