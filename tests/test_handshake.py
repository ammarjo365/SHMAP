import pytest
from src.shmap import SecureDevice

def test_handshake():
    shared_key = b"32-byte-long-secret-key-ERROR404-99"
    dev_a = SecureDevice("A", shared_key)
    dev_b = SecureDevice("B", shared_key)
    
    # Test handshake completion
    assert dev_a.establish_session(dev_b.public_key) is not None
