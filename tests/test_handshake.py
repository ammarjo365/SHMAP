import pytest
from src.shmap import SecureDevice

def test_handshake():
    shared_key = b"32-byte-long-secret-key-1234567890"
    dev_a = SecureDevice("A", shared_key)
    dev_b = SecureDevice("B", shared_key)
    
    assert dev_a.establish_session(dev_b.public_key) is not None
