import pytest
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, HMAC
from src.shmap import SecureDevice

@pytest.fixture
def devices():
    shared_key = b"32-byte-test-key-1234567890abcdef"
    dev_a = SecureDevice("Device_A", shared_key)
    dev_b = SecureDevice("Device_B", shared_key)
    return dev_a, dev_b

def test_mitm_protection(devices):
    """Verify MITM can't spoof signatures"""
    dev_a, dev_b = devices
    
    fake_device = SecureDevice("MITM", b"fake-key-1234567890abcdefghijklmnop")
    
    with pytest.raises(ValueError, match="Signature verification failed"):
        dev_a.establish_session(fake_device.public_key)

def test_replay_attack(devices):
    """Verify nonce sequencing prevents replays"""
    dev_a, dev_b = devices
    
    session_key = dev_a.establish_session(dev_b.public_key)
    
    old_message = dev_a.last_outgoing_message
    
    with pytest.raises(ValueError, match="Invalid sequence number"):
        dev_b.process_message(old_message)

def test_key_derivation():
    """Verify HKDF produces deterministic keys"""
    shared_key = b"test-key-1234567890abcdefghijklmnop"
    nonce_a = b"nonce-a-12345678"
    nonce_b = b"nonce-b-87654321"
    
    key1 = HKDF(shared_key, 32, nonce_a + nonce_b, SHA256)
    key2 = HKDF(shared_key, 32, nonce_a + nonce_b, SHA256)
    
    assert key1 == key2, "Key derivation should be deterministic"

def test_hmac_integrity(devices):
    """Verify HMAC detects tampered messages"""
    dev_a, dev_b = devices
    dev_a.establish_session(dev_b.public_key)
    
    msg = b"ERROR404 - This is me Everywhere"
    encrypted, hmac = dev_a.secure_message(msg)
    
    tampered = bytearray(encrypted)
    tampered[10] ^= 0xFF
    
    with pytest.raises(ValueError, match="HMAC verification failed"):
        dev_b.receive_message(bytes(tampered), hmac)

def test_nonce_uniqueness():
    """Verify nonces are never reused"""
    dev = SecureDevice("TestDevice", b"test-key-1234567890abcdef")
    nonces = set()
    
    for _ in range(100):
        nonce = dev._generate_nonce()
        assert nonce not in nonces, "Nonce reuse detected"
        nonces.add(nonce)

# pytest tests/test_security.py -v  # Run
# Expected Output:
# collected 5 items

# tests/test_security.py::test_mitm_protection PASSED
# tests/test_security.py::test_replay_attack PASSED  
# tests/test_security.py::test_key_derivation PASSED
# tests/test_security.py::test_hmac_integrity PASSED
# tests/test_security.py::test_nonce_uniqueness PASSED
