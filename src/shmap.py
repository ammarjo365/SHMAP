import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

class SecureProtocol:
    def __init__(self, device_id, shared_key):
        self.device_id = device_id
        self.shared_key = shared_key
        
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        
        self.session_key = None
        self.seq_number = 0
        self.peer_public_key = None
        self.nonce_a = None
        self.nonce_b = None
    
    def generate_nonce(self, length=16):
        return os.urandom(length)
    
    def create_hmac(self, message):
        h = hmac.new(self.session_key, digestmod=hashlib.sha256)
        h.update(message)
        return h.digest()
    
    def verify_hmac(self, message, received_hmac):
        expected_hmac = self.create_hmac(message)
        return hmac.compare_digest(expected_hmac, received_hmac)
    
    def encrypt_aes(self, plaintext):
        iv = os.urandom(16)
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ciphertext
    
    def decrypt_aes(self, ciphertext):
        iv = ciphertext[:16]
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
        return plaintext
    
    def create_auth_request(self):
        self.nonce_a = self.generate_nonce()
        return {
            'type': 'auth_request',
            'id': self.device_id,
            'nonce': self.nonce_a,
            'public_key': self.public_key.export_key().decode('utf-8')
        }
    
    def process_auth_request(self, request):
        if request['type'] != 'auth_request':
            raise ValueError("Invalid message type")
        
        self.peer_public_key = RSA.import_key(request['public_key'].encode('utf-8'))
        self.nonce_a = request['nonce']
        self.nonce_b = self.generate_nonce()
        
        h = SHA256.new(self.nonce_a + self.nonce_b)
        signature = pkcs1_15.new(self.private_key).sign(h)
        
        return {
            'type': 'auth_response',
            'id': self.device_id,
            'nonce': self.nonce_b,
            'signature': signature,
            'public_key': self.public_key.export_key().decode('utf-8')
        }
    
    def process_auth_response(self, response):
        if response['type'] != 'auth_response':
            raise ValueError("Invalid message type")
        
        if not self.peer_public_key:
            self.peer_public_key = RSA.import_key(response['public_key'].encode('utf-8'))
        
        h = SHA256.new(self.nonce_a + response['nonce'])
        try:
            pkcs1_15.new(self.peer_public_key).verify(h, response['signature'])
        except (ValueError, TypeError) as e:
            raise ValueError(f"Signature verification failed: {str(e)}")
        
        self.nonce_b = response['nonce']
        
        h = hashlib.sha256()
        h.update(self.shared_key)
        h.update(self.nonce_a)
        h.update(self.nonce_b)
        self.session_key = h.digest()
        self.seq_number = 0
        
        timestamp = int(datetime.now().timestamp()).to_bytes(8, 'big')
        session_data = self.session_key + self.seq_number.to_bytes(4, 'big') + timestamp
        
        iv = os.urandom(16)
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(session_data, AES.block_size))
        
        h = SHA256.new(self.nonce_b)
        signature = pkcs1_15.new(self.private_key).sign(h)
        
        return {
            'type': 'session_init',
            'signature': signature,
            'encrypted_data': iv + encrypted_data
        }
    
    def process_session_init(self, message):
        if message['type'] != 'session_init':
            raise ValueError("Invalid message type")
        
        h = SHA256.new(self.nonce_b)
        try:
            pkcs1_15.new(self.peer_public_key).verify(h, message['signature'])
        except (ValueError, TypeError) as e:
            raise ValueError(f"Signature verification failed: {str(e)}")
        
        iv = message['encrypted_data'][:16]
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(message['encrypted_data'][16:]), AES.block_size)
        
        self.session_key = decrypted[:32]
        self.seq_number = int.from_bytes(decrypted[32:36], 'big')
        timestamp = int.from_bytes(decrypted[36:], 'big')
        
        if abs(datetime.now().timestamp() - timestamp) > 120:
            raise ValueError("Expired session initialization")
        
        self.seq_number += 1
        ack_msg = self.seq_number.to_bytes(4, 'big')
        hmac_val = self.create_hmac(ack_msg)
        
        return {
            'type': 'session_ack',
            'hmac': hmac_val
        }
    
    def process_session_ack(self, message):
        if message['type'] != 'session_ack':
            raise ValueError("Invalid message type")
        
        expected_seq = (self.seq_number + 1).to_bytes(4, 'big')
        if not self.verify_hmac(expected_seq, message['hmac']):
            raise ValueError("HMAC verification failed")
        
        self.seq_number += 2
    
    def create_secure_message(self, plaintext):
        self.seq_number += 1
        seq_bytes = self.seq_number.to_bytes(4, 'big')
        
        encrypted = self.encrypt_aes(plaintext)
        
        hmac_data = seq_bytes + encrypted
        hmac_val = self.create_hmac(hmac_data)
        
        return {
            'type': 'secure_message',
            'seq': seq_bytes,
            'encrypted_data': encrypted,
            'hmac': hmac_val
        }
    
    def process_secure_message(self, message):
        if message['type'] != 'secure_message':
            raise ValueError("Invalid message type")
        
        hmac_data = message['seq'] + message['encrypted_data']
        if not self.verify_hmac(hmac_data, message['hmac']):
            raise ValueError("HMAC verification failed")
        
        received_seq = int.from_bytes(message['seq'], 'big')
        if received_seq <= self.seq_number:
            raise ValueError("Invalid sequence number (possible replay)")
        self.seq_number = received_seq
        
        return self.decrypt_aes(message['encrypted_data'])

if __name__ == "__main__":
    shared_key = os.urandom(32)
    
    device_a = SecureProtocol("Device_A", shared_key)
    device_b = SecureProtocol("Device_B", shared_key)
    
    print("=== Starting Protocol Execution ===")
    
    try:
        auth_req = device_a.create_auth_request()
        print("Device A → Device B: Auth Request")
        
        auth_resp = device_b.process_auth_request(auth_req)
        print("Device B → Device A: Auth Response")
        
        session_init = device_a.process_auth_response(auth_resp)
        print("Device A → Device B: Session Init")
        
        session_ack = device_b.process_session_init(session_init)
        print("Device B → Device A: Session Ack")
        
        device_a.process_session_ack(session_ack)
        print("=== Secure Session Established ===")
        
        message = b"ERROR404 - This is My Signiture Name"
        secure_msg = device_a.create_secure_message(message)
        print(f"\nDevice A → Device B: Secure Message (Length: {len(message)})")
        
        decrypted = device_b.process_secure_message(secure_msg)
        print(f"Device B received: {decrypted.decode('utf-8')}")
        
        print("\nTesting replay protection...")
        try:
            device_b.process_secure_message(secure_msg)
            print("FAIL: Replay attack succeeded!")
        except ValueError as e:
            print(f"SUCCESS: Replay prevented - {str(e)}")
            
    except Exception as e:
        print(f"\nProtocol failed: {str(e)}")


class MITMAttacker:
    def __init__(self):
        self.intercepted_messages = []
        self.fake_key = os.urandom(32)
        self.fake_device_a = None
        self.fake_device_b = None
    
    def intercept_auth_request(self, original_msg):
        self.intercepted_messages.append(('original_auth_request', original_msg))
        
        self.fake_device_a = SecureProtocol("FAKE_Device_A", self.fake_key)
        self.fake_device_b = SecureProtocol("FAKE_Device_B", self.fake_key)
        
        fake_req = self.fake_device_a.create_auth_request()
        self.intercepted_messages.append(('fake_auth_request', fake_req))
        return fake_req
    
    def intercept_auth_response(self, original_msg):
        self.intercepted_messages.append(('original_auth_response', original_msg))
        
        fake_resp = self.fake_device_b.process_auth_request(
            self.intercepted_messages[-2][1]
        )
        self.intercepted_messages.append(('fake_auth_response', fake_resp))
        return fake_resp
    
    def intercept_session_init(self, original_msg):
        self.intercepted_messages.append(('original_session_init', original_msg))
        
        fake_init = self.fake_device_a.process_auth_response(
            self.intercepted_messages[-1][1]
        )
        self.intercepted_messages.append(('fake_session_init', fake_init))
        return fake_init
    
    def intercept_session_ack(self, original_msg):
        self.intercepted_messages.append(('original_session_ack', original_msg))
        
        fake_ack = self.fake_device_b.process_session_init(
            self.intercepted_messages[-1][1]
        )
        self.intercepted_messages.append(('fake_session_ack', fake_ack))
        return fake_ack

def simulate_mitm_attack():
    shared_key = os.urandom(32)
    
    device_a = SecureProtocol("Device_A", shared_key)
    device_b = SecureProtocol("Device_B", shared_key)
    
    eve = MITMAttacker()
    
    print("=== Starting MITM Attack Simulation ===")
    
    try:
        auth_req = device_a.create_auth_request()
        print("\nLegitimate Device A → Eve (attacker): Auth Request")
        intercepted_req = eve.intercept_auth_request(auth_req)
        print("Eve → Legitimate Device B: Modified Auth Request")
        
        auth_resp = device_b.process_auth_request(intercepted_req)
        print("\nLegitimate Device B → Eve: Auth Response")
        intercepted_resp = eve.intercept_auth_response(auth_resp)
        print("Eve → Legitimate Device A: Modified Auth Response")
        
        session_init = device_a.process_auth_response(intercepted_resp)
        print("\nLegitimate Device A → Eve: Session Init")
        intercepted_init = eve.intercept_session_init(session_init)
        print("Eve → Legitimate Device B: Modified Session Init")
        
        session_ack = device_b.process_session_init(intercepted_init)
        print("\nLegitimate Device B → Eve: Session Ack")
        intercepted_ack = eve.intercept_session_ack(session_ack)
        print("Eve → Legitimate Device A: Modified Session Ack")
        
        device_a.process_session_ack(intercepted_ack)
        eve.fake_device_a.process_session_ack(eve.intercepted_messages[-1][1])
        print("\n=== Attack Result ===")
        print("Legitimate session established:", device_a.session_key is not None)
        print("Fake session established:", eve.fake_device_a.session_key is not None)
        
        print("\n=== Testing Communication ===")
        message = b" ASU is a secret message"
        secure_msg = device_a.create_secure_message(message)
        print("Device A → Eve: Encrypted Message")
        
        try:
            decrypted = eve.fake_device_b.process_secure_message(secure_msg)
            print(f"Eve decrypted: {decrypted.decode('utf-8')}")
        except Exception as e:
            print(f"Eve failed to decrypt: {str(e)}")
        
        try:
            decrypted = device_b.process_secure_message(secure_msg)
            print(f"Device B decrypted: {decrypted.decode('utf-8')}")
        except Exception as e:
            print(f"Device B failed to decrypt: {str(e)}")
            
    except Exception as e:
        print(f"\nAttack failed: {str(e)}")

if __name__ == "__main__":
    simulate_mitm_attack()
