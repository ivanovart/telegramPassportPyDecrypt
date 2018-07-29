import hashlib
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP

PRIVKEY_PATH = "PATH TO YOUR PRIVATE KEY HERE"


def decrypt_data(data_encrypted, data_secret, data_hash):
    # Check types and decode from base64
    if type(data_encrypted) != bytes:
        data_encrypted = str.encode(data_encrypted)
    if type(data_secret) != bytes:
        data_secret = str.encode(data_secret)
    if type(data_hash) != bytes:
        data_hash = str.encode(data_hash)
    data_encrypted = base64.decodebytes(data_encrypted)
    data_secret = base64.decodebytes(data_secret)
    data_hash = base64.decodebytes(data_hash)
    # Calculate hash, key & iv
    data_secret_hash = hashlib.sha512(data_secret + data_hash).digest()
    data_key = data_secret_hash[:32]
    data_iv = data_secret_hash[32:48]
    # Decrypt data
    cipher = AES.new(data_key, AES.MODE_CBC, iv=data_iv)
    data_decrypted = cipher.decrypt(data_encrypted)
    # Check decrypted data with hash provided
    data_decrypted_hash = hashlib.sha256(data_decrypted).digest()
    if data_hash != data_decrypted_hash:
        raise Exception('HASH_INVALID')
    # Remove padding
    padding_len = data_decrypted[0]
    data_decrypted = data_decrypted[padding_len:]
    
    return data_decrypted


def decrypt_credential_secret(credential_secret):
    # Check types and decode from base64
    if type(credential_secret) != bytes:
        credential_secret = str.encode(credential_secret)
    credential_secret = base64.decodebytes(credential_secret)
    # Import key and decrypt secret
    private_key = RSA.import_key(open(PRIVKEY_PATH).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_secret = cipher_rsa.decrypt(credential_secret)
    
    return base64.encodebytes(decrypted_secret)
