from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# ---------------生成一對RSA private_key and public_key----------------


def generate_rsa_key():
    private_key = rsa.generate_private_key(  # 私鑰生成
        public_exponent=65537,  # The public exponent of the new key
        key_size=2048,  # The length of the modulus in bits
        backend=default_backend()
    )
    public_key = private_key.public_key()  # 公鑰生成
    return private_key, public_key


# -------將 RSA public_key存為 PEM format(Privacy-Enhanced Mail)----
def save_public_key(public_key, filepath):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, 'wb') as f:
        f.write(pem)


# --------將 RSA private_key 存PEM format(Privacy-Enhanced Mail)-------------------
def save_private_key(private_key, filepath, password=None):
    if password is not None:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm
    )
    with open(filepath, 'wb') as f:
        f.write(pem)


# ---------------load PEM fomat的public_key-------------------
def load_public_key(filepath):
    with open(filepath, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend())
    return public_key


# ---------------load PEM fomat的private_key-------------------
def load_private_key(filepath, password=None):
    with open(filepath, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=password, backend=default_backend())
    return private_key

# ------------------生成 AES key------------------


def generate_aes_key():
    return os.urandom(32)  # 隨機生成32個bytes (256bit)長度 AES-256


# ----------------rsa encypted aes_key------------
def encrypt_aes_key(aes_key, public_key):
    encrypt_key = public_key.encrypt(
        aes_key,
        padding.OAEP(  # OAEP (Optimal Asymmetric Encryption Padding)
            # Mask Generation Function, MGF
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypt_key


# -------------rsa decrpted aes_key--------------
def decrypt_aes_key(encrypted_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


# ------------用aes encrypted 檔案---------------
def encrypt_file(content, aes_key):
    iv = os.urandom(16)  # 隨機生成一個16bytes的初始向量
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv),
                    backend=default_backend())  # 利用密鑰與iv開始進行加密
    encryptor = cipher.encryptor()  # update ,finalize
    if os.path.isfile(content):
        with open(content, 'rb') as f:
            plaintext = f.read()
    else:
        plaintext = content.encode()
    ciphertext = encryptor.update(
        plaintext) + encryptor.finalize()  # 塊加密以及剩下的data也要處理
    return iv + ciphertext

# ------------用aes decrypted 檔案---------------


def decrypt_file(ciphertext, aes_key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext
