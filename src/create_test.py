from Crypto.Cipher import AES
from hashlib import md5, sha256

for i in range(1):
    key = md5(f"key{i}".encode()).digest()
    data = md5(f"data{i}".encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)
    print(f"md5 {i}:")
    print(data)
    print(key)
    print(ciphertext)

for i in range(1):
    key = sha256(f"key192{i}".encode()).digest()
    key = key[0:24]
    data = md5(f"data{i}".encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)
    print(f"sha256 192 {i}:")
    print(data)
    print(key)
    print(ciphertext)

for i in range(1):
    key = sha256(f"key{i}".encode()).digest()
    data = md5(f"data{i}".encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)
    print(f"sha256 {i}:")
    print(data)
    print(key)
    print(ciphertext)


key = md5(f"key0".encode()).digest()
data = md5(f"data0".encode()).digest()
cipher = AES.new(key, AES.MODE_CBC)
ciphertext = cipher.encrypt(data)
print("cbc")
print(cipher.iv)
cipher = AES.new(key, AES.MODE_CBC, cipher.iv)
plain = cipher.decrypt(ciphertext)
print(data)
print(key)
print(ciphertext)
