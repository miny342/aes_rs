from Crypto.Cipher import AES
from hashlib import md5, sha256, sha224

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
data = sha256(f"data0".encode()).digest()
cipher = AES.new(key, AES.MODE_CBC)
ciphertext = cipher.encrypt(data)
print("cbc")
print(cipher.iv)
print(data)
print(key)
print(ciphertext)

key = md5(f"key0".encode()).digest()
data = sha224(f"data0".encode()).digest()
cipher = AES.new(key, AES.MODE_OFB)
ciphertext = cipher.encrypt(data)
print("ofb")
print(cipher.iv)
print(data)
print(key)
print(ciphertext)

key = md5(f"key0".encode()).digest()
data = sha224(f"data0".encode()).digest()
cipher = AES.new(key, AES.MODE_CFB, segment_size=128)
ciphertext = cipher.encrypt(data)
print("cfb seg128")
print(cipher.iv)
print(data)
print(key)
print(ciphertext)

key = md5(f"key0".encode()).digest()
data = sha224(f"data0".encode()).digest()
cipher = AES.new(key, AES.MODE_CFB, segment_size=16)
ciphertext = cipher.encrypt(data)
print("cfb seg16")
print(cipher.iv)
print(data)
print(key)
print(ciphertext)
