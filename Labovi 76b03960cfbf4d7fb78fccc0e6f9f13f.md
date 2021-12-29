# Labovi

## ARP-spoofing

Cloned git repo: `git clone https://github.com/mcagalj/SRP-2021-22`

In directory run bash script that started docker containers: `sh ./start/sh`

Entered docker container with `docker exec -it station-1 bash` and pinged station-2 with `ping station-2`

Got containers IP and MAC addresses using `ipconfig`

station-1:
`IP: 172.21.0.2`

`ETH: 00:02`

station-2:

`IP: 172.21.0.4`

`ETH: 00:04`

evil-station:

`IP: 172.21.0.3`

`ETH: 00:03`

Emulated conversation between 2 stations, entered container 1 and 2 with aforementioned command. On station-2 used command: `netstat -l -p 8000` and on station-1: `netstat station-2 8000`. After that every "message" we write in one of containers the other one gets it.

On evil-station we listened on eth0 with `tcpdump` command. To arpspoof we used command `arpspoof -t station-1 -r station-2`. And to filter out messages we don't want to see we used `tcpdump -XA station-1 and not arp`.
After that we blocked communication between 2 stations using DoS attack with command:

`echo 0 > /proc/sys/net/ipv4/ip_forward`

## Symetric key - Crypto challenge (Brute force)

In this lab we used brute force to decrypt the ciphertext encrypted with symmetric key and get the image from it.

As the image from the lab didn't work for me I encrpyted my own image using this function.

```python
def create_image():
    filename = 'slika.png'

    key = int.from_bytes(os.urandom(32), "big") & int('1'*22, 2)
    key_base64 = base64.urlsafe_b64encode(key.to_bytes(32, "big"))
    f = Fernet(key_base64) 

    with open(filename, "rb") as file:
        plaintext = file.read()

    with open(hash(filename) + '.encrypted', 'wb') as file:
        file.write(f.encrypt(plaintext))
```

I created random key with entropy of 22 bits and using Fernet encrypted the image plaintext and then saved it in the file witch name is firstly hashed with hash function.

```python
def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()
```

After that we opened the file with ciphertext and using while loop created random keys and tried to decipher it. We know that we used the valid key if the first 32 chars of the plaintext are PNG header, we tested it with test_png function. After we found the right key we decrypt ciphertext and store plaintext in the file called BINGO.png.

```python
def brute_force():
    filename = hash('slika.png') + ".encrypted"
    with open(filename, "rb") as file:
        ciphertext = file.read()
    
    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)

        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr + 1:,}", end="\r")
        
        try:
            plaintext = Fernet(key).decrypt(ciphertext)
            
            header = plaintext[:32]
            if test_png(header):
                print(f"[+] KEY FOUND: {key}")
                with open("BINGO.png", "wb") as file:
                    file.write(plaintext) 
                break

        except Exception:
            pass
        
        ctr += 1
```

```python
def test_png(text):
    if text.startswith(b"\211PNG\r\n\032\n"):
        return true
```

# **Message authentication and integrity**

In this challenge we got 2 images and we need to find out which image wasn’t changed, it’s integrity was secured.

First we loaded public key:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY
```

After that we verified the signature with:

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
```

After that we loaded images messages and signatures and provided it to verify function which gave us result.

# **Password-hashing (iterative hashing, salt, memory-hard functions)**

In this lab we tested few of cryptographic hash functions to see how they work and how they affect performance. But first we installed all of requirements from requirements.txt file.

We copied this code which has decorator function which calculates time for each hash function:

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "Linux crypt 5 000",
            "service": lambda: linux_hash(password, measure=True, rounds=5000)
        },
        {
            "name": "Linux crypt 10 000",
            "service": lambda: linux_hash(password, measure=True, rounds=10000)
        },
        {
            "name": "Linux crypt 50 000",
            "service": lambda: linux_hash(password, measure=True, rounds=50000)
        },
        {
            "name": "Linux crypt 100 000",
            "service": lambda: linux_hash(password, measure=True, rounds=100000)
        },
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

All of the functions that we tested can be found in TESTS. We see how performance changes when we have more iterations, e.g. Linux crypt function.
We also used Argon2 function which could be memory hard or time hard function. We saw spikes  in performance of memory and CPU depending on howe we used Argon2.