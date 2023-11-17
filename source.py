from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from Crypto.PublicKey import RSA as _RSA
from random import randint
from secret import FLAG


class RSA:

    def __init__(self, size):
        self.e = 65537
        self.n = 1

        p = getPrime(size)
        r = randint(10, 20)
        for _ in range(r):
            self.n *= p

        self.key = _RSA.construct((self.n, self.e), True)

    def encrypt(self, message):
        message = bytes_to_long(message)
        return pow(message, self.e, self.n)

    def export_key(self):
        return self.key.export_key('PEM').decode()


def main():
    rsa = RSA(512)
    key = rsa.export_key()
    enc = long_to_bytes(rsa.encrypt(FLAG))

    with open("key.pem", "w") as f:
        f.write(key)

    with open("flag.enc", "wb") as f:
        f.write(enc)


if __name__ == "__main__":
    main()
