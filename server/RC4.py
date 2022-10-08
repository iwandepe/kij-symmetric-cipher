import numpy as np

class RC4_encryption:
    def __init__(self, text, key):
        self.text = text
        self.key = key
        self.iv = "RC4"
        self.process()

    def process(self):
        S = self.KSA()
        data = np.array(self.PRGA(S, len(self.text)))
        data_ord = np.array([ord(c) for c in self.text])
        res = data_ord ^ data
        self.result = "".join([chr(c) for c in res])

    def KSA(self):
        key_length = len(self.key)
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + self.key[i % key_length]) % 256
            S[i], S[j] = S[j], S[i]

        return S

    def PRGA(self, S, n):
        i = 0
        j = 0
        key = []

        while n>0:
            n = n-1
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            key.append(K)
        return key