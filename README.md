# ChaCha
GLua implementation of ChaCha

## Usage

```
local key = string.rep("a", 32)
local nonce = tostring(os.time()):sub(1, 8)
local plainText = string.rep("b", 512)

local cipherText = ChaCha.crypt(key, nonce, plainText, 20)

local decryptedText = ChaCha.crypt(key, nonce, cipherText, 20)
```

Full specifications can be found [here](https://cr.yp.to/chacha/chacha-20080128.pdf) and [here](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant).  
Test vectors can be found [here](https://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-00).
