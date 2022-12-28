# GOST Engenhoca
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/engine/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/engine?status.png)](http://godoc.org/github.com/pedroalbanese/engine)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/engine/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/engine/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/engine)](https://goreportcard.com/report/github.com/pedroalbanese/engine)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/engine)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/engine)](https://github.com/pedroalbanese/engine/releases)

### GOST Toolkit Lite (TC26 Compliant)
Cross-platform hybrid cryptography toolkit for bulk encryption, recursive message digest, key derivation function (KDF), message authentication code (MAC), shared key agreement (VKO), digital signature and TLS 1.2 for small or embedded systems. 

**GOST refers to a set of technical standards maintained by the Euro-Asian Council for Standardization, Metrology and Certification (EASC), a regional standards organization operating under the auspices of the Commonwealth of Independent States (CIS).**

## Roll of Algorithms
#### GOST is GOvernment STandard of Russian Federation (and Soviet Union):
  - TLS 1.2 Transport Layer Security (RFC 5246)
  - GOST R 34.11-2012 Стрибог (Streebog) hash function 256/512-bit (RFC 6986)
  - GOST R 34.10-2012 public key signature function (RFC 7091)
  - VKO GOST R 34.10-2012 key agreement function (RFC 7836)
  - GOST R 34.12-2015 128-bit block cipher Кузнечик (Kuznechik) (RFC 7801)
  - GOST R 34.12-2015 64-bit block cipher Магма (Magma) (RFC 8891)
  - MGM AEAD mode for 64 and 128 bit ciphers (RFC 9058)

### Symmetric:
- **Block Ciphers:**
   - GOST R 34.12-2015 Magma (default)
   - GOST R 34.12-2015 Kuznechik (Grasshopper)

- **Mode of Operation:**
   - MGM: Multilinear Galois Mode (AEAD)
   - CFB: Cipher Feedback Mode (AEAD)
   - CTR: Counter Mode (AEAD)
   - OFB: Output Feedback Mode (AEAD)

- **Message Digest Algorithm:**
   - GOST R 34.11-2012 Streebog 256/512-bit 
   
### Asymmetric:
- **Public key Algorithm:**
   - GOST R 34.10-2012 256/512-bit

- **Supported ParamSets:**
   - GOST R 34.10-2012 256-bit: A, B, C, D
   - GOST R 34.10-2012 512-bit: A, B

## Features
* **Cryptographic Functions:**
   * Symmetric Encryption + AEAD Mode
   * Digital Signature (ECDSA-like)
   * Recursive Hash Digest + Check 
   * CMAC (Cipher-based message authentication code)
   * HMAC (Hash-based message authentication code)
   * HKDF (HMAC-based key derivation function)
   * PBKDF2 (Password-based key derivation function 2)
   * VKO (выработка ключа общего) Shared Key Agreement (ECDH)
   * TLS 1.2 (Transport Layer Security)
   
* **Non-cryptographic Functions:**

   * Privacy-Enhanced Mail (PEM format)
   * RandomArt (OpenSSH-like)

## Usage
<pre> -128
       Block size: 64 or 128. (for symmetric encryption only) (default 64)
 -512
       Key length: 256 or 512. (default 256)
 -cert string
       Certificate path/name. (default "Certificate.pem")
 -check string
       Check hashsum file. ('-' for STDIN)
 -crypt string
       Encrypt/Decrypt with symmetric ciphers.
 -digest string
       File/Wildcard to generate hashsum list. ('-' for STDIN)
 -hex string
       Encode binary string to hex format and vice-versa.
 -hkdf int
       HMAC-based key derivation function with a given output bit length.
 -info string
       Associated data, additional info. (for HKDF and AEAD encryption)
 -ipport string
       Local Port/remote's side Public IP:Port.
 -iter int
       Iterations. (for PBKDF2 command) (default 1)
 -iv string
       Initialization vector. (for non-AEAD symmetric encryption)
 -key string
       Private/Public key, depending on operation.
 -mac string
       Compute hash-based/cipher-based message authentication code.
 -mode string
       Mode of operation: MGM, CFB, CTR or OFB. (default "MGM")
 -paramset string
       Elliptic curve ParamSet: A, B, C, D. (default "A")
 -pbkdf2
       Password-based key derivation function 2.
 -pkey string
       Generate keypair, Generate certificate. [keygen|certgen]
 -private string
       Private key path. (for keypair generation) (default "Private.pem")
 -public string
       Public key path. (for keypair generation) (default "Public.pem")
 -pwd string
       Password. (for Private key PEM encryption)
 -rand int
       Generate random cryptographic key with a given output bit length.
 -recursive
       Process directories recursively. (for DIGEST command only)
 -salt string
       Salt. (for PBKDF2 and HKDF commands)
 -signature string
       Input signature. (verification only)
 -tcp string
       Encrypted TCP/IP Transfer Protocol. [server|ip|client]
 -version
       Print version information.</pre>

## Examples
#### Asymmetric GOST2012 keypair generation:
```sh
./engine -pkey keygen [-512] [-paramset B] [-pwd "pass"]
```
#### Parse keys info:
```sh
./engine -pkey [text|modulus] [-pwd "pass"] -key private.pem
./engine -pkey [text|modulus|randomart] -key public.pem
```
#### Digital signature:
```sh
./engine -pkey sign -key private.pem [-pwd "pass"] < file.ext > sign.txt
sign=$(cat sign.txt|awk '{print $2}')
./engine -pkey verify -key public.pem -signature $sign < file.ext
echo $?
```
#### VKO Shared key agreement:
```sh
./engine -pkey derive -key private.pem -public peerkey.pem
```
#### Generate Certificate:
```sh
./engine -pkey certgen -key private.pem [-pwd "pass"] [-cert "output.ext"]
```
#### Parse Certificate info:
```sh
./engine -pkey [text|modulus] -cert certificate.pem
```
#### TLS Layer (TCP/IP):
```sh
./engine -tcp ip > PubIP.txt
./engine -tcp server -cert certificate.pem -key private.pem [-ipport "8081"]
./engine -tcp client -cert certificate.pem -key private.pem [-ipport "127.0.0.1:8081"]
```
#### Encryption/decryption with Magma (GOST R 34.12-2015) block cipher (default):
```sh
./engine -crypt enc -key $shared < plaintext.ext > ciphertext.ext
./engine -crypt dec -key $shared < ciphertext.ext > plaintext.ext
```
#### Encryption/decryption with Kuznyechik (GOST R 34.12-2015) block cipher:
```sh
./engine -crypt enc -128 -key $shared < plaintext.ext > ciphertext.ext
./engine -crypt dec -128 -key $shared < ciphertext.ext > plaintext.ext
```
#### CMAC-Kuznechik (cipher-based message authentication code):
```sh
./engine -mac cmac -128 -key $128bitkey < file.ext
./engine -mac cmac -128 -key $128bitkey -signature $128bitmac < file.ext
```
#### Streebog256/512 hashsum:
```sh
./engine -digest - [-512] < file.ext
./engine -digest *.* [-512]
```
#### HMAC-Streebog256/512:
```sh
./engine -mac hmac [-512] -key $256bitkey < file.ext
./engine -mac hmac [-512] -key $256bitkey -signature $256bitmac < file.ext
```
#### HKDF (HMAC-based key derivation function 256-bit output):
```sh
./engine -hkdf 256 [-512] -key "IKM" -info "AD" -salt "salt"
```
#### PBKDF2 (password-based key derivation function):
```sh
./engine -pbkdf2 [-512] -key "pass" -iter 10000 -salt "salt" -crypt enc < plaintext.ext > ciphertext.ext
```
#### Bin to Hex/Hex to Bin:
```sh
./engine -hex enc < File.ext > File.hex
./engine -hex dec < File.hex > File.ext
./engine -hex dump < File.ext
```

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2023 Pedro F. Albanese - ALBANESE Research Lab.
