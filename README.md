# (work-in-progress) QUIC with Low Latency Cryptography Areion 
## About
This is a fork of [quictls](https://github.com/quictls/openssl) to enable low-latency cryptographic permutation algorithm Areion.

Our research team is actively working on applying Areion to QUIC, which is one of the cryptographic applications, as part of our efforts to standardize Areion in the IETF.

We plan to gradually release the current implementation in this repository as we progress towards completing the integration of Areion to QUIC.
For the current status of the implementation, please refer to the "Status" section."

## Status
- We have experimentally added new TLS 1.3 ciphersuites with Areion enabled "TLS_AREION_256_OPP_SHA256" to quictls. (2023.7.22)

## About Areion
Areion is low-latency cryptographic permutation algorithm and includes applications such as hashing and AEAD processing mode like OPP. 

For more information on Areion, visit: https://eprint.iacr.org/2023/794

Reference codes of Areion is available at:
https://github.com/gmo-ierae/low-latency-crypto-areion

## Support Architecture
To run this software, the following environmental requirements are necessary.
- SIMD
- x86-64 architecture (with AES-NI support)

We have confirmed that this software can be built and executed on the following OS.
- Ubuntu 22.04

Note. Ubuntu is a registered trademark or trademark of Canonical Ltd. in the United States and other countries.

## How to Build
```
$ sudo apt update
$ sudo apt install --no-install-recommends make gcc libc-dev
$ mkdir build
$ cd build
$ ../Configure no-shared linux-x86_64
$ make
```

## How to Test
### Check OpenSSL Ciphers
```
$ ./apps/openssl ciphers -v | grep -i areion
```

### Check Secure Communication with New TLS1.3 CipherSuites Available Areion

Before executing the following command, please make sure to create the server certificate 'server.pem'.

- server side
```
$ ./apps/openssl s_server -cert server.pem -key private-key.pem -accept 10000 -ciphersuites "TLS_AREION_256_OPP_SHA256"
```

- client side
```
$ ./apps/openssl s_client -connect localhost:10000 -ciphersuites "TLS_AREION_256_OPP_SHA256"
```


# License
The source code is provided under the Apache License 2.0.
The full text is included in the file LICENSE.txt.

## Reference
The cryptographic algorithms implemented in this software were proposed in the following research paper.

```
@misc{cryptoeprint:2023/794,
      author = {Takanori Isobe and Ryoma Ito and Fukang Liu and Kazuhiko Minematsu and Motoki Nakahashi and Kosei Sakamoto and Rentaro Shiba},
      title = {Areion: Highly-Efficient Permutations and Its Applications (Extended Version)},
      howpublished = {Cryptology ePrint Archive, Paper 2023/794},
      year = {2023},
      doi = {10.46586/tches.v2023.i2.115-154},
      note = {\url{https://eprint.iacr.org/2023/794}},
      url = {https://eprint.iacr.org/2023/794}
}
```

## Notes
- This software is provided as a reference and has not been optimized.
- This software is experimentally implemented as runnning codes.

