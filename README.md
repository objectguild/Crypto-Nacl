# Crypto-Nacl
A binding to Libsodium for Pharo, updated for Libsodium version 1.0.18.

[![Build Status](https://github.com/objectguild/Crypto-Nacl/workflows/Build/badge.svg)](https://github.com/objectguild/Crypto-Nacl/actions?query=workflow%3ABuild)
[![Pharo 7.0](https://img.shields.io/badge/Pharo-7.0-informational)](https://pharo.org)
[![Pharo 8.0](https://img.shields.io/badge/Pharo-8.0-informational)](https://pharo.org)

Adapted from [SmalltalkHub](http://static.smalltalkhub.com/tonyg/Crypto-Nacl/index.html).

The original author is [Tony Garnock-Jones](https://github.com/tonyg), with contributions from [Hernán Morales Durand](https://github.com/hernanmd). See Tony's article on the original code for Squeak and Pharo here: http://www.eighty-twenty.org/index.cgi/tech/smalltalk/nacl-for-squeak-and-pharo-20130601.html

[Ken Dickey](https://github.com/KenDickey) ported this to Cuis Smalltalk a while back: https://github.com/KenDickey/Cuis-Smalltalk-Crypto-NaCl

Since the original implementation by Tony Garnock-Jones, Libsodium has evolved and expanded its functionality, which hasn't been included in this library (yet). See its extensive documentation here: https://doc.libsodium.org/

You can find the original Crypto NaCl site here: http://nacl.cr.yp.to

A good description of the motivation for the original Crypto NaCl library can be found here: [The security impact of a new cryptographic library (PDF)](http://cr.yp.to/highspeed/coolnacl-20120725.pdf)

## Loading
The original `ConfigurationOfNacl` has been replaced with `BaselineOfCryptoNacl`, which has groups `core` and `tests`, with default only loading `core`.

```Smalltalk
Metacello new
  baseline: 'CryptoNacl';
  repository: 'github://objectguild/Crypto-Nacl:master';
  load.
```

## Installing Libsodium
In order to use **Crypto-Nacl**, you have to have the Libsodium native library installed on the target system.

### macOS
On macOS, this is done by installing using Homebrew:

```
brew install libsodium
```
## Ubuntu Linux
On Ubuntu Linux, this is done by installing the libsodium-dev package:

```
sudo apt-get install -y libsodium-dev
```
