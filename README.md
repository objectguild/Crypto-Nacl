# Crypto-Nacl
A binding to libsodium for Pharo, updated for Libsodium version 1.0.18.

[![Build Status](https://github.com/objectguild/Crypto-Nacl/workflows/Build/badge.svg)](https://github.com/objectguild/Crypto-Nacl/actions?query=workflow%3ABuild)
[![Pharo 7.0](https://img.shields.io/badge/Pharo-7.0-informational)](https://pharo.org)
[![Pharo 8.0](https://img.shields.io/badge/Pharo-8.0-informational)](https://pharo.org)

Adapted from [SmalltalkHub](http://static.smalltalkhub.com/tonyg/Crypto-Nacl/index.html). The original author is [Tony Garnock-Jones](https://github.com/tonyg), with contributions from [Hernán Morales Durand](https://github.com/hernanmd).

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
