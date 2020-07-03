# ppap

[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)
[![PyPI version](https://badge.fury.io/py/ppapzip.svg)](https://badge.fury.io/py/ppapzip)
[![Python Versions](https://img.shields.io/pypi/pyversions/ppapzip.svg)](https://pypi.org/project/ppapzip/)

Utility to simplify zip file encryption using RSA keys.  
~ for eradicate ppap ~

## Overview

PPAP means 

```
- Password encrypted zip file
- Password
- Apartly Sending
- Protocol
```

Original Meaning in Japanese.

```
- Passwordつきzip暗号化ファイルを送ります
- Passwordを送ります
- Aん号か*
- Protocol
```

\* = 暗号化 = Encryption

[JIPDEC - S/MIME利用の最新動向](https://itc.jipdec.or.jp/common/images/4_20170227_otaishi.pdf)


### Pros
- Easy to send.
- Misdelivery Prevention.

### Cons
- The recipient must be find the password and type it.
- Bypassing malware detection filters.
- In the first place, sending the password twice does not guarantee confidentiality.


## Usage

### Encryption
```bash
# it generates /path/to/your/ppap-yyyymmdd_HHMMssSSSSSS.zip
$ ppap --encrypt /path/to/your/file --key ~/.ssh/your_key.pub
```

### Decryption
```bash
$ ppap --decrypt /path/to/your/ppap-yyyymmdd_HHMMssSSSSSS.zip --key ~/.ssh/your_key
```

### Help
```
$ ppap -h
```

## Installation
```
$ pip install ppapzip
```

The source code for ppap is hosted at GitHub, and you may download, fork, and review it from this repository(https://github.com/sumeshi/ppap).
Please report issues and feature requests. :sushi: :sushi: :sushi:

## License
ppap is released under the [MIT](LICENSE) License.
