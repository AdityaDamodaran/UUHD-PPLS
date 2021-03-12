<!--
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2

Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
-->
# Unlinkable Updatable Hiding Databases and Privacy-Preserving Loyalty Programs

This repository contains the source code for an implementation of the HD (Unlinkable Updatable Hiding Database) primitive described in our paper titled "Unlinkable Updatable Hiding Databases and Privacy-Prserving Loyalty Programs". It also includes an implementation of the Privacy-Preserving Loyalty Program protocol put forward in this paper, which uses the aforementioned primitive. 

These implementations were used to measure the storage and computation costs of the cryptographic operations in our primitive and the protocol, for the _Efficiency Analysis_ sections of our paper.


# Installation

## Virtual Machine (Vagrant)
You can the use `Vagrantfile` file in this repository to spin up a virtual machine with a pre-configured execution environment using Vagrant: https://www.vagrantup.com.

You must first install Vagrant, and then run the following command from the root directory of this repository:
```bash
$ vagrant up
```

The code will then be accessible from the `/vagrant` directory, in the virtual machine window that shows up after the script downloads and installs all prerequisites.


## Manual Installation
Our code requires Python 3.7, and the Charm-Crypto library (v0.50) built with the Relic toolkit (v0.5.0) , as described on these pages:

1. Relic toolkit : https://jhuisi.github.io/charm/relic.html#charm-with-relic
2. Charm-Crypto https://jhuisi.github.io/charm/install_source.html#platform-install-manual

> Note: Charm-Crypto additionally requires PBC (v0.5.14) and GMP (v6.2.1). 

Finally, use the following command to install Openpyxl and Texttable: 
```bash
$ python3 -m pip install -r requirements.txt
```


# Usage
```bash
Usage: python3 ./protocol.py [-h] [-k K] [-r] N

positional arguments:
  N                    Database size (100-65000)

optional arguments:
  -h, --help           show this help message and exit
  -k K, --keylength K  Paillier Encryption key size (Supported values: 1024, 2048)
  -r, --randomise      Randomise database state 
```

 - Run tests against a database of size N = 100, random database values, and a Paillier key length of 2048 bits:
   ```bash
   $ python3 ./protocol.py -k 2048 -r 100
   ```

# Acknowledgements

This research is supported by the Luxembourg National Research Fund (FNR) CORE
project “Stateful Zero-Knowledge” (Project code: C17/11650748).