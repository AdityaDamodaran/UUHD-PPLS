<!--
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2

Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
-->
# Unlinkable Updatable Hiding Databases and Privacy-Preserving Loyalty Programs

This repository contains the source code for an implementation of the HD (Unlinkable Updatable Hiding Database) primitive described in our paper titled "Unlinkable Updatable Hiding Databases and Privacy-Preserving Loyalty Programs", published at PETS 2021. It also includes an implementation of the Privacy-Preserving Loyalty Program protocol put forward in this paper, which uses the aforementioned primitive. 

These implementations were used to measure the storage and computation costs of the cryptographic operations in our primitive and the protocol, for the _Efficiency Analysis_ sections of our paper.


## Installation

### Virtual Machine (Vagrant)
You can the use `Vagrantfile` file in this repository to spin up a virtual machine with a pre-configured execution environment using Vagrant: https://www.vagrantup.com.

1. Download and run the VirtualBox installer for your operating system from the VirtualBox downloads page: https://www.virtualbox.org/wiki/Downloads

2. Download and run the Vagrant installer for your operating system from the Vagrant downloads page: https://www.vagrantup.com/downloads

3. Clone this repository, and run the `vagrant up` command from its root directory:
```bash
$ git clone https://gitlab.uni.lu/APSIA/uuhd-ppls.git
$ cd uuhd-ppls
$ vagrant up
```

4. Once the virtual machine is ready, and a window with a login prompt shows up, log in with `vagrant:vagrant`.

5. Wait until the script finishes installing all prerequisites. The code will then be accessible from the `/vagrant` directory.
```bash 
$ cd /vagrant
$ python3 ./protocol.py -h
```


### Manual Installation (Ubuntu)

Instructions are available [here](doc/install_bionic.md).

### Manual Installation
Our code requires Python 3.6, and the Charm-Crypto library (v0.50) built with the Relic Toolkit (v0.5.0), as described on these pages:

1. Relic Toolkit: https://jhuisi.github.io/charm/relic.html#charm-with-relic

   (Please download Relic from its [github repository](https://github.com/relic-toolkit/relic) and checkout the version identified by commit id `0534bd5cc7`.)
2. Charm-Crypto:  https://jhuisi.github.io/charm/install_source.html#platform-install-manual
   
   (Please download Charm from its [github repository](https://github.com/JHUISI/charm))
> Note: Charm-Crypto additionally requires PBC (v0.5.14) and GMP (v6.2.1). 

Finally, use the following command to install Openpyxl (v3.0.6) and Texttable (v1.6.3): 
```bash
$ python3 -m pip install -r requirements.txt
```


## Usage
```bash
Usage: python3 ./protocol.py [-h] [-k K] [-r] N

positional arguments:
  N                    Database size (100-65000)

optional arguments:
  -h, --help           show this help message and exit
  -k K, --keylength K  Paillier Encryption key size (Supported values: 1024, 2048; Default: 2048)
  -r, --randomise      Randomise database state 
  -v, --verbose        Display database contents and commitment values
```
### Examples
 - Run tests against a database of size N = 100, random database values, and a Paillier key length of 2048 bits:
   ```bash
   $ python3 ./protocol.py -k 2048 -r 100
   ```

- Run tests against a database of size N = 16000, and a Paillier key length of 2048 bits:
  ```bash
  $ python3 ./protocol.py -k 2048 16000
  ```

- Run tests against a database of size N = 65000, with random database values, and whilst displaying database contents:
  ```bash
  $ python3 ./protocol.py -r -v 65000
  ```

### Results
The program prints measurements to console, and also appends these measurements to a file named `UUHD-PPLS-Timing-Data.xlsx`. 

```
+----+---------+---------------------+--------------+---------------------+
| N  | DB Size | Paillier Key Length | First Update | Computation of Vcom |
+====+=========+=====================+==============+=====================+
| 10 | 100     | 2048                | 0.384        | 0.001               |
+----+---------+---------------------+--------------+---------------------+
+----------------+--------------+--------------+--------------+----------+
| 1 Entry Update | 1 Entry Read | 5 Entry Read | Registration | Purchase |
+================+==============+==============+==============+==========+
| 0.000          | 4.271        | 14.013       | 0.385        | 7.642    |
+----------------+--------------+--------------+--------------+----------+
+------------+-------------------+------------------+------------------+-------+
| Redemption | 1 Entry Profiling |     5 Entry      |     10 Entry     | Setup |
|            |                   |    Profiling     |    Profiling     |       |
+============+===================+==================+==================+=======+
| 5.806      | 6.245             | 33.575           | 61.165           | 0.366 |
+------------+-------------------+------------------+------------------+-------+
```

## The Paper
Damodaran A. and Rial A. (2021) Unlinkable Updatable Hiding Databases and Privacy-Preserving Loyalty Programs. Proceedings on Privacy Enhancing Technologies, Vol.2021 (Issue 3), pp. 95-121. https://doi.org/10.2478/popets-2021-0039

## License
This project is licensed under the GPLv3 license.

## Acknowledgements

This research was supported by the Luxembourg National Research Fund (FNR) CORE
project ???Stateful Zero-Knowledge??? (Project code: C17/11650748).
