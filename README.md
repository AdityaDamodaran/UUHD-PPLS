# Unlinkable Updatable Hiding Databases and Privacy-Preserving Loyalty Programs

This repository contains the source code for an implementation of the UUHD (Unlinkable Updatable Hiding Database) primitive described in our paper titled "Unlinkable Updatable Hiding Databases and Privacy-Prserving Loyalty Programs". It also includes an implementation of the Privacy-Preserving Loyalty Program protocol put forward in this paper which uses the aforementioned primitive. These implementations were used to measure the storage and computation costs of the cryptographic operations in our primitive and the protocol, for the _Efficiency Analysis_ sections of our paper.


# Installation

## Virtual Machine (Vagrant)
You can the Vagrantfile in this repository to spin up a virtual machine with a pre-configured execution environment using Vagrant: ([https://www.vagrantup.com/]).

The code will then be accessible from the `/vagrant` directory, in the virtual machine.


## Manual Installation
Our code requires the Charm-Crypto library (v0.50) built with the Relic toolkit (0.5.0) , as described on these pages:

1. Relic toolkit : [https://jhuisi.github.io/charm/relic.html#charm-with-relic]
2. Charm-Crypto [https://jhuisi.github.io/charm/install_source.html#platform-install-manual]

Charm-Crypto additionally requires PBC (v0.5.14) and GMP (v6.2.1). 

# Usage
```bash
python3 ./protocol.py 100
```
