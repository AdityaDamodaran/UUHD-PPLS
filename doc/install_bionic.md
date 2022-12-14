<!--
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2

Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
-->
# Installation instructions (Ubuntu)

For best results, please use a fresh installation of Ubuntu 18.04 LTS (Bionic Beaver). We ran into a few issues whilst trying to install this project's dependencies on Ubuntu 20.04 LTS. 

You could alternatively use our `install_ubuntu.sh` script located in the root directory of this repository, as it includes all of the following installation commands.

## Instructions
 1. Start by installing all prerequisites for building charm:

    ```
    $ sudo apt-get update
    $ sudo apt-get install -y openssl gcc python3.6 python3-pip flex bison byacc git cmake libssl-dev
    ```

2. Clone our repository:
   ```
   $ git clone https://gitlab.uni.lu/APSIA/uuhd-ppls.git
   ```

3. Download GMP, PBC, and Charm-Crypto:

   ```
   $ cd uuhd-ppls
   $ mkdir requirements && cd requirements
   $ wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz
   $ wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
   $ git clone "https://github.com/JHUISI/charm.git"
   $ cd charm && git checkout -q acb55513b2
   $ cd ..
   $ tar -xvf gmp-6.2.1.tar.xz
   $ tar -xvf pbc-0.5.14.tar.gz
   ```

4. Build and install GMP and PBC (Warning: This will install GMP and PBC as root):

   ```
   $ cd gmp-6.2.1
   $ ./configure
   $ make
   $ sudo make install
   $ cd ..
   $ cd pbc-0.5.14
   $ ./configure
   $ make
   $ sudo make install
   $ cd ..
   ```

5. Download and prepare Relic pairing libraries:

   ```
   $ cd charm/charm/core/math/pairing/relic
   $ git clone https://github.com/relic-toolkit/relic.git
   $ cd relic
   $ git checkout -q 0534bd5cc7
   $ cd ..
   $ mkdir relic-target && cd relic-target
   $ sudo ../buildRELIC.sh ../relic/
   $ cd ../../../../../../
   ```

6. Build and install Charm-Crypto (Warning: This will install Charm-Crypto as root):

   ```
   $ ./configure.sh --enable-pairing-relic
   $ make
   $ sudo make install
   $ sudo ldconfig -v
   $ cd ../../
   ```

7. Install Openpyxl and Texttable:

   ```
   $ python3.6 -m pip install -r requirements.txt
   ```  

   Things should now work as expected. 
   ```
   $ python3.6 ./protocol.py -h
   ```




