#!/bin/sh
# SPDX-FileCopyrightText: 2021 University of Luxembourg
# SPDX-License-Identifier: CC0-1.0
# SPDXVersion: SPDX-2.2
sudo apt-get update
sudo apt-get install -y openssl gcc python3.6 python3-pip flex bison byacc git cmake libssl-dev
mkdir requirements && cd requirements
wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
git clone "https://github.com/JHUISI/charm.git"
cd charm
git checkout -q acb55513b2
cd ..
tar -xvf gmp-6.2.1.tar.xz
tar -xvf pbc-0.5.14.tar.gz
cd gmp-6.2.1
./configure
make
sudo make install
cd ..
cd pbc-0.5.14
./configure
make
sudo make install
cd ..
cd charm/charm/core/math/pairing/relic
git clone https://github.com/relic-toolkit/relic.git
cd relic
git checkout -q 0534bd5cc7
cd ..
mkdir relic-target && cd relic-target
sudo ../buildRELIC.sh ../relic/
cd ../../../../../../
./configure.sh --enable-pairing-relic
make
sudo make install
sudo ldconfig -v
cd ../../
python3.6 -m pip install -r requirements.txt
python3.6 ./protocol.py -h
