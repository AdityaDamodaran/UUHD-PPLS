 
# SPDX-FileCopyrightText: 2021 University of Luxembourg
# SPDX-License-Identifier: CC0-1.0
# SPDXVersion: SPDX-2.2

# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://vagrantcloud.com/search.
  config.vm.box = "hashicorp/bionic64"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # NOTE: This will enable public access to the opened port
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine and only allow access
  # via 127.0.0.1 to disable public access
  # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
     vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
     vb.memory = "1024"
  end
  #
  # View the documentation for the provider you are using for more
  # information on available options.

  # Enable provisioning with a shell script. Additional provisioners such as
  # Ansible, Chef, Docker, Puppet and Salt are also available. Please see the
  # documentation for more information about their specific syntax and use.
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y openssl gcc python3 python3-pip flex bison byacc git cmake
    sudo su
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
    make install
    cd ..
    cd pbc-0.5.14
    ./configure
    make
    make install
    cd ..
    cd charm/charm/core/math/pairing/relic
    git clone https://github.com/relic-toolkit/relic.git
    cd relic
    git checkout -q 0534bd5cc7
    cd ..
    mkdir relic-target && cd relic-target
    ../buildRELIC.sh ../relic/
    cd /home/vagrant/requirements/charm
    ./configure.sh --enable-pairing-relic
    make
    make install
    ldconfig -v
    cd /vagrant
    python3 -m pip install -r requirements.txt 
  SHELL
end
