#!/usr/bin/env bash
apt-get update
apt-get install openvswitch-switch
apt-get install mininet
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get -yq install wireshark
usermod -aG wireshark $(whoami)
apt-get install python3-pip
echo "export PATH=\"$PATH:$HOME/.local/bin\"" >> $HOME/.bashrc
pip3 install ryu
pip3 install mininet
