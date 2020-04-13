#!/bin/bash

sudo apt -y update
sudo apt-get install -y libc6-dev g++-multilib python p7zip-full pwgen jq curl
cd ~

if [ -f acash.zip ]
then
    rm acash.zip
fi
wget -O acash.zip `curl -s 'https://api.github.com/repos/acashcommunity/acash/releases/latest' | jq -r '.assets[].browser_download_url' | egrep "acash.+x64.zip"`
7z x -y acash.zip
chmod -R a+x ~/acash-pkg
rm acash.zip

cd ~/acash-pkg
./fetch-params.sh

if ! [[ -d ~/.acash ]]
then
    mkdir -p ~/.acash
fi

if ! [[ -f ~/.acash/acash.conf ]]
then
    echo "rpcuser=rpc`pwgen 15 1`" > ~/.acash/acash.conf
    echo "rpcpassword=rpc`pwgen 15 1`" >> ~/.acash/acash.conf
fi

./acashd
