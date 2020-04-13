#!/bin/bash

if [ $# -eq 0 ]
then
    echo "ACASH systemd unit setup."
    echo -e "Run:\n$0 user\nor install for current user\n$0 $USER"
    exit 1
fi

if id "$1" >/dev/null 2>&1
then
    echo "Installing ACASH service for $1 user..."
else
    echo -e "User $1 does not exist.\nTo add user run the following command:\nsudo adduser --disabled-password --gecos '' $1"
    exit 1
fi

cat > /tmp/config_setup.sh << EOF
#!/bin/bash
if ! [[ -d ~/.acash ]]
then
    mkdir -p ~/.acash
fi

if ! [[ -f ~/.acash/acash.conf ]]
then
    echo "rpcuser=rpc`pwgen 15 1`" > ~/.acash/acash.conf
    echo "rpcpassword=rpc`pwgen 15 1`" >> ~/.acash/acash.conf
fi
EOF
chmod +x /tmp/config_setup.sh
sudo -H -u $1 /tmp/config_setup.sh
sudo -H -u $1 ~/acash-pkg/fetch-params.sh


cat > /etc/systemd/system/acash.service << EOF
[Unit]
Description=acash

[Service]
ExecStart=`cd ~; pwd`/acash-pkg/acashd
User=$1
Restart=always


[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable acash
systemctl start acash

systemctl status acash
