![ACASH Logo](http://acashex.info/wp-content/uploads/2020/03/achchain.png)
![ACASH Logo](http://acashex.info/wp-content/uploads/2020/02/acashcoin.png)

=======
# ACASH
**Keep running wallet to strengthen the ACASH network. Backup your wallet in many locations & keep your coins wallet offline.**

### Ports:
- RPC port: 2022
- P2P port: 2020

Install
-----------------
### Linux

### [Quick guide for beginners](https://github.com/acash/acash/wiki/Quick-guide-for-beginners)

Install required dependencies:
```{r, engine='bash'}
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake
```

Execute the build command:
```{r, engine='bash'}
# Clone ACASH Repository
git clone https://github.com/acash/acash
# Build
cd acash/
./zcutil/build.sh -j$(nproc)
# fetch key
./zcutil/fetch-params.sh
```

Usage:
```{r, engine='bash'}
# Run
./src/acashd
# Test getting information about the network
cd src/
./acash-cli getmininginfo
# Test creating new transparent address
./acash-cli getnewaddress
# Test creating new private address
./acash-cli z_getnewaddress
# Test checking transparent balance
./acash-cli getbalance
# Test checking total balance 
./acash-cli z_gettotalbalance
# Check all available wallet commands
./acash-cli help
# Get more info about a single wallet command
./acash-cli help "The-command-you-want-to-learn-more-about"
./acash-cli help "getbalance"
```

### Windows
The ACASH Windows Command Line Wallet can only be built from ubuntu for now.

Install required dependencies:
```
apt-get update \
&& apt-get install -y \
    curl build-essential pkg-config libc6-dev m4 g++-multilib autoconf \
    libtool ncurses-dev unzip git python zlib1g-dev wget bsdmainutils \
    automake p7zip-full pwgen mingw-w64 cmake
```

Execute the build command:
```
./zcutil/build-win.sh -j$(nproc)
```

### Docker

Build
```
$ docker build -t ach/acash .
```

Create a data directory on your local drive and create a acash.conf config file
```
$ mkdir -p /ops/volumes/acash/data
$ touch /ops/volumes/acash/data/acash.conf
$ chown -R 999:999 /ops/volumes/acash/data
```

Create acash.conf config file and run the application
```
$ docker run -d --name acash-node \
  -v acash.conf:/acash/data/acash.conf \
  -p 2020:2020 -p 127.0.0.1:2022:2022 \
  ach/acash
```

Verify acash-node is running
```
$ docker ps
CONTAINER ID        IMAGE                  COMMAND                     CREATED             STATUS              PORTS                                              NAMES
31868a91456d        ach/acash          "acashd --datadir=..."   2 hours ago         Up 2 hours          127.0.0.1:2022->2022/tcp, 0.0.0.0:2020->2020/tcp   acash-node
```

Follow the logs
```
docker logs -f acash-node
```

The cli command is a wrapper to acash-cli that works with an already running Docker container
```
docker exec -it acash-node cli help
```

## Using a Dockerfile
If you'd like to have a production btc/acash image with a pre-baked configuration
file, use of a Dockerfile is recommended:

```
FROM ach/acash
COPY acash.conf /acash/data/acash.conf
```

Then, build with `docker build -t my-acash .` and run.

### Windows
Windows build is maintained in [acash-win project](https://github.com/acashcrypto/acash-win).

Security Warnings
-----------------

**ACASH is experimental and a work-in-progress.** Use at your own risk.
