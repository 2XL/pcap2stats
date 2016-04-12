#!/usr/bin/env bash




# dependency [1]
sudo apt-get install autoconf automake libtool
sudo apt-get install libpcap-dev



wget http://tstat.polito.it/download/tstat-3.0.1.tar.gz
# wget http://tstat.polito.it/download/tstat-3.x.y.tar.gz
tar -xzvf tstat-3.0.1.tar.gz
cd tstat-3.0.1




./autogen.sh # [1] (with sudo)
./configure  --enable-libtstat --enable-zlib # [2]
make
make install #  (with root privileges)



