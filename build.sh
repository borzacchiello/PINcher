#!/bin/bash

wget -O pin.tar.gz https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.20-98437-gf02b61307-gcc-linux.tar.gz
tar xf pin.tar.gz -C .
mv pin-3.20* pin
rm pin.tar.gz

pushd pintool
make
popd
