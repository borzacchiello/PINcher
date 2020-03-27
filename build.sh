#!/bin/bash

wget -O pin.tar.gz https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.13-98189-g60a6ef199-gcc-linux.tar.gz
tar xf pin.tar.gz -C .
mv pin-3.13* pin
rm pin.tar.gz

pushd pintool
make
popd
