#!/bin/bash

wget -O pin.tar.gz https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.19-98425-gd666b2bee-gcc-linux.tar.gz
tar xf pin.tar.gz -C .
mv pin-3.19* pin
rm pin.tar.gz

pushd pintool
make
popd
