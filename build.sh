#!/bin/bash

wget -O pin.tar.gz https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.18-98332-gaebd7b1e6-gcc-linux.tar.gz
tar xf pin.tar.gz -C .
mv pin-3.18* pin
rm pin.tar.gz

pushd pintool
make
popd
