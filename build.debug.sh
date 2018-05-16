#!/usr/bin/env bash

mkdir -p build
pushd build
cmake -DCMAKE_BUILD_TYPE=Debug -G "Unix Makefiles" ..

echo ">>>>>> start make project >>>>>"
make -j8

popd
