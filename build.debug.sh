#!/usr/bin/env bash
cmake_fullpath=$(pwd -P)
build_temppath="$HOME/cmake_output/luketun/debug"

mkdir -p $build_temppath
pushd $build_temppath
cmake -DCMAKE_BUILD_TYPE=Debug -G "Ninja" ${cmake_fullpath}

echo ">>>>>> start build debug project >>>>>"
ninja

popd

