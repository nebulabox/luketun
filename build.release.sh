#!/usr/bin/env bash
cmake_fullpath=$(pwd -P)
build_temppath="$HOME/cmake_output/luketun/release"

rm -rf $build_temppath
mkdir -p $build_temppath
pushd $build_temppath
cmake -DCMAKE_BUILD_TYPE=Release -G "Ninja" ${cmake_fullpath}

echo ">>>>>> start build release project >>>>>"
ninja

popd

