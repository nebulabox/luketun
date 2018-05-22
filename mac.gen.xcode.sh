#!/usr/bin/env bash
cmake_fullpath=$(pwd -P)
build_temppath="$HOME/cmake_output/luketun/xcode"

mkdir -p $build_temppath
pushd $build_temppath
cmake -DCMAKE_BUILD_TYPE=Debug -G "Xcode" ${cmake_fullpath}

popd

