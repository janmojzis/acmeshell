#!/bin/sh

version=`cat version`

build="`pwd`/build"
bin="${build}/bin"

rm -rf "${build}"
mkdir -p "${build}"
mkdir -p "${bin}"


mkdir -p "${build}/work"
cp source/*.py source/SOURCES "${build}/work"
( 
  cd "${build}/work"
  (
    echo "#!/usr/bin/env python"
    echo "#${version}"
    echo "#Jan Mojzis"
    echo "#Public Domain"
    echo
    cat SOURCES \
    | while read file
    do
      echo "#${file}"
      grep -v '^from' "${file}"
      echo ""
    done 
  ) > acmeshell
  chmod 755 acmeshell
  mv acmeshell "${bin}"
)

