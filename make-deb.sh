#!/usr/bin/env bash

set -x
set -e

base="$(realpath -e "$(dirname "$0")")"
deb_dir="${1:-$(realpath "${base}/../deb")}"

rm -rf "${deb_dir}"
mkdir "${deb_dir}"

version="1"
target="address-monitor-${version}"
otarget="$(echo "${target}" | tr '-' '_')"
build_dir="${deb_dir}/${target}"

cp -arf "${base}" "${build_dir}"
cd "${build_dir}"
git clean -dxf

cd ..
tar cvzf "${otarget}.orig.tar.gz" "${target}"

cd -
debuild -us -uc

exit 0
