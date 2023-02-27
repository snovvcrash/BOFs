#!/usr/bin/env bash

shopt -s extglob

for d in !(template)/; do
	pushd "${d}" > /dev/null
	make
	popd > /dev/null
done
