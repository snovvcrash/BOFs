#!/usr/bin/env bash

for d in */; do
	if [ "${d}" != "template/" ]; then
		pushd "${d}" > /dev/null
		make
		popd > /dev/null
	fi
done
