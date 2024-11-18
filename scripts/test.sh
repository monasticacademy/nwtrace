#!/bin/bash -v

# run each makefile target that has the prefix "test-"
for i in $(grep -o '^test-\S*:' Makefile); do
    echo make ${i%":"}
    make ${i%":"} || exit 1
done
