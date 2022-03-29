#!/bin/bash

IFS=$'\n'
dirs=$(ls | egrep '^[0-9]{4}-[0-9]{2}-[0-9]{2}.+')
for d in $dirs
do
rm -r "$d"
done
