#!/bin/sh
set -eu

output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    http://*|https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
[ -n "$output" ] && [ -n "$url" ]
name=${url##*/}
case "$name" in
  *.gz) exit 22 ;;
esac
cp "@FIXTURE@/$name" "$output"
