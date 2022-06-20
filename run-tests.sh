#!/bin/sh --
set -euf
coverage= IFS=' '
if [ "${1-}" = '--coverage' ]; then coverage='-m coverage run'; shift; fi
s=$(dirname -- "$0") && cd -- "$s" &&
exec python3 $coverage -m unittest discover -p test_\*.py -v -s splitgpg2 -t . "$@"
