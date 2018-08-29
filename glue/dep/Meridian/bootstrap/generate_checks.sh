#!/bin/bash

create_entry () {
  fileName=$1

  hash=$(cat $fileName | openssl dgst -sha1 | sed 's/^.* //')

  echo '        {'
  echo '                "filename": "'$fileName'",'
  echo '                "hash": "'$hash'"'
  echo '        },'
}

if [ -e checks.json ]; then
  rm checks.json
fi

# Redirect all output into checks.json file 
exec 3>&1 4>&2 >checks.json 2>&1

echo "["

create_entry tar

for fileName in $(ls *.tar); do
  create_entry $fileName
done

echo "]"

