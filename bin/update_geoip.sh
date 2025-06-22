#!/usr/bin/env bash

set -e

LICENSE=${1}
DIR=${2}

if [[ "${LICENSE}" == "" ]]; then
  echo "License is required in order to update files GeoIP Files"
  exit 1
fi

if [ ! -d $DIR ]; then
  echo "$DIR does not exist"
  exit 1
fi

cd $DIR

CURRENT=$(pwd)

for EDITION in "GeoLite2-City" "GeoLite2-ASN" "GeoLite2-Country"
do
  echo "Downloading ${EDITION}..."
  curl -fsSL -o ${EDITION}.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${LICENSE}&suffix=tar.gz"
  tar -xf ${EDITION}.tar.gz
  mv ${EDITION}_*/${EDITION}.mmdb $CURRENT
  rm -rf ${EDITION}*.tar.gz ${EDITION}_*
done