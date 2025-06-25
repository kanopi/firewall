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

# Using the following mirror to download files.
curl -fsSL -O https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
curl -fsSL -O https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
curl -fsSL -O https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb

exit 0


# Used as a way to download directory from MaxMind site.
CURRENT=$(pwd)

for EDITION in "GeoLite2-City" "GeoLite2-ASN" "GeoLite2-Country"
do
  echo "Downloading ${EDITION}..."
  curl -fsSL -o ${EDITION}.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${LICENSE}&suffix=tar.gz"
  tar -xf ${EDITION}.tar.gz
  mv ${EDITION}_*/${EDITION}.mmdb $CURRENT
  rm -rf ${EDITION}*.tar.gz ${EDITION}_*
done