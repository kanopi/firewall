#!/bin/sh
# Container entrypoint for the php-fpm service.
#
# php-fpm's own config-file variable interpolation differs across versions,
# so the worker count is substituted here with sed instead. One less thing
# that can silently start the wrong pool size and quietly invalidate a
# whole benchmark run.
set -eu

WORKERS="${PERF_FPM_WORKERS:-64}"

case "$WORKERS" in
    ''|*[!0-9]*)
        echo "entrypoint: PERF_FPM_WORKERS must be an integer, got '$WORKERS'" >&2
        exit 1
        ;;
esac

sed "s/__PERF_FPM_WORKERS__/${WORKERS}/" \
    /app/tests/Performance/conf/www.conf \
    > /usr/local/etc/php-fpm.d/zz-perf.conf

# The base image ships a www pool that would collide with ours.
rm -f /usr/local/etc/php-fpm.d/www.conf /usr/local/etc/php-fpm.d/www.conf.default

echo "entrypoint: php-fpm starting with ${WORKERS} static workers, scenario '${FIREWALL_PERF_SCENARIO:-unset}'"

exec php-fpm --nodaemonize
