#!/usr/bin/env bash
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

PHP_CONFIG=php-config8.4
PHP_INC=$($PHP_CONFIG --includes)
EXT_SRCS="redis.c redis_commands.c library.c redis_session.c redis_array.c redis_array_impl.c \
redis_cluster.c redis_cmd.c cluster_library.c redis_sentinel.c sentinel_library.c backoff.c"
LIBS="-lphp8.4 -llzf -llz4 -lzstd -lm"

# config.h for the extension: the same feature set `phpize && ./configure --enable-redis-lzf
# --enable-redis-lz4 --enable-redis-zstd --enable-redis-session --enable-redis-json` would define.
mkdir -p build-fuzz build-test
cat > build-fuzz/config.h <<'CFG'
#define HAVE_REDIS 1
#define PHP_SESSION 1
#define HAVE_REDIS_JSON 1
#define HAVE_REDIS_LZF 1
#define HAVE_REDIS_LZ4 1
#define HAVE_REDIS_ZSTD 1
CFG
cp build-fuzz/config.h build-test/config.h

COMMON_DEFS="-D_GNU_SOURCE -DHAVE_CONFIG_H -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1 -I$SRC -I/usr/include/liblzf"

# 1) the extension itself, sanitized, DWARF 3
for f in $EXT_SRCS; do
    $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $COMMON_DEFS -Ibuild-fuzz $PHP_INC \
        -c "$f" -o "build-fuzz/${f%.c}.o" &
    while [ "$(jobs -r | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
done
wait
$CXX $SANITIZER_FLAGS -c mayhem/lsan_off.cc -o build-fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build-fuzz/standalone_main.o

OBJS=$(for f in $EXT_SRCS; do printf 'build-fuzz/%s.o ' "${f%.c}"; done)

# 2) harnesses: libFuzzer binary + standalone reproducer
for h in fuzz_reply; do
    $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $COMMON_DEFS -Ibuild-fuzz $PHP_INC \
        -c "mayhem/$h.c" -o "build-fuzz/$h.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build-fuzz/$h.o" $OBJS build-fuzz/lsan_off.o \
        $LIBS -o "/mayhem/$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "build-fuzz/$h.o" build-fuzz/standalone_main.o $OBJS build-fuzz/lsan_off.o \
        $LIBS -o "/mayhem/$h-standalone"
done

# 3) the test suite: the same sources with the project's normal flags (no sanitizers), then the
#    known-answer selftest that mayhem/test.sh runs
for f in $EXT_SRCS; do
    $CC -O2 $COVERAGE_FLAGS $COMMON_DEFS -Ibuild-test $PHP_INC \
        -c "$f" -o "build-test/${f%.c}.o" &
    while [ "$(jobs -r | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
done
wait
TOBJS=$(for f in $EXT_SRCS; do printf 'build-test/%s.o ' "${f%.c}"; done)
$CC -O2 $COVERAGE_FLAGS $COMMON_DEFS -Ibuild-test $PHP_INC -c mayhem/selftest.c -o build-test/selftest.o
$CC -O2 $COVERAGE_FLAGS build-test/selftest.o $TOBJS $LIBS -o /mayhem/phpredis_selftest
