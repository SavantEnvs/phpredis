# LZ4/ZSTD decoders allocate the attacker-declared output size up front

`redis_uncompress()` (library.c) reads the decompressed size from the value's own header and calls
`emalloc(declared + 1)` before decompressing anything. LZ4 frames guard that field with a 1-byte CRC8
that an attacker can compute, so 6 bytes request a ~2 GiB allocation (ZSTD: any frame whose content
size is <= INT_MAX).

Reproducer: `lz4-declared-size-alloc` (mode byte 3 = no serializer + LZ4, then crc8, `0x7fffffff`, 2 bytes).
`fuzz_codec -runs=1 lz4-declared-size-alloc` reports `out-of-memory (malloc(2147483648))`.

Impact: a malicious or compromised Redis server can make a client with `Redis::COMPRESSION_LZ4` /
`COMPRESSION_ZSTD` allocate gigabytes per reply, bounded in a real PHP process only by `memory_limit`
(the harness runs with PHP's allocator disabled so ASan can see heap errors, so no limit applies).

Fix: cap the declared size, or allocate incrementally while decompressing.
