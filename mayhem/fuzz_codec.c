/* Feeds attacker-controlled bytes to phpredis's value decoders: decompression (LZF/LZ4/ZSTD) and
 * unserialization (PHP/JSON). Input: [mode][value bytes...]. */
#include "harness_common.h"

static const int compressions[] = {REDIS_COMPRESSION_NONE, REDIS_COMPRESSION_LZF,
                                   REDIS_COMPRESSION_ZSTD, REDIS_COMPRESSION_LZ4};
static const redis_serializer serializers[] = {REDIS_SERIALIZER_NONE, REDIS_SERIALIZER_PHP,
                                               REDIS_SERIALIZER_JSON, REDIS_SERIALIZER_NONE};

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    phpredis_embed_init();
    return 0;
}

typedef struct {
    const uint8_t *data;
    size_t size;
} input_t;

static void run(void *arg) {
    const uint8_t *data = ((input_t *)arg)->data;
    const size_t size = ((input_t *)arg)->size;
    const uint8_t mode = data[0];
    const size_t len = size - 1;
    /* The extension hands decoders NUL-terminated buffers (bulk replies are read into len+1 bytes). */
    char *val = emalloc(len + 1);
    memcpy(val, data + 1, len);
    val[len] = 0;

    RedisSock *sock = phpredis_sock_from_bytes(NULL, 0);
    sock->compression = compressions[mode & 3];
    sock->serializer = serializers[(mode >> 2) & 3];
    sock->pack_ignore_numbers = (mode >> 4) & 1;

    zval zv;
    ZVAL_UNDEF(&zv);
    if (redis_unpack(sock, val, (int)len, &zv) > 0)
        zval_ptr_dtor(&zv);

    char *out;
    size_t outlen;
    if (sock->compression != REDIS_COMPRESSION_NONE && len > 0) {
        if (redis_uncompress(sock, &out, &outlen, val, len) > 0)
            efree(out);

        /* compress -> uncompress must give the bytes back */
        char *packed;
        size_t packedlen;
        if (redis_compress(sock, &packed, &packedlen, (char *)val, len) > 0) {
            if (redis_uncompress(sock, &out, &outlen, packed, packedlen) <= 0 ||
                outlen != len || memcmp(out, val, len) != 0)
                abort();
            efree(out);
            efree(packed);
        }
    }

    efree(val);
    phpredis_sock_destroy(sock);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > INT_MAX)
        return -1;
    input_t in = {data, size};
    phpredis_run(run, &in);
    return 0;
}
