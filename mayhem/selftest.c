/* Known-answer tests for phpredis's reply parsers and value codecs, run inside an embedded PHP with
 * the extension's own sources linked in (built with the project's normal flags, no sanitizers).
 * Prints one PASS/FAIL line per check and a final "SUMMARY: N tests run; F failed". */
#include "harness_common.h"

static int tests, failed;

#define CHECK(name, cond)                                                   \
    do {                                                                    \
        tests++;                                                            \
        if (cond) printf("PASS %s\n", name);                                \
        else { failed++; printf("FAIL %s (line %d)\n", name, __LINE__); }   \
    } while (0)

typedef int (*reply_fn)(INTERNAL_FUNCTION_PARAMETERS, RedisSock *, zval *, void *);

static void call_reply(reply_fn fn, void *ctx, const char *reply, zval *rv) {
    RedisSock *sock = phpredis_sock_from_bytes((const uint8_t *)reply, strlen(reply));
    ZVAL_UNDEF(rv);
    fn(NULL, rv, sock, NULL, ctx);
    phpredis_sock_destroy(sock);
}

static int is_str(zval *z, const char *s) {
    return Z_TYPE_P(z) == IS_STRING && Z_STRLEN_P(z) == strlen(s) && !memcmp(Z_STRVAL_P(z), s, strlen(s));
}

static zval *idx(zval *arr, zend_ulong i) {
    return Z_TYPE_P(arr) == IS_ARRAY ? zend_hash_index_find(Z_ARRVAL_P(arr), i) : NULL;
}

static zval *key(zval *arr, const char *k) {
    return Z_TYPE_P(arr) == IS_ARRAY ? zend_hash_str_find(Z_ARRVAL_P(arr), k, strlen(k)) : NULL;
}

static void test_replies(void) {
    zval rv, *e;

    call_reply(redis_string_response, NULL, "$5\r\nhello\r\n", &rv);
    CHECK("bulk string", is_str(&rv, "hello"));
    zval_ptr_dtor(&rv);

    call_reply(redis_long_response, NULL, ":42\r\n", &rv);
    CHECK("integer reply", Z_TYPE(rv) == IS_LONG && Z_LVAL(rv) == 42);
    zval_ptr_dtor(&rv);

    call_reply(redis_long_response, NULL, ":-7\r\n", &rv);
    CHECK("negative integer reply", Z_TYPE(rv) == IS_LONG && Z_LVAL(rv) == -7);
    zval_ptr_dtor(&rv);

    call_reply(redis_boolean_response, NULL, "+OK\r\n", &rv);
    CHECK("boolean true", Z_TYPE(rv) == IS_TRUE);
    zval_ptr_dtor(&rv);

    call_reply(redis_boolean_response, NULL, ":0\r\n", &rv);
    CHECK("boolean false", Z_TYPE(rv) == IS_FALSE);
    zval_ptr_dtor(&rv);

    call_reply(redis_bulk_double_response, NULL, "$3\r\n1.5\r\n", &rv);
    CHECK("bulk double", Z_TYPE(rv) == IS_DOUBLE && Z_DVAL(rv) == 1.5);
    zval_ptr_dtor(&rv);

    call_reply(redis_sock_read_multibulk_reply, NULL,
               "*3\r\n$1\r\na\r\n$1\r\nb\r\n$-1\r\n", &rv);
    CHECK("multibulk size", Z_TYPE(rv) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL(rv)) == 3);
    CHECK("multibulk first", (e = idx(&rv, 0)) && is_str(e, "a"));
    CHECK("multibulk second", (e = idx(&rv, 1)) && is_str(e, "b"));
    CHECK("multibulk nil", (e = idx(&rv, 2)) && Z_TYPE_P(e) == IS_FALSE);
    zval_ptr_dtor(&rv);

    call_reply(redis_mbulk_reply_zipped_raw, NULL,
               "*4\r\n$1\r\na\r\n$1\r\n1\r\n$1\r\nb\r\n$1\r\n2\r\n", &rv);
    CHECK("zipped size", Z_TYPE(rv) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL(rv)) == 2);
    CHECK("zipped a", (e = key(&rv, "a")) && is_str(e, "1"));
    CHECK("zipped b", (e = key(&rv, "b")) && is_str(e, "2"));
    zval_ptr_dtor(&rv);

    call_reply(redis_info_response, NULL,
               "$56\r\n# Server\r\nredis_version:7.0.0\r\nredis_mode:standalone\r\n\r\n\r\n", &rv);
    CHECK("info redis_version", (e = key(&rv, "redis_version")) && is_str(e, "7.0.0"));
    CHECK("info redis_mode", (e = key(&rv, "redis_mode")) && is_str(e, "standalone"));
    zval_ptr_dtor(&rv);

    call_reply(redis_client_list_reply, NULL,
               "$56\r\nid=3 addr=127.0.0.1:5000 name=foo age=1 db=0 cmd=client\n\r\n", &rv);
    CHECK("client list one client", Z_TYPE(rv) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL(rv)) == 1);
    CHECK("client list id", (e = idx(&rv, 0)) && (e = key(e, "id")) && Z_TYPE_P(e) == IS_LONG && Z_LVAL_P(e) == 3);
    zval_ptr_dtor(&rv);

    call_reply(redis_xrange_reply, NULL,
               "*1\r\n*2\r\n$3\r\n1-0\r\n*2\r\n$1\r\nf\r\n$1\r\nv\r\n", &rv);
    CHECK("xrange entry", (e = key(&rv, "1-0")) && (e = key(e, "f")) && is_str(e, "v"));
    zval_ptr_dtor(&rv);

    {
        uint64_t cursor = 99;
        static const char scan[] = "*2\r\n$2\r\n17\r\n*2\r\n$1\r\nk\r\n$1\r\nl\r\n";
        RedisSock *sock = phpredis_sock_from_bytes((const uint8_t *)scan, sizeof(scan) - 1);
        ZVAL_UNDEF(&rv);
        int ok = redis_sock_read_scan_reply(NULL, &rv, sock, TYPE_SCAN, &cursor);
        CHECK("scan cursor", ok == SUCCESS && cursor == 17);
        CHECK("scan elements", Z_TYPE(rv) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL(rv)) == 2);
        zval_ptr_dtor(&rv);
        phpredis_sock_destroy(sock);
    }
}

static void test_codecs(void) {
    static const char sample[] = "hello world hello world hello world hello world 0123456789";
    static const int comps[] = {REDIS_COMPRESSION_LZF, REDIS_COMPRESSION_ZSTD, REDIS_COMPRESSION_LZ4};
    static const char *names[] = {"lzf", "zstd", "lz4"};
    char label[64];

    for (int i = 0; i < 3; i++) {
        RedisSock *sock = phpredis_sock_from_bytes(NULL, 0);
        sock->compression = comps[i];
        char *packed, *out;
        size_t plen, olen;
        int c = redis_compress(sock, &packed, &plen, (char *)sample, sizeof(sample) - 1);
        snprintf(label, sizeof label, "%s compress", names[i]);
        CHECK(label, c == 1 && plen > 0 && plen < sizeof(sample) - 1);
        int u = redis_uncompress(sock, &out, &olen, packed, plen);
        snprintf(label, sizeof label, "%s roundtrip", names[i]);
        CHECK(label, u == 1 && olen == sizeof(sample) - 1 && !memcmp(out, sample, olen));
        efree(out);
        efree(packed);
        phpredis_sock_destroy(sock);
    }

    {
        RedisSock *sock = phpredis_sock_from_bytes(NULL, 0);
        sock->serializer = REDIS_SERIALIZER_JSON;
        static const char json[] = "{\"a\":1,\"b\":[true,null]}";
        zval zv, *e;
        ZVAL_UNDEF(&zv);
        int ok = redis_unpack(sock, json, sizeof(json) - 1, &zv);
        CHECK("json unpack", ok > 0 && Z_TYPE(zv) == IS_ARRAY);
        CHECK("json key a", (e = key(&zv, "a")) && Z_TYPE_P(e) == IS_LONG && Z_LVAL_P(e) == 1);
        CHECK("json key b", (e = key(&zv, "b")) && Z_TYPE_P(e) == IS_ARRAY &&
                            zend_hash_num_elements(Z_ARRVAL_P(e)) == 2);
        zval_ptr_dtor(&zv);
        phpredis_sock_destroy(sock);
    }

    {
        RedisSock *sock = phpredis_sock_from_bytes(NULL, 0);
        sock->serializer = REDIS_SERIALIZER_PHP;
        zval zv, *e;
        ZVAL_UNDEF(&zv);
        const char ser[] = "a:2:{i:0;s:3:\"foo\";i:1;d:1.5;}";
        int ok = redis_unpack(sock, ser, sizeof(ser) - 1, &zv);
        CHECK("php unpack", ok > 0 && Z_TYPE(zv) == IS_ARRAY);
        CHECK("php element 0", (e = idx(&zv, 0)) && is_str(e, "foo"));
        CHECK("php element 1", (e = idx(&zv, 1)) && Z_TYPE_P(e) == IS_DOUBLE && Z_DVAL_P(e) == 1.5);
        zval_ptr_dtor(&zv);

        zval zs;
        char *packed;
        size_t plen;
        ZVAL_STRING(&zs, "x");
        int freed = redis_pack(sock, &zs, &packed, &plen);
        CHECK("php pack string", plen == 8 && !memcmp(packed, "s:1:\"x\";", 8));
        if (freed) efree(packed);
        zval_ptr_dtor(&zs);
        phpredis_sock_destroy(sock);
    }
}

static void run_all(void *arg) {
    (void)arg;
    test_replies();
    test_codecs();
}

int main(void) {
    phpredis_embed_init();
    phpredis_run(run_all, NULL);
    printf("SUMMARY: %d tests run; %d failed\n", tests, failed);
    fflush(stdout);
    php_embed_shutdown();
    return failed ? 1 : 0;
}
