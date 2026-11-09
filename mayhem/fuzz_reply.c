/* Feeds attacker-controlled bytes to phpredis's reply parsers as if they were a Redis server's
 * answer. Input: [handler][flags][reply bytes...]. */
#include "harness_common.h"

typedef int (*reply_fn)(INTERNAL_FUNCTION_PARAMETERS, RedisSock *, zval *, void *);

typedef struct {
    reply_fn fn;
    void *ctx;
} handler_t;

/* At this commit a reply handler's ctx is NULL or PHPREDIS_CTX_PTR + n, n naming the command's variant. */
#define H(f) {f, NULL}
#define HM(f, n) {f, PHPREDIS_CTX_PTR + (n)}

/* A handler is listed once per ctx value its command can pass it; other values are unreachable by
 * construction in the extension (ZEND_ASSERT), so they are not fed. */
static const handler_t handlers[] = {
    H(redis_1_response), H(redis_long_response), H(redis_boolean_response),
    H(redis_bulk_double_response), H(redis_string_response), H(redis_bulk_withmeta_response),
    H(redis_ping_response), H(redis_info_response),
    H(redis_zrange_response), HM(redis_zrange_response, 0),
    H(redis_type_response), H(redis_sock_read_multibulk_reply), H(redis_mbulk_reply_raw),
    H(redis_mbulk_reply_zipped_raw), H(redis_mbulk_reply_zipped_vals),
    H(redis_mbulk_reply_zipped_keys_int), H(redis_mbulk_reply_zipped_keys_dbl),
    H(redis_mbulk_reply_assoc), H(redis_mbulk_reply_double), H(redis_xrange_reply),
    H(redis_xread_reply), H(redis_xclaim_reply), HM(redis_xclaim_reply, 0),
    H(redis_xinfo_reply), H(redis_vinfo_reply), H(redis_vemb_reply),
    H(redis_vlinks_reply), HM(redis_vlinks_reply, 0),
    H(redis_vgetattr_reply), HM(redis_vgetattr_reply, 0),
    H(redis_acl_response), HM(redis_acl_response, 0), HM(redis_acl_response, 1),
    HM(redis_acl_response, 2), HM(redis_acl_response, 3), HM(redis_acl_response, 4),
    H(redis_acl_getuser_reply), H(redis_acl_log_reply),
    H(redis_read_variant_reply), H(redis_read_raw_variant_reply),
    H(redis_read_variant_reply_strings), H(redis_client_list_reply),
    H(redis_client_response), HM(redis_client_response, 0), HM(redis_client_response, 1),
    HM(redis_client_response, 2), HM(redis_client_response, 3), HM(redis_client_response, 4),
    H(redis_zadd_response), HM(redis_zadd_response, 0),
    H(redis_zrandmember_response), HM(redis_zrandmember_response, 0),
    HM(redis_zrandmember_response, 1),
    H(redis_zdiff_response), HM(redis_zdiff_response, 0),
    H(redis_set_response), HM(redis_set_response, 0),
    H(redis_geosearch_response), HM(redis_geosearch_response, 0),
    H(redis_hrandfield_response), HM(redis_hrandfield_response, 0),
    HM(redis_hrandfield_response, 1),
    H(redis_pop_response), HM(redis_pop_response, 0),
    H(redis_randmember_response), HM(redis_randmember_response, 0),
    H(redis_lpos_response), HM(redis_lpos_response, 0),
    HM(redis_object_response, 0), HM(redis_object_response, 1),
    H(redis_function_response), HM(redis_function_response, 0), HM(redis_function_response, 1),
    H(redis_command_response), HM(redis_command_response, 0), HM(redis_command_response, 1),
    H(redis_select_response), H(redis_hello_server_response), H(redis_hello_version_response),
    H(redis_mpop_response), HM(redis_mpop_response, 0),
};
#define NHANDLERS (sizeof(handlers) / sizeof(handlers[0]))
#define NSCAN 4

static const int compressions[] = {REDIS_COMPRESSION_NONE, REDIS_COMPRESSION_LZF,
                                   REDIS_COMPRESSION_ZSTD, REDIS_COMPRESSION_LZ4};

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
    const unsigned sel = data[0] % (NHANDLERS + NSCAN);
    const uint8_t flags = data[1];

    RedisSock *sock = phpredis_sock_from_bytes(data + 2, size - 2);
    sock->reply_literal = flags & 1;
    sock->null_mbulk_as_null = (flags >> 1) & 1;
    sock->compression = compressions[(flags >> 2) & 3];
    sock->pack_ignore_numbers = (flags >> 4) & 1;

    zval rv;
    ZVAL_UNDEF(&rv);
    if (sel < NHANDLERS) {
        void *ctx = handlers[sel].ctx;
        /* HMGET pairs the reply with the requested keys, passed as a HashTable in the ctx; the
         * handler takes ownership of it. */
        if (handlers[sel].fn == redis_mbulk_reply_assoc) {
            HashTable *keys = zend_new_array(0);
            for (unsigned i = 0; i < (flags >> 5); i++)
                { zval zk; ZVAL_STRING(&zk, "k"); zend_hash_next_index_insert(keys, &zk); };
            ctx = keys;
        }
        handlers[sel].fn(NULL, &rv, sock, NULL, ctx);
    } else {
        uint64_t cursor = 0;
        redis_sock_read_scan_reply(NULL, &rv, sock, (REDIS_SCAN_TYPE)(sel - NHANDLERS), &cursor);
    }
    zval_ptr_dtor(&rv);
    phpredis_sock_destroy(sock);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return -1;
    input_t in = {data, size};
    phpredis_run(run, &in);
    return 0;
}
