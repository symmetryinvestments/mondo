// This file was auto-generated. Don't change it.
// mongo-c-driver version: 1.3.4
// libbson version: 1.3.4
extern (C): 

// libbson stuffs --->

void bson_context_destroy (bson_context_t* context);
bson_context_t* bson_context_get_default ();
bool bson_init_static (bson_t* b, const(ubyte)* data, size_t length);
bson_t* bson_new_from_data (const(ubyte)* data, size_t length);
void bson_destroy (bson_t* bson);
const(ubyte)* bson_get_data (const(bson_t)* bson);
char* bson_as_json (const(bson_t)* bson, size_t* length);
void bson_oid_init (bson_oid_t* oid, bson_context_t* context);
void bson_strfreev (char** strv);
// libbson data struct --->
extern (C):

alias uint bson_unichar_t;
// found alias: _Anonymous_0 => bson_context_flags_t
alias _bson_context_t bson_context_t;
alias _bson_t bson_t;
alias char[1] static_assert_test_145;
// found alias: _Anonymous_1 => bson_oid_t
alias char[1] static_assert_test_161;
// found alias: _Anonymous_2 => bson_validate_flags_t
// found alias: _Anonymous_3 => bson_type_t
// found alias: _Anonymous_4 => bson_subtype_t
alias _bson_value_t bson_value_t;
// found alias: _Anonymous_5 => bson_iter_t
// found alias: _Anonymous_6 => bson_reader_t
// found alias: _Anonymous_7 => bson_visitor_t
alias _bson_error_t bson_error_t;
alias char[1] static_assert_test_485;

enum bson_context_flags_t
{
    BSON_CONTEXT_NONE = 0,
    BSON_CONTEXT_THREAD_SAFE = 1,
    BSON_CONTEXT_DISABLE_HOST_CACHE = 2,
    BSON_CONTEXT_DISABLE_PID_CACHE = 4,
    BSON_CONTEXT_USE_TASK_ID = 8
}

enum bson_validate_flags_t
{
    BSON_VALIDATE_NONE = 0,
    BSON_VALIDATE_UTF8 = 1,
    BSON_VALIDATE_DOLLAR_KEYS = 2,
    BSON_VALIDATE_DOT_KEYS = 4,
    BSON_VALIDATE_UTF8_ALLOW_NULL = 8
}

enum bson_type_t
{
    BSON_TYPE_EOD = 0,
    BSON_TYPE_DOUBLE = 1,
    BSON_TYPE_UTF8 = 2,
    BSON_TYPE_DOCUMENT = 3,
    BSON_TYPE_ARRAY = 4,
    BSON_TYPE_BINARY = 5,
    BSON_TYPE_UNDEFINED = 6,
    BSON_TYPE_OID = 7,
    BSON_TYPE_BOOL = 8,
    BSON_TYPE_DATE_TIME = 9,
    BSON_TYPE_NULL = 10,
    BSON_TYPE_REGEX = 11,
    BSON_TYPE_DBPOINTER = 12,
    BSON_TYPE_CODE = 13,
    BSON_TYPE_SYMBOL = 14,
    BSON_TYPE_CODEWSCOPE = 15,
    BSON_TYPE_INT32 = 16,
    BSON_TYPE_TIMESTAMP = 17,
    BSON_TYPE_INT64 = 18,
    BSON_TYPE_MAXKEY = 127,
    BSON_TYPE_MINKEY = 255
}

enum bson_subtype_t
{
    BSON_SUBTYPE_BINARY = 0,
    BSON_SUBTYPE_FUNCTION = 1,
    BSON_SUBTYPE_BINARY_DEPRECATED = 2,
    BSON_SUBTYPE_UUID_DEPRECATED = 3,
    BSON_SUBTYPE_UUID = 4,
    BSON_SUBTYPE_MD5 = 5,
    BSON_SUBTYPE_USER = 128
}

struct _bson_t
{
    uint flags;
    uint len;
    ubyte[120] padding;
}

struct bson_oid_t
{
    ubyte[12] bytes;
}

struct _bson_value_t;
// IGN struct _bson_value_t
// IGN {
// IGN     bson_type_t value_type;
// IGN     int padding;
// IGN     union
// IGN     {
// IGN         bson_oid_t v_oid;
// IGN         long v_int64;
// IGN         int v_int32;
// IGN         byte v_int8;
// IGN         double v_double;
// IGN         bool v_bool;
// IGN         long v_datetime;
// IGN         struct
// IGN         {
// IGN             uint timestamp;
// IGN             uint increment;
// IGN         }
// IGN         struct
// IGN         {
// IGN             char* str;
// IGN             uint len;
// IGN         }
// IGN         struct
// IGN         {
// IGN             ubyte* data;
// IGN             uint data_len;
// IGN         }
// IGN         struct
// IGN         {
// IGN             ubyte* data;
// IGN             uint data_len;
// IGN             bson_subtype_t subtype;
// IGN         }
// IGN         struct
// IGN         {
// IGN             char* regex;
// IGN             char* options;
// IGN         }
// IGN         struct
// IGN         {
// IGN             char* collection;
// IGN             uint collection_len;
// IGN             bson_oid_t oid;
// IGN         }
// IGN         struct
// IGN         {
// IGN             char* code;
// IGN             uint code_len;
// IGN         }
// IGN         struct
// IGN         {
// IGN             char* code;
// IGN             ubyte* scope_data;
// IGN             uint code_len;
// IGN             uint scope_len;
// IGN         }
// IGN         struct
// IGN         {
// IGN             char* symbol;
// IGN             uint len;
// IGN         }
// IGN     }
// IGN }

struct bson_iter_t;
// IGN struct bson_iter_t
// IGN {
// IGN     const(ubyte)* raw;
// IGN     uint len;
// IGN     uint off;
// IGN     uint type;
// IGN     uint key;
// IGN     uint d1;
// IGN     uint d2;
// IGN     uint d3;
// IGN     uint d4;
// IGN     uint next_off;
// IGN     uint err_off;
// IGN     bson_value_t value;
// IGN }

struct bson_reader_t
{
    uint type;
}

struct bson_visitor_t
{
    bool function (const(bson_iter_t)*, const(char)*, void*) visit_before;
    bool function (const(bson_iter_t)*, const(char)*, void*) visit_after;
    void function (const(bson_iter_t)*, void*) visit_corrupt;
    bool function (const(bson_iter_t)*, const(char)*, double, void*) visit_double;
    bool function (const(bson_iter_t)*, const(char)*, size_t, const(char)*, void*) visit_utf8;
    bool function (const(bson_iter_t)*, const(char)*, const(bson_t)*, void*) visit_document;
    bool function (const(bson_iter_t)*, const(char)*, const(bson_t)*, void*) visit_array;
    bool function (const(bson_iter_t)*, const(char)*, bson_subtype_t, size_t, const(ubyte)*, void*) visit_binary;
    bool function (const(bson_iter_t)*, const(char)*, void*) visit_undefined;
    bool function (const(bson_iter_t)*, const(char)*, const(bson_oid_t)*, void*) visit_oid;
    bool function (const(bson_iter_t)*, const(char)*, bool, void*) visit_bool;
    bool function (const(bson_iter_t)*, const(char)*, long, void*) visit_date_time;
    bool function (const(bson_iter_t)*, const(char)*, void*) visit_null;
    bool function (const(bson_iter_t)*, const(char)*, const(char)*, const(char)*, void*) visit_regex;
    bool function (const(bson_iter_t)*, const(char)*, size_t, const(char)*, const(bson_oid_t)*, void*) visit_dbpointer;
    bool function (const(bson_iter_t)*, const(char)*, size_t, const(char)*, void*) visit_code;
    bool function (const(bson_iter_t)*, const(char)*, size_t, const(char)*, void*) visit_symbol;
    bool function (const(bson_iter_t)*, const(char)*, size_t, const(char)*, const(bson_t)*, void*) visit_codewscope;
    bool function (const(bson_iter_t)*, const(char)*, int, void*) visit_int32;
    bool function (const(bson_iter_t)*, const(char)*, uint, uint, void*) visit_timestamp;
    bool function (const(bson_iter_t)*, const(char)*, long, void*) visit_int64;
    bool function (const(bson_iter_t)*, const(char)*, void*) visit_maxkey;
    bool function (const(bson_iter_t)*, const(char)*, void*) visit_minkey;
    void*[9] padding;
}

struct _bson_error_t
{
    uint domain;
    uint code;
    char[504] message;
}

struct _bson_context_t;


size_t bson_next_power_of_two (size_t v);
bool bson_is_power_of_two (uint v);

// mongo-c-clients stuffs --->

// from file mongoc-stream-tls.h:

bool mongoc_stream_tls_do_handshake (mongoc_stream_t* stream, int timeout_msec);
bool mongoc_stream_tls_should_retry (mongoc_stream_t* stream);
bool mongoc_stream_tls_should_read (mongoc_stream_t* stream);
bool mongoc_stream_tls_should_write (mongoc_stream_t* stream);
bool mongoc_stream_tls_check_cert (mongoc_stream_t* stream, const(char)* host);
mongoc_stream_t* mongoc_stream_tls_new (mongoc_stream_t* base_stream, mongoc_ssl_opt_t* opt, int client);

// from file mongoc-read-prefs.h:

alias _mongoc_read_prefs_t mongoc_read_prefs_t;
// found alias: _Anonymous_0 => mongoc_read_mode_t

enum mongoc_read_mode_t
{
    PRIMARY = 1,
    SECONDARY = 2,
    PRIMARY_PREFERRED = 5,
    SECONDARY_PREFERRED = 6,
    NEAREST = 10
}

struct _mongoc_read_prefs_t;


mongoc_read_prefs_t* mongoc_read_prefs_new (mongoc_read_mode_t read_mode);
mongoc_read_prefs_t* mongoc_read_prefs_copy (const(mongoc_read_prefs_t)* read_prefs);
void mongoc_read_prefs_destroy (mongoc_read_prefs_t* read_prefs);
mongoc_read_mode_t mongoc_read_prefs_get_mode (const(mongoc_read_prefs_t)* read_prefs);
void mongoc_read_prefs_set_mode (mongoc_read_prefs_t* read_prefs, mongoc_read_mode_t mode);
const(bson_t)* mongoc_read_prefs_get_tags (const(mongoc_read_prefs_t)* read_prefs);
void mongoc_read_prefs_set_tags (mongoc_read_prefs_t* read_prefs, const(bson_t)* tags);
void mongoc_read_prefs_add_tag (mongoc_read_prefs_t* read_prefs, const(bson_t)* tag);
bool mongoc_read_prefs_is_valid (const(mongoc_read_prefs_t)* read_prefs);

// from file mongoc-matcher.h:

alias _mongoc_matcher_t mongoc_matcher_t;

struct _mongoc_matcher_t;


mongoc_matcher_t* mongoc_matcher_new (const(bson_t)* query, bson_error_t* error);
bool mongoc_matcher_match (const(mongoc_matcher_t)* matcher, const(bson_t)* document);
void mongoc_matcher_destroy (mongoc_matcher_t* matcher);

// from file mongoc-gridfs-file.h:
import core.stdc.stdio;


alias _mongoc_gridfs_file_t mongoc_gridfs_file_t;
alias _mongoc_gridfs_file_opt_t mongoc_gridfs_file_opt_t;

struct _mongoc_gridfs_file_opt_t
{
    const(char)* md5;
    const(char)* filename;
    const(char)* content_type;
    const(bson_t)* aliases;
    const(bson_t)* metadata;
    uint chunk_size;
}

struct _mongoc_gridfs_file_t;


const(char)* mongoc_gridfs_file_get_md5 (mongoc_gridfs_file_t* file);
void mongoc_gridfs_file_set_md5 (mongoc_gridfs_file_t* file, const(char)* str);
const(char)* mongoc_gridfs_file_get_filename (mongoc_gridfs_file_t* file);
void mongoc_gridfs_file_set_filename (mongoc_gridfs_file_t* file, const(char)* str);
const(char)* mongoc_gridfs_file_get_content_type (mongoc_gridfs_file_t* file);
void mongoc_gridfs_file_set_content_type (mongoc_gridfs_file_t* file, const(char)* str);
const(bson_t)* mongoc_gridfs_file_get_aliases (mongoc_gridfs_file_t* file);
void mongoc_gridfs_file_set_aliases (mongoc_gridfs_file_t* file, const(bson_t)* bson);
const(bson_t)* mongoc_gridfs_file_get_metadata (mongoc_gridfs_file_t* file);
void mongoc_gridfs_file_set_metadata (mongoc_gridfs_file_t* file, const(bson_t)* bson);
const(bson_value_t)* mongoc_gridfs_file_get_id (mongoc_gridfs_file_t* file);
long mongoc_gridfs_file_get_length (mongoc_gridfs_file_t* file);
int mongoc_gridfs_file_get_chunk_size (mongoc_gridfs_file_t* file);
long mongoc_gridfs_file_get_upload_date (mongoc_gridfs_file_t* file);
ssize_t mongoc_gridfs_file_writev (mongoc_gridfs_file_t* file, mongoc_iovec_t* iov, size_t iovcnt, uint timeout_msec);
ssize_t mongoc_gridfs_file_readv (mongoc_gridfs_file_t* file, mongoc_iovec_t* iov, size_t iovcnt, size_t min_bytes, uint timeout_msec);
int mongoc_gridfs_file_seek (mongoc_gridfs_file_t* file, long delta, int whence);
ulong mongoc_gridfs_file_tell (mongoc_gridfs_file_t* file);
bool mongoc_gridfs_file_save (mongoc_gridfs_file_t* file);
void mongoc_gridfs_file_destroy (mongoc_gridfs_file_t* file);
bool mongoc_gridfs_file_error (mongoc_gridfs_file_t* file, bson_error_t* error);
bool mongoc_gridfs_file_remove (mongoc_gridfs_file_t* file, bson_error_t* error);

// from file mongoc-bulk-operation.h:

alias _mongoc_bulk_operation_t mongoc_bulk_operation_t;
alias _mongoc_bulk_write_flags_t mongoc_bulk_write_flags_t;

struct _mongoc_bulk_write_flags_t;


struct _mongoc_bulk_operation_t;


void mongoc_bulk_operation_destroy (mongoc_bulk_operation_t* bulk);
uint mongoc_bulk_operation_execute (mongoc_bulk_operation_t* bulk, bson_t* reply, bson_error_t* error);
void mongoc_bulk_operation_delete (mongoc_bulk_operation_t* bulk, const(bson_t)* selector);
void mongoc_bulk_operation_delete_one (mongoc_bulk_operation_t* bulk, const(bson_t)* selector);
void mongoc_bulk_operation_insert (mongoc_bulk_operation_t* bulk, const(bson_t)* document);
void mongoc_bulk_operation_remove (mongoc_bulk_operation_t* bulk, const(bson_t)* selector);
void mongoc_bulk_operation_remove_one (mongoc_bulk_operation_t* bulk, const(bson_t)* selector);
void mongoc_bulk_operation_replace_one (mongoc_bulk_operation_t* bulk, const(bson_t)* selector, const(bson_t)* document, bool upsert);
void mongoc_bulk_operation_update (mongoc_bulk_operation_t* bulk, const(bson_t)* selector, const(bson_t)* document, bool upsert);
void mongoc_bulk_operation_update_one (mongoc_bulk_operation_t* bulk, const(bson_t)* selector, const(bson_t)* document, bool upsert);
void mongoc_bulk_operation_set_bypass_document_validation (mongoc_bulk_operation_t* bulk, bool bypass);
mongoc_bulk_operation_t* mongoc_bulk_operation_new (bool ordered);
void mongoc_bulk_operation_set_write_concern (mongoc_bulk_operation_t* bulk, const(mongoc_write_concern_t)* write_concern);
void mongoc_bulk_operation_set_database (mongoc_bulk_operation_t* bulk, const(char)* database);
void mongoc_bulk_operation_set_collection (mongoc_bulk_operation_t* bulk, const(char)* collection);
void mongoc_bulk_operation_set_client (mongoc_bulk_operation_t* bulk, void* client);
void mongoc_bulk_operation_set_hint (mongoc_bulk_operation_t* bulk, uint hint);
const(mongoc_write_concern_t)* mongoc_bulk_operation_get_write_concern (const(mongoc_bulk_operation_t)* bulk);

// from file mongoc-read-concern.h:

alias _mongoc_read_concern_t mongoc_read_concern_t;

struct _mongoc_read_concern_t;


mongoc_read_concern_t* mongoc_read_concern_new ();
mongoc_read_concern_t* mongoc_read_concern_copy (const(mongoc_read_concern_t)* read_concern);
void mongoc_read_concern_destroy (mongoc_read_concern_t* read_concern);
const(char)* mongoc_read_concern_get_level (const(mongoc_read_concern_t)* read_concern);
bool mongoc_read_concern_set_level (mongoc_read_concern_t* read_concern, const(char)* level);

// from file mongoc-client-pool.h:

alias _mongoc_client_pool_t mongoc_client_pool_t;

struct _mongoc_client_pool_t;


mongoc_client_pool_t* mongoc_client_pool_new (const(mongoc_uri_t)* uri);
void mongoc_client_pool_destroy (mongoc_client_pool_t* pool);
mongoc_client_t* mongoc_client_pool_pop (mongoc_client_pool_t* pool);
void mongoc_client_pool_push (mongoc_client_pool_t* pool, mongoc_client_t* client);
mongoc_client_t* mongoc_client_pool_try_pop (mongoc_client_pool_t* pool);
void mongoc_client_pool_max_size (mongoc_client_pool_t* pool, uint max_pool_size);
void mongoc_client_pool_min_size (mongoc_client_pool_t* pool, uint min_pool_size);
void mongoc_client_pool_set_ssl_opts (mongoc_client_pool_t* pool, const(mongoc_ssl_opt_t)* opts);

// from file mongoc-host-list.h:

alias _mongoc_host_list_t mongoc_host_list_t;

struct _mongoc_host_list_t
{
    mongoc_host_list_t* next;
    char[65] host;
    char[71] host_and_port;
    ushort port;
    int family;
    void*[4] padding;
}

// from file mongoc-server-description.h:

alias _mongoc_server_description_t mongoc_server_description_t;

struct _mongoc_server_description_t;


void mongoc_server_description_destroy (mongoc_server_description_t* description);
mongoc_server_description_t* mongoc_server_description_new_copy (const(mongoc_server_description_t)* description);
uint mongoc_server_description_id (mongoc_server_description_t* description);
mongoc_host_list_t* mongoc_server_description_host (mongoc_server_description_t* description);

// from file mongoc-gridfs.h:

alias _mongoc_gridfs_t mongoc_gridfs_t;

struct _mongoc_gridfs_t;


mongoc_gridfs_file_t* mongoc_gridfs_create_file_from_stream (mongoc_gridfs_t* gridfs, mongoc_stream_t* stream, mongoc_gridfs_file_opt_t* opt);
mongoc_gridfs_file_t* mongoc_gridfs_create_file (mongoc_gridfs_t* gridfs, mongoc_gridfs_file_opt_t* opt);
mongoc_gridfs_file_list_t* mongoc_gridfs_find (mongoc_gridfs_t* gridfs, const(bson_t)* query);
mongoc_gridfs_file_t* mongoc_gridfs_find_one (mongoc_gridfs_t* gridfs, const(bson_t)* query, bson_error_t* error);
mongoc_gridfs_file_t* mongoc_gridfs_find_one_by_filename (mongoc_gridfs_t* gridfs, const(char)* filename, bson_error_t* error);
bool mongoc_gridfs_drop (mongoc_gridfs_t* gridfs, bson_error_t* error);
void mongoc_gridfs_destroy (mongoc_gridfs_t* gridfs);
mongoc_collection_t* mongoc_gridfs_get_files (mongoc_gridfs_t* gridfs);
mongoc_collection_t* mongoc_gridfs_get_chunks (mongoc_gridfs_t* gridfs);
bool mongoc_gridfs_remove_by_filename (mongoc_gridfs_t* gridfs, const(char)* filename, bson_error_t* error);

// from file mongoc-write-concern.h:

alias _mongoc_write_concern_t mongoc_write_concern_t;

struct _mongoc_write_concern_t;


mongoc_write_concern_t* mongoc_write_concern_new ();
mongoc_write_concern_t* mongoc_write_concern_copy (const(mongoc_write_concern_t)* write_concern);
void mongoc_write_concern_destroy (mongoc_write_concern_t* write_concern);
bool mongoc_write_concern_get_fsync (const(mongoc_write_concern_t)* write_concern);
void mongoc_write_concern_set_fsync (mongoc_write_concern_t* write_concern, bool fsync_);
bool mongoc_write_concern_get_journal (const(mongoc_write_concern_t)* write_concern);
void mongoc_write_concern_set_journal (mongoc_write_concern_t* write_concern, bool journal);
int mongoc_write_concern_get_w (const(mongoc_write_concern_t)* write_concern);
void mongoc_write_concern_set_w (mongoc_write_concern_t* write_concern, int w);
const(char)* mongoc_write_concern_get_wtag (const(mongoc_write_concern_t)* write_concern);
void mongoc_write_concern_set_wtag (mongoc_write_concern_t* write_concern, const(char)* tag);
int mongoc_write_concern_get_wtimeout (const(mongoc_write_concern_t)* write_concern);
void mongoc_write_concern_set_wtimeout (mongoc_write_concern_t* write_concern, int wtimeout_msec);
bool mongoc_write_concern_get_wmajority (const(mongoc_write_concern_t)* write_concern);
void mongoc_write_concern_set_wmajority (mongoc_write_concern_t* write_concern, int wtimeout_msec);

// from file mongoc-opcode.h:

// found alias: _Anonymous_0 => mongoc_opcode_t

enum mongoc_opcode_t
{
    REPLY = 1,
    MSG = 1000,
    UPDATE = 2001,
    INSERT = 2002,
    QUERY = 2004,
    GET_MORE = 2005,
    DELETE = 2006,
    KILL_CURSORS = 2007
}

// from file mongoc.h:

// from file mongoc-stream-file.h:

alias _mongoc_stream_file_t mongoc_stream_file_t;

struct _mongoc_stream_file_t;


mongoc_stream_t* mongoc_stream_file_new (int fd);
mongoc_stream_t* mongoc_stream_file_new_for_path (const(char)* path, int flags, int mode);
int mongoc_stream_file_get_fd (mongoc_stream_file_t* stream);

// from file mongoc-version.h:

// from file mongoc-cursor.h:

alias _mongoc_cursor_t mongoc_cursor_t;

struct _mongoc_cursor_t;


mongoc_cursor_t* mongoc_cursor_clone (const(mongoc_cursor_t)* cursor);
void mongoc_cursor_destroy (mongoc_cursor_t* cursor);
bool mongoc_cursor_more (mongoc_cursor_t* cursor);
bool mongoc_cursor_next (mongoc_cursor_t* cursor, const(bson_t*)* bson);
bool mongoc_cursor_error (mongoc_cursor_t* cursor, bson_error_t* error);
void mongoc_cursor_get_host (mongoc_cursor_t* cursor, mongoc_host_list_t* host);
bool mongoc_cursor_is_alive (const(mongoc_cursor_t)* cursor);
const(bson_t)* mongoc_cursor_current (const(mongoc_cursor_t)* cursor);
void mongoc_cursor_set_batch_size (mongoc_cursor_t* cursor, uint batch_size);
uint mongoc_cursor_get_batch_size (const(mongoc_cursor_t)* cursor);
uint mongoc_cursor_get_hint (const(mongoc_cursor_t)* cursor);
long mongoc_cursor_get_id (const(mongoc_cursor_t)* cursor);
void mongoc_cursor_set_max_await_time_ms (mongoc_cursor_t* cursor, uint max_await_time_ms);
uint mongoc_cursor_get_max_await_time_ms (const(mongoc_cursor_t)* cursor);

// from file mongoc-config.h:

// from file mongoc-version-functions.h:

int mongoc_get_major_version ();
int mongoc_get_minor_version ();
int mongoc_get_micro_version ();
const(char)* mongoc_get_version ();
bool mongoc_check_version (int required_major, int required_minor, int required_micro);

// from file mongoc-gridfs-file-page.h:

alias _mongoc_gridfs_file_page_t mongoc_gridfs_file_page_t;

struct _mongoc_gridfs_file_page_t;

// from file mongoc-log.h:

// found alias: _Anonymous_0 => mongoc_log_level_t
alias void function (mongoc_log_level_t, const(char)*, const(char)*, void*) mongoc_log_func_t;

enum mongoc_log_level_t
{
    LEVEL_ERROR = 0,
    LEVEL_CRITICAL = 1,
    LEVEL_WARNING = 2,
    LEVEL_MESSAGE = 3,
    LEVEL_INFO = 4,
    LEVEL_DEBUG = 5,
    LEVEL_TRACE = 6
}

void mongoc_log_set_handler (mongoc_log_func_t log_func, void* user_data);
void mongoc_log (mongoc_log_level_t log_level, const(char)* log_domain, const(char)* format, ...);
void mongoc_log_default_handler (mongoc_log_level_t log_level, const(char)* log_domain, const(char)* message, void* user_data);
const(char)* mongoc_log_level_str (mongoc_log_level_t log_level);

// from file mongoc-stream-gridfs.h:

mongoc_stream_t* mongoc_stream_gridfs_new (mongoc_gridfs_file_t* file);

// from file mongoc-iovec.h:

alias iovec mongoc_iovec_t;

// from file mongoc-ssl.h:

alias _mongoc_ssl_opt_t mongoc_ssl_opt_t;

struct _mongoc_ssl_opt_t
{
    const(char)* pem_file;
    const(char)* pem_pwd;
    const(char)* ca_file;
    const(char)* ca_dir;
    const(char)* crl_file;
    bool weak_cert_validation;
    void*[8] padding;
}

const(mongoc_ssl_opt_t)* mongoc_ssl_opt_get_default ();

// from file mongoc-gridfs-file-list.h:

alias _mongoc_gridfs_file_list_t mongoc_gridfs_file_list_t;

struct _mongoc_gridfs_file_list_t;


mongoc_gridfs_file_t* mongoc_gridfs_file_list_next (mongoc_gridfs_file_list_t* list);
void mongoc_gridfs_file_list_destroy (mongoc_gridfs_file_list_t* list);
bool mongoc_gridfs_file_list_error (mongoc_gridfs_file_list_t* list, bson_error_t* error);

// from file mongoc-flags.h:

// found alias: _Anonymous_0 => mongoc_delete_flags_t
// found alias: _Anonymous_1 => mongoc_remove_flags_t
// found alias: _Anonymous_2 => mongoc_insert_flags_t
// found alias: _Anonymous_3 => mongoc_query_flags_t
// found alias: _Anonymous_4 => mongoc_reply_flags_t
// found alias: _Anonymous_5 => mongoc_update_flags_t

enum mongoc_delete_flags_t
{
    NONE = 0,
    SINGLE_REMOVE = 1
}

enum mongoc_remove_flags_t
{
    NONE = 0,
    SINGLE_REMOVE = 1
}

enum mongoc_insert_flags_t
{
    NONE = 0,
    CONTINUE_ON_ERROR = 1
}

enum mongoc_query_flags_t
{
    NONE = 0,
    TAILABLE_CURSOR = 2,
    SLAVE_OK = 4,
    OPLOG_REPLAY = 8,
    NO_CURSOR_TIMEOUT = 16,
    AWAIT_DATA = 32,
    EXHAUST = 64,
    PARTIAL = 128
}

enum mongoc_reply_flags_t
{
    NONE = 0,
    CURSOR_NOT_FOUND = 1,
    QUERY_FAILURE = 2,
    SHARD_CONFIG_STALE = 4,
    AWAIT_CAPABLE = 8
}

enum mongoc_update_flags_t
{
    NONE = 0,
    UPSERT = 1,
    MULTI_UPDATE = 2
}

// from file mongoc-trace.h:

// from file mongoc-rand.h:

void mongoc_rand_seed (const(void)* buf, int num);
void mongoc_rand_add (const(void)* buf, int num, double entropy);
int mongoc_rand_status ();

// from file mongoc-uri.h:

alias _mongoc_uri_t mongoc_uri_t;

struct _mongoc_uri_t;


mongoc_uri_t* mongoc_uri_copy (const(mongoc_uri_t)* uri);
void mongoc_uri_destroy (mongoc_uri_t* uri);
mongoc_uri_t* mongoc_uri_new (const(char)* uri_string);
mongoc_uri_t* mongoc_uri_new_for_host_port (const(char)* hostname, ushort port);
const(mongoc_host_list_t)* mongoc_uri_get_hosts (const(mongoc_uri_t)* uri);
const(char)* mongoc_uri_get_database (const(mongoc_uri_t)* uri);
const(bson_t)* mongoc_uri_get_options (const(mongoc_uri_t)* uri);
const(char)* mongoc_uri_get_password (const(mongoc_uri_t)* uri);
const(bson_t)* mongoc_uri_get_read_prefs (const(mongoc_uri_t)* uri);
const(char)* mongoc_uri_get_replica_set (const(mongoc_uri_t)* uri);
const(char)* mongoc_uri_get_string (const(mongoc_uri_t)* uri);
const(char)* mongoc_uri_get_username (const(mongoc_uri_t)* uri);
const(bson_t)* mongoc_uri_get_credentials (const(mongoc_uri_t)* uri);
const(char)* mongoc_uri_get_auth_source (const(mongoc_uri_t)* uri);
const(char)* mongoc_uri_get_auth_mechanism (const(mongoc_uri_t)* uri);
bool mongoc_uri_get_mechanism_properties (const(mongoc_uri_t)* uri, bson_t* properties);
bool mongoc_uri_get_ssl (const(mongoc_uri_t)* uri);
char* mongoc_uri_unescape (const(char)* escaped_string);
const(mongoc_read_prefs_t)* mongoc_uri_get_read_prefs_t (const(mongoc_uri_t)* uri);
const(mongoc_write_concern_t)* mongoc_uri_get_write_concern (const(mongoc_uri_t)* uri);
const(mongoc_read_concern_t)* mongoc_uri_get_read_concern (const(mongoc_uri_t)* uri);

// from file mongoc-database-patched.c:

alias _mongoc_collection_t mongoc_collection_t;
alias _mongoc_database_t mongoc_database_t;

struct _mongoc_collection_t;


struct _mongoc_database_t;


const(char)* mongoc_database_get_name (mongoc_database_t* database);
bool mongoc_database_remove_user (mongoc_database_t* database, const(char)* username, bson_error_t* error);
bool mongoc_database_remove_all_users (mongoc_database_t* database, bson_error_t* error);
bool mongoc_database_add_user (mongoc_database_t* database, const(char)* username, const(char)* password, const(bson_t)* roles, const(bson_t)* custom_data, bson_error_t* error);
void mongoc_database_destroy (mongoc_database_t* database);
mongoc_database_t* mongoc_database_copy (mongoc_database_t* database);
mongoc_cursor_t* mongoc_database_command (mongoc_database_t* database, mongoc_query_flags_t flags, uint skip, uint limit, uint batch_size, const(bson_t)* command, const(bson_t)* fields, const(mongoc_read_prefs_t)* read_prefs);
bool mongoc_database_command_simple (mongoc_database_t* database, const(bson_t)* command, const(mongoc_read_prefs_t)* read_prefs, bson_t* reply, bson_error_t* error);
bool mongoc_database_drop (mongoc_database_t* database, bson_error_t* error);
bool mongoc_database_has_collection (mongoc_database_t* database, const(char)* name, bson_error_t* error);
mongoc_collection_t* mongoc_database_create_collection (mongoc_database_t* database, const(char)* name, const(bson_t)* options, bson_error_t* error);
const(mongoc_read_prefs_t)* mongoc_database_get_read_prefs (const(mongoc_database_t)* database);
void mongoc_database_set_read_prefs (mongoc_database_t* database, const(mongoc_read_prefs_t)* read_prefs);
const(mongoc_write_concern_t)* mongoc_database_get_write_concern (const(mongoc_database_t)* database);
void mongoc_database_set_write_concern (mongoc_database_t* database, const(mongoc_write_concern_t)* write_concern);
const(mongoc_read_concern_t)* mongoc_database_get_read_concern (const(mongoc_database_t)* database);
void mongoc_database_set_read_concern (mongoc_database_t* database, const(mongoc_read_concern_t)* read_concern);
mongoc_cursor_t* mongoc_database_find_collections (mongoc_database_t* database, const(bson_t)* filter, bson_error_t* error);
char** mongoc_database_get_collection_names (mongoc_database_t* database, bson_error_t* error);
mongoc_collection_t* mongoc_database_get_collection (mongoc_database_t* database, const(char)* name);

// from file mongoc-stream.h:
import core.stdc.stdio;
import core.sys.posix.unistd;
import core.stdc.stdio;
import core.sys.posix.unistd;
import core.stdc.stdio;


alias _mongoc_stream_t mongoc_stream_t;
alias _mongoc_stream_poll_t mongoc_stream_poll_t;

struct _mongoc_stream_poll_t
{
    mongoc_stream_t* stream;
    int events;
    int revents;
}

struct _mongoc_stream_t
{
    int type;
    void function (mongoc_stream_t*) destroy;
    int function (mongoc_stream_t*) close;
    int function (mongoc_stream_t*) flush;
    ssize_t function (mongoc_stream_t*, mongoc_iovec_t*, size_t, int) writev;
    ssize_t function (mongoc_stream_t*, mongoc_iovec_t*, size_t, size_t, int) readv;
    int function (mongoc_stream_t*, int, int, void*, socklen_t) setsockopt;
    mongoc_stream_t* function (mongoc_stream_t*) get_base_stream;
    bool function (mongoc_stream_t*) check_closed;
    ssize_t function (mongoc_stream_poll_t*, size_t, int) poll;
    void function (mongoc_stream_t*) failed;
    void*[5] padding;
}

mongoc_stream_t* mongoc_stream_get_base_stream (mongoc_stream_t* stream);
int mongoc_stream_close (mongoc_stream_t* stream);
void mongoc_stream_destroy (mongoc_stream_t* stream);
void mongoc_stream_failed (mongoc_stream_t* stream);
int mongoc_stream_flush (mongoc_stream_t* stream);
ssize_t mongoc_stream_writev (mongoc_stream_t* stream, mongoc_iovec_t* iov, size_t iovcnt, int timeout_msec);
ssize_t mongoc_stream_write (mongoc_stream_t* stream, void* buf, size_t count, int timeout_msec);
ssize_t mongoc_stream_readv (mongoc_stream_t* stream, mongoc_iovec_t* iov, size_t iovcnt, size_t min_bytes, int timeout_msec);
ssize_t mongoc_stream_read (mongoc_stream_t* stream, void* buf, size_t count, size_t min_bytes, int timeout_msec);
int mongoc_stream_setsockopt (mongoc_stream_t* stream, int level, int optname, void* optval, socklen_t optlen);
bool mongoc_stream_check_closed (mongoc_stream_t* stream);
ssize_t mongoc_stream_poll (mongoc_stream_poll_t* streams, size_t nstreams, int timeout);

// from file mongoc-index.h:

// found alias: _Anonymous_0 => mongoc_index_opt_geo_t
// found alias: _Anonymous_1 => mongoc_index_opt_storage_t
// found alias: _Anonymous_2 => mongoc_index_storage_opt_type_t
// found alias: _Anonymous_3 => mongoc_index_opt_wt_t
// found alias: _Anonymous_4 => mongoc_index_opt_t

enum mongoc_index_storage_opt_type_t
{
    STORAGE_OPT_MMAPV1 = 0,
    STORAGE_OPT_WIREDTIGER = 1
}

struct mongoc_index_opt_geo_t
{
    ubyte twod_sphere_version;
    ubyte twod_bits_precision;
    double twod_location_min;
    double twod_location_max;
    double haystack_bucket_size;
    ubyte*[32] padding;
}

struct mongoc_index_opt_storage_t
{
    int type;
}

struct mongoc_index_opt_wt_t
{
    mongoc_index_opt_storage_t base;
    const(char)* config_str;
    void*[8] padding;
}

struct mongoc_index_opt_t
{
    bool is_initialized;
    bool background;
    bool unique;
    const(char)* name;
    bool drop_dups;
    bool sparse;
    int expire_after_seconds;
    int v;
    const(bson_t)* weights;
    const(char)* default_language;
    const(char)* language_override;
    mongoc_index_opt_geo_t* geo_options;
    mongoc_index_opt_storage_t* storage_options;
    const(bson_t)* partial_filter_expression;
    void*[5] padding;
}

const(mongoc_index_opt_t)* mongoc_index_opt_get_default ();
const(mongoc_index_opt_geo_t)* mongoc_index_opt_geo_get_default ();
const(mongoc_index_opt_wt_t)* mongoc_index_opt_wt_get_default ();
void mongoc_index_opt_init (mongoc_index_opt_t* opt);
void mongoc_index_opt_geo_init (mongoc_index_opt_geo_t* opt);
void mongoc_index_opt_wt_init (mongoc_index_opt_wt_t* opt);

// from file mongoc-collection.h:




mongoc_cursor_t* mongoc_collection_aggregate (mongoc_collection_t* collection, mongoc_query_flags_t flags, const(bson_t)* pipeline, const(bson_t)* options, const(mongoc_read_prefs_t)* read_prefs);
void mongoc_collection_destroy (mongoc_collection_t* collection);
mongoc_collection_t* mongoc_collection_copy (mongoc_collection_t* collection);
mongoc_cursor_t* mongoc_collection_command (mongoc_collection_t* collection, mongoc_query_flags_t flags, uint skip, uint limit, uint batch_size, const(bson_t)* command, const(bson_t)* fields, const(mongoc_read_prefs_t)* read_prefs);
bool mongoc_collection_command_simple (mongoc_collection_t* collection, const(bson_t)* command, const(mongoc_read_prefs_t)* read_prefs, bson_t* reply, bson_error_t* error);
long mongoc_collection_count (mongoc_collection_t* collection, mongoc_query_flags_t flags, const(bson_t)* query, long skip, long limit, const(mongoc_read_prefs_t)* read_prefs, bson_error_t* error);
long mongoc_collection_count_with_opts (mongoc_collection_t* collection, mongoc_query_flags_t flags, const(bson_t)* query, long skip, long limit, const(bson_t)* opts, const(mongoc_read_prefs_t)* read_prefs, bson_error_t* error);
bool mongoc_collection_drop (mongoc_collection_t* collection, bson_error_t* error);
bool mongoc_collection_drop_index (mongoc_collection_t* collection, const(char)* index_name, bson_error_t* error);
bool mongoc_collection_create_index (mongoc_collection_t* collection, const(bson_t)* keys, const(mongoc_index_opt_t)* opt, bson_error_t* error);
bool mongoc_collection_ensure_index (mongoc_collection_t* collection, const(bson_t)* keys, const(mongoc_index_opt_t)* opt, bson_error_t* error);
mongoc_cursor_t* mongoc_collection_find_indexes (mongoc_collection_t* collection, bson_error_t* error);
mongoc_cursor_t* mongoc_collection_find (mongoc_collection_t* collection, mongoc_query_flags_t flags, uint skip, uint limit, uint batch_size, const(bson_t)* query, const(bson_t)* fields, const(mongoc_read_prefs_t)* read_prefs);
bool mongoc_collection_insert (mongoc_collection_t* collection, mongoc_insert_flags_t flags, const(bson_t)* document, const(mongoc_write_concern_t)* write_concern, bson_error_t* error);
bool mongoc_collection_insert_bulk (mongoc_collection_t* collection, mongoc_insert_flags_t flags, const(bson_t*)* documents, uint n_documents, const(mongoc_write_concern_t)* write_concern, bson_error_t* error);
bool mongoc_collection_update (mongoc_collection_t* collection, mongoc_update_flags_t flags, const(bson_t)* selector, const(bson_t)* update, const(mongoc_write_concern_t)* write_concern, bson_error_t* error);
bool mongoc_collection_delete (mongoc_collection_t* collection, mongoc_delete_flags_t flags, const(bson_t)* selector, const(mongoc_write_concern_t)* write_concern, bson_error_t* error);
bool mongoc_collection_save (mongoc_collection_t* collection, const(bson_t)* document, const(mongoc_write_concern_t)* write_concern, bson_error_t* error);
bool mongoc_collection_remove (mongoc_collection_t* collection, mongoc_remove_flags_t flags, const(bson_t)* selector, const(mongoc_write_concern_t)* write_concern, bson_error_t* error);
bool mongoc_collection_rename (mongoc_collection_t* collection, const(char)* new_db, const(char)* new_name, bool drop_target_before_rename, bson_error_t* error);
bool mongoc_collection_find_and_modify_with_opts (mongoc_collection_t* collection, const(bson_t)* query, const(mongoc_find_and_modify_opts_t)* opts, bson_t* reply, bson_error_t* error);
bool mongoc_collection_find_and_modify (mongoc_collection_t* collection, const(bson_t)* query, const(bson_t)* sort, const(bson_t)* update, const(bson_t)* fields, bool _remove, bool upsert, bool _new, bson_t* reply, bson_error_t* error);
bool mongoc_collection_stats (mongoc_collection_t* collection, const(bson_t)* options, bson_t* reply, bson_error_t* error);
mongoc_bulk_operation_t* mongoc_collection_create_bulk_operation (mongoc_collection_t* collection, bool ordered, const(mongoc_write_concern_t)* write_concern);
const(mongoc_read_prefs_t)* mongoc_collection_get_read_prefs (const(mongoc_collection_t)* collection);
void mongoc_collection_set_read_prefs (mongoc_collection_t* collection, const(mongoc_read_prefs_t)* read_prefs);
const(mongoc_read_concern_t)* mongoc_collection_get_read_concern (const(mongoc_collection_t)* collection);
void mongoc_collection_set_read_concern (mongoc_collection_t* collection, const(mongoc_read_concern_t)* read_concern);
const(mongoc_write_concern_t)* mongoc_collection_get_write_concern (const(mongoc_collection_t)* collection);
void mongoc_collection_set_write_concern (mongoc_collection_t* collection, const(mongoc_write_concern_t)* write_concern);
const(char)* mongoc_collection_get_name (mongoc_collection_t* collection);
const(bson_t)* mongoc_collection_get_last_error (const(mongoc_collection_t)* collection);
char* mongoc_collection_keys_to_index_string (const(bson_t)* keys);
bool mongoc_collection_validate (mongoc_collection_t* collection, const(bson_t)* options, bson_t* reply, bson_error_t* error);

// from file utlist.h:

// from file mongoc-error.h:

// found alias: _Anonymous_0 => mongoc_error_domain_t
// found alias: _Anonymous_1 => mongoc_error_code_t

enum mongoc_error_domain_t
{
    CLIENT = 1,
    STREAM = 2,
    PROTOCOL = 3,
    CURSOR = 4,
    QUERY = 5,
    INSERT = 6,
    SASL = 7,
    BSON = 8,
    MATCHER = 9,
    NAMESPACE = 10,
    COMMAND = 11,
    COLLECTION = 12,
    GRIDFS = 13,
    SCRAM = 14,
    SERVER_SELECTION = 15,
    WRITE_CONCERN = 16
}

enum mongoc_error_code_t
{
    STREAM_INVALID_TYPE = 1,
    STREAM_INVALID_STATE = 2,
    STREAM_NAME_RESOLUTION = 3,
    STREAM_SOCKET = 4,
    STREAM_CONNECT = 5,
    STREAM_NOT_ESTABLISHED = 6,
    CLIENT_NOT_READY = 7,
    CLIENT_TOO_BIG = 8,
    CLIENT_TOO_SMALL = 9,
    CLIENT_GETNONCE = 10,
    CLIENT_AUTHENTICATE = 11,
    CLIENT_NO_ACCEPTABLE_PEER = 12,
    CLIENT_IN_EXHAUST = 13,
    PROTOCOL_INVALID_REPLY = 14,
    PROTOCOL_BAD_WIRE_VERSION = 15,
    CURSOR_INVALID_CURSOR = 16,
    QUERY_FAILURE = 17,
    BSON_INVALID = 18,
    MATCHER_INVALID = 19,
    NAMESPACE_INVALID = 20,
    NAMESPACE_INVALID_FILTER_TYPE = 21,
    COMMAND_INVALID_ARG = 22,
    COLLECTION_INSERT_FAILED = 23,
    COLLECTION_UPDATE_FAILED = 24,
    COLLECTION_DELETE_FAILED = 25,
    COLLECTION_DOES_NOT_EXIST = 26,
    GRIDFS_INVALID_FILENAME = 27,
    SCRAM_NOT_DONE = 28,
    SCRAM_PROTOCOL_ERROR = 29,
    QUERY_COMMAND_NOT_FOUND = 59,
    QUERY_NOT_TAILABLE = 13051,
    SERVER_SELECTION_BAD_WIRE_VERSION = 13052,
    SERVER_SELECTION_FAILURE = 13053,
    SERVER_SELECTION_INVALID_ID = 13054,
    GRIDFS_CHUNK_MISSING = 13055,
    PROTOCOL_ERROR = 17,
    WRITE_CONCERN_ERROR = 64
}

// from file mongoc-init.h:

void mongoc_init ();
void mongoc_cleanup ();

// from file mongoc-stream-buffered.h:

mongoc_stream_t* mongoc_stream_buffered_new (mongoc_stream_t* base_stream, size_t buffer_size);

// from file mongoc-socket.h:
import core.sys.posix.unistd;
import core.stdc.stdio;
import core.sys.posix.unistd;
import core.stdc.stdio;
import core.sys.posix.netdb;
import core.stdc.stdio;


alias _mongoc_socket_t mongoc_socket_t;
// found alias: _Anonymous_0 => mongoc_socket_poll_t

struct mongoc_socket_poll_t
{
    mongoc_socket_t* socket;
    int events;
    int revents;
}

struct _mongoc_socket_t;


mongoc_socket_t* mongoc_socket_accept (mongoc_socket_t* sock, long expire_at);
int mongoc_socket_bind (mongoc_socket_t* sock, const(sockaddr)* addr, socklen_t addrlen);
int mongoc_socket_close (mongoc_socket_t* socket);
int mongoc_socket_connect (mongoc_socket_t* sock, const(sockaddr)* addr, socklen_t addrlen, long expire_at);
char* mongoc_socket_getnameinfo (mongoc_socket_t* sock);
void mongoc_socket_destroy (mongoc_socket_t* sock);
int mongoc_socket_errno (mongoc_socket_t* sock);
int mongoc_socket_getsockname (mongoc_socket_t* sock, sockaddr* addr, socklen_t* addrlen);
int mongoc_socket_listen (mongoc_socket_t* sock, uint backlog);
mongoc_socket_t* mongoc_socket_new (int domain, int type, int protocol);
ssize_t mongoc_socket_recv (mongoc_socket_t* sock, void* buf, size_t buflen, int flags, long expire_at);
int mongoc_socket_setsockopt (mongoc_socket_t* sock, int level, int optname, const(void)* optval, socklen_t optlen);
ssize_t mongoc_socket_send (mongoc_socket_t* sock, const(void)* buf, size_t buflen, long expire_at);
ssize_t mongoc_socket_sendv (mongoc_socket_t* sock, mongoc_iovec_t* iov, size_t iovcnt, long expire_at);
bool mongoc_socket_check_closed (mongoc_socket_t* sock);
void mongoc_socket_inet_ntop (addrinfo* rp, char* buf, size_t buflen);
ssize_t mongoc_socket_poll (mongoc_socket_poll_t* sds, size_t nsds, int timeout);

// from file mongoc-find-and-modify.h:

// found alias: _Anonymous_0 => mongoc_find_and_modify_flags_t
alias _mongoc_find_and_modify_opts_t mongoc_find_and_modify_opts_t;

enum mongoc_find_and_modify_flags_t
{
    AND_MODIFY_NONE = 0,
    AND_MODIFY_REMOVE = 1,
    AND_MODIFY_UPSERT = 2,
    AND_MODIFY_RETURN_NEW = 4
}

struct _mongoc_find_and_modify_opts_t;


mongoc_find_and_modify_opts_t* mongoc_find_and_modify_opts_new ();
bool mongoc_find_and_modify_opts_set_sort (mongoc_find_and_modify_opts_t* opts, const(bson_t)* sort);
bool mongoc_find_and_modify_opts_set_update (mongoc_find_and_modify_opts_t* opts, const(bson_t)* update);
bool mongoc_find_and_modify_opts_set_fields (mongoc_find_and_modify_opts_t* opts, const(bson_t)* fields);
bool mongoc_find_and_modify_opts_set_flags (mongoc_find_and_modify_opts_t* opts, const mongoc_find_and_modify_flags_t flags);
bool mongoc_find_and_modify_opts_set_bypass_document_validation (mongoc_find_and_modify_opts_t* opts, bool bypass);
void mongoc_find_and_modify_opts_destroy (mongoc_find_and_modify_opts_t* opts);

// from file mongoc-client.h:

alias _mongoc_client_t mongoc_client_t;
alias _mongoc_stream_t* function (const(_mongoc_uri_t)*, const(_mongoc_host_list_t)*, void*, _bson_error_t*) mongoc_stream_initiator_t;

struct _mongoc_client_t;


mongoc_client_t* mongoc_client_new (const(char)* uri_string);
mongoc_client_t* mongoc_client_new_from_uri (const(mongoc_uri_t)* uri);
const(mongoc_uri_t)* mongoc_client_get_uri (const(mongoc_client_t)* client);
void mongoc_client_set_stream_initiator (mongoc_client_t* client, mongoc_stream_initiator_t initiator, void* user_data);
mongoc_cursor_t* mongoc_client_command (mongoc_client_t* client, const(char)* db_name, mongoc_query_flags_t flags, uint skip, uint limit, uint batch_size, const(bson_t)* query, const(bson_t)* fields, const(mongoc_read_prefs_t)* read_prefs);
void mongoc_client_kill_cursor (mongoc_client_t* client, long cursor_id);
bool mongoc_client_command_simple (mongoc_client_t* client, const(char)* db_name, const(bson_t)* command, const(mongoc_read_prefs_t)* read_prefs, bson_t* reply, bson_error_t* error);
void mongoc_client_destroy (mongoc_client_t* client);
mongoc_database_t* mongoc_client_get_database (mongoc_client_t* client, const(char)* name);
mongoc_database_t* mongoc_client_get_default_database (mongoc_client_t* client);
mongoc_gridfs_t* mongoc_client_get_gridfs (mongoc_client_t* client, const(char)* db, const(char)* prefix, bson_error_t* error);
mongoc_collection_t* mongoc_client_get_collection (mongoc_client_t* client, const(char)* db, const(char)* collection);
char** mongoc_client_get_database_names (mongoc_client_t* client, bson_error_t* error);
mongoc_cursor_t* mongoc_client_find_databases (mongoc_client_t* client, bson_error_t* error);
bool mongoc_client_get_server_status (mongoc_client_t* client, mongoc_read_prefs_t* read_prefs, bson_t* reply, bson_error_t* error);
int mongoc_client_get_max_message_size (mongoc_client_t* client);
int mongoc_client_get_max_bson_size (mongoc_client_t* client);
const(mongoc_write_concern_t)* mongoc_client_get_write_concern (const(mongoc_client_t)* client);
void mongoc_client_set_write_concern (mongoc_client_t* client, const(mongoc_write_concern_t)* write_concern);
const(mongoc_read_concern_t)* mongoc_client_get_read_concern (const(mongoc_client_t)* client);
void mongoc_client_set_read_concern (mongoc_client_t* client, const(mongoc_read_concern_t)* read_concern);
const(mongoc_read_prefs_t)* mongoc_client_get_read_prefs (const(mongoc_client_t)* client);
void mongoc_client_set_read_prefs (mongoc_client_t* client, const(mongoc_read_prefs_t)* read_prefs);
void mongoc_client_set_ssl_opts (mongoc_client_t* client, const(mongoc_ssl_opt_t)* opts);

// from file mongoc-stream-socket.h:

alias _mongoc_stream_socket_t mongoc_stream_socket_t;

struct _mongoc_stream_socket_t;


mongoc_stream_t* mongoc_stream_socket_new (mongoc_socket_t* socket);
mongoc_socket_t* mongoc_stream_socket_get_socket (mongoc_stream_socket_t* stream);
