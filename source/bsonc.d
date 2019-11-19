


        import core.stdc.config;
        import core.stdc.stdarg: va_list;
        static import core.simd;
        static import std.conv;

        struct Int128 { long lower; long upper; }
        struct UInt128 { ulong lower; ulong upper; }

        struct __locale_data { int dummy; }



alias _Bool = bool;
struct dpp {
    static struct Opaque(int N) {
        void[N] bytes;
    }

    static bool isEmpty(T)() {
        return T.tupleof.length == 0;
    }
    static struct Move(T) {
        T* ptr;
    }


    static auto move(T)(ref T value) {
        return Move!T(&value);
    }
    mixin template EnumD(string name, T, string prefix) if(is(T == enum)) {
        private static string _memberMixinStr(string member) {
            import std.conv: text;
            import std.array: replace;
            return text(` `, member.replace(prefix, ""), ` = `, T.stringof, `.`, member, `,`);
        }
        private static string _enumMixinStr() {
            import std.array: join;
            string[] ret;
            ret ~= "enum " ~ name ~ "{";
            static foreach(member; __traits(allMembers, T)) {
                ret ~= _memberMixinStr(member);
            }
            ret ~= "}";
            return ret.join("\n");
        }
        mixin(_enumMixinStr());
    }
}

extern(C)
{
    alias wchar_t = int;
    int getentropy(void*, c_ulong) @nogc nothrow;
    char* crypt(const(char)*, const(char)*) @nogc nothrow;
    int fdatasync(int) @nogc nothrow;
    int lockf(int, int, c_long) @nogc nothrow;
    c_long syscall(c_long, ...) @nogc nothrow;
    void* sbrk(c_long) @nogc nothrow;
    int brk(void*) @nogc nothrow;
    int ftruncate(int, c_long) @nogc nothrow;
    int truncate(const(char)*, c_long) @nogc nothrow;
    int getdtablesize() @nogc nothrow;
    int getpagesize() @nogc nothrow;
    void sync() @nogc nothrow;
    c_long gethostid() @nogc nothrow;
    int fsync(int) @nogc nothrow;
    char* getpass(const(char)*) @nogc nothrow;
    int chroot(const(char)*) @nogc nothrow;
    int daemon(int, int) @nogc nothrow;
    void setusershell() @nogc nothrow;
    void endusershell() @nogc nothrow;
    char* getusershell() @nogc nothrow;
    int acct(const(char)*) @nogc nothrow;
    int profil(ushort*, c_ulong, c_ulong, uint) @nogc nothrow;
    int revoke(const(char)*) @nogc nothrow;
    int vhangup() @nogc nothrow;
    int setdomainname(const(char)*, c_ulong) @nogc nothrow;
    int getdomainname(char*, c_ulong) @nogc nothrow;
    int sethostid(c_long) @nogc nothrow;
    int sethostname(const(char)*, c_ulong) @nogc nothrow;
    int gethostname(char*, c_ulong) @nogc nothrow;
    int setlogin(const(char)*) @nogc nothrow;
    int getlogin_r(char*, c_ulong) @nogc nothrow;
    char* getlogin() @nogc nothrow;
    int tcsetpgrp(int, int) @nogc nothrow;
    int tcgetpgrp(int) @nogc nothrow;
    int rmdir(const(char)*) @nogc nothrow;
    int unlinkat(int, const(char)*, int) @nogc nothrow;
    int unlink(const(char)*) @nogc nothrow;
    c_long readlinkat(int, const(char)*, char*, c_ulong) @nogc nothrow;
    int symlinkat(const(char)*, int, const(char)*) @nogc nothrow;
    c_long readlink(const(char)*, char*, c_ulong) @nogc nothrow;
    int symlink(const(char)*, const(char)*) @nogc nothrow;
    int linkat(int, const(char)*, int, const(char)*, int) @nogc nothrow;
    int link(const(char)*, const(char)*) @nogc nothrow;
    int ttyslot() @nogc nothrow;
    int isatty(int) @nogc nothrow;
    int ttyname_r(int, char*, c_ulong) @nogc nothrow;
    char* ttyname(int) @nogc nothrow;
    int vfork() @nogc nothrow;
    int fork() @nogc nothrow;
    int setegid(uint) @nogc nothrow;
    int setregid(uint, uint) @nogc nothrow;
    int setgid(uint) @nogc nothrow;
    int seteuid(uint) @nogc nothrow;
    int setreuid(uint, uint) @nogc nothrow;
    int setuid(uint) @nogc nothrow;
    int getgroups(int, uint*) @nogc nothrow;
    uint getegid() @nogc nothrow;
    uint getgid() @nogc nothrow;
    uint geteuid() @nogc nothrow;
    uint getuid() @nogc nothrow;
    int getsid(int) @nogc nothrow;
    int setsid() @nogc nothrow;
    int setpgrp() @nogc nothrow;
    int setpgid(int, int) @nogc nothrow;
    int getpgid(int) @nogc nothrow;
    int __getpgid(int) @nogc nothrow;
    int getpgrp() @nogc nothrow;
    int getppid() @nogc nothrow;
    int getpid() @nogc nothrow;
    c_ulong confstr(int, char*, c_ulong) @nogc nothrow;
    c_long sysconf(int) @nogc nothrow;
    c_long fpathconf(int, int) @nogc nothrow;
    c_long pathconf(const(char)*, int) @nogc nothrow;
    void _exit(int) @nogc nothrow;
    int nice(int) @nogc nothrow;
    int execlp(const(char)*, const(char)*, ...) @nogc nothrow;
    int execvp(const(char)*, char**) @nogc nothrow;
    int execl(const(char)*, const(char)*, ...) @nogc nothrow;
    int execle(const(char)*, const(char)*, ...) @nogc nothrow;
    int execv(const(char)*, char**) @nogc nothrow;
    int fexecve(int, char**, char**) @nogc nothrow;
    int execve(const(char)*, char**, char**) @nogc nothrow;
    extern __gshared char** __environ;
    int dup2(int, int) @nogc nothrow;
    int dup(int) @nogc nothrow;
    char* getwd(char*) @nogc nothrow;
    char* getcwd(char*, c_ulong) @nogc nothrow;
    int fchdir(int) @nogc nothrow;
    int chdir(const(char)*) @nogc nothrow;
    int fchownat(int, const(char)*, uint, uint, int) @nogc nothrow;
    int lchown(const(char)*, uint, uint) @nogc nothrow;
    int fchown(int, uint, uint) @nogc nothrow;
    int chown(const(char)*, uint, uint) @nogc nothrow;
    int pause() @nogc nothrow;
    int usleep(uint) @nogc nothrow;
    uint ualarm(uint, uint) @nogc nothrow;
    uint sleep(uint) @nogc nothrow;
    uint alarm(uint) @nogc nothrow;
    static const(char)* bcon_ensure_const_char_ptr(const(char)*) @nogc nothrow;
    static const(char)** bcon_ensure_const_char_ptr_ptr(const(char)**) @nogc nothrow;
    static double bcon_ensure_double(double) @nogc nothrow;
    static double* bcon_ensure_double_ptr(double*) @nogc nothrow;
    static const(_bson_t)* bcon_ensure_const_bson_ptr(const(_bson_t)*) @nogc nothrow;
    static _bson_t* bcon_ensure_bson_ptr(_bson_t*) @nogc nothrow;
    static bson_subtype_t bcon_ensure_subtype(bson_subtype_t) @nogc nothrow;
    static bson_subtype_t* bcon_ensure_subtype_ptr(bson_subtype_t*) @nogc nothrow;
    static const(ubyte)* bcon_ensure_const_uint8_ptr(const(ubyte)*) @nogc nothrow;
    static const(ubyte)** bcon_ensure_const_uint8_ptr_ptr(const(ubyte)**) @nogc nothrow;
    static uint bcon_ensure_uint32(uint) @nogc nothrow;
    static uint* bcon_ensure_uint32_ptr(uint*) @nogc nothrow;
    static const(bson_oid_t)* bcon_ensure_const_oid_ptr(const(bson_oid_t)*) @nogc nothrow;
    static const(bson_oid_t)** bcon_ensure_const_oid_ptr_ptr(const(bson_oid_t)**) @nogc nothrow;
    static int bcon_ensure_int32(int) @nogc nothrow;
    static int* bcon_ensure_int32_ptr(int*) @nogc nothrow;
    static c_long bcon_ensure_int64(c_long) @nogc nothrow;
    static c_long* bcon_ensure_int64_ptr(c_long*) @nogc nothrow;
    static const(bson_decimal128_t)* bcon_ensure_const_decimal128_ptr(const(bson_decimal128_t)*) @nogc nothrow;
    static bool bcon_ensure_bool(bool) @nogc nothrow;
    static bool* bcon_ensure_bool_ptr(bool*) @nogc nothrow;
    static bson_type_t bcon_ensure_bson_type(bson_type_t) @nogc nothrow;
    static bson_iter_t* bcon_ensure_bson_iter_ptr(bson_iter_t*) @nogc nothrow;
    static const(bson_iter_t)* bcon_ensure_const_bson_iter_ptr(const(bson_iter_t)*) @nogc nothrow;
    int pipe(int*) @nogc nothrow;
    c_long pwrite(int, const(void)*, c_ulong, c_long) @nogc nothrow;
    c_long pread(int, void*, c_ulong, c_long) @nogc nothrow;
    c_long write(int, const(void)*, c_ulong) @nogc nothrow;
    c_long read(int, void*, c_ulong) @nogc nothrow;
    int close(int) @nogc nothrow;
    c_long lseek(int, c_long, int) @nogc nothrow;
    int faccessat(int, const(char)*, int, int) @nogc nothrow;
    int access(const(char)*, int) @nogc nothrow;
    alias socklen_t = uint;
    alias intptr_t = c_long;
    alias pid_t = int;
    alias useconds_t = uint;
    alias uid_t = uint;
    alias gid_t = uint;
    alias bcon_type_t = _Anonymous_0;
    enum _Anonymous_0
    {
        BCON_TYPE_UTF8 = 0,
        BCON_TYPE_DOUBLE = 1,
        BCON_TYPE_DOCUMENT = 2,
        BCON_TYPE_ARRAY = 3,
        BCON_TYPE_BIN = 4,
        BCON_TYPE_UNDEFINED = 5,
        BCON_TYPE_OID = 6,
        BCON_TYPE_BOOL = 7,
        BCON_TYPE_DATE_TIME = 8,
        BCON_TYPE_NULL = 9,
        BCON_TYPE_REGEX = 10,
        BCON_TYPE_DBPOINTER = 11,
        BCON_TYPE_CODE = 12,
        BCON_TYPE_SYMBOL = 13,
        BCON_TYPE_CODEWSCOPE = 14,
        BCON_TYPE_INT32 = 15,
        BCON_TYPE_TIMESTAMP = 16,
        BCON_TYPE_INT64 = 17,
        BCON_TYPE_DECIMAL128 = 18,
        BCON_TYPE_MAXKEY = 19,
        BCON_TYPE_MINKEY = 20,
        BCON_TYPE_BCON = 21,
        BCON_TYPE_ARRAY_START = 22,
        BCON_TYPE_ARRAY_END = 23,
        BCON_TYPE_DOC_START = 24,
        BCON_TYPE_DOC_END = 25,
        BCON_TYPE_END = 26,
        BCON_TYPE_RAW = 27,
        BCON_TYPE_SKIP = 28,
        BCON_TYPE_ITER = 29,
        BCON_TYPE_ERROR = 30,
    }
    enum BCON_TYPE_UTF8 = _Anonymous_0.BCON_TYPE_UTF8;
    enum BCON_TYPE_DOUBLE = _Anonymous_0.BCON_TYPE_DOUBLE;
    enum BCON_TYPE_DOCUMENT = _Anonymous_0.BCON_TYPE_DOCUMENT;
    enum BCON_TYPE_ARRAY = _Anonymous_0.BCON_TYPE_ARRAY;
    enum BCON_TYPE_BIN = _Anonymous_0.BCON_TYPE_BIN;
    enum BCON_TYPE_UNDEFINED = _Anonymous_0.BCON_TYPE_UNDEFINED;
    enum BCON_TYPE_OID = _Anonymous_0.BCON_TYPE_OID;
    enum BCON_TYPE_BOOL = _Anonymous_0.BCON_TYPE_BOOL;
    enum BCON_TYPE_DATE_TIME = _Anonymous_0.BCON_TYPE_DATE_TIME;
    enum BCON_TYPE_NULL = _Anonymous_0.BCON_TYPE_NULL;
    enum BCON_TYPE_REGEX = _Anonymous_0.BCON_TYPE_REGEX;
    enum BCON_TYPE_DBPOINTER = _Anonymous_0.BCON_TYPE_DBPOINTER;
    enum BCON_TYPE_CODE = _Anonymous_0.BCON_TYPE_CODE;
    enum BCON_TYPE_SYMBOL = _Anonymous_0.BCON_TYPE_SYMBOL;
    enum BCON_TYPE_CODEWSCOPE = _Anonymous_0.BCON_TYPE_CODEWSCOPE;
    enum BCON_TYPE_INT32 = _Anonymous_0.BCON_TYPE_INT32;
    enum BCON_TYPE_TIMESTAMP = _Anonymous_0.BCON_TYPE_TIMESTAMP;
    enum BCON_TYPE_INT64 = _Anonymous_0.BCON_TYPE_INT64;
    enum BCON_TYPE_DECIMAL128 = _Anonymous_0.BCON_TYPE_DECIMAL128;
    enum BCON_TYPE_MAXKEY = _Anonymous_0.BCON_TYPE_MAXKEY;
    enum BCON_TYPE_MINKEY = _Anonymous_0.BCON_TYPE_MINKEY;
    enum BCON_TYPE_BCON = _Anonymous_0.BCON_TYPE_BCON;
    enum BCON_TYPE_ARRAY_START = _Anonymous_0.BCON_TYPE_ARRAY_START;
    enum BCON_TYPE_ARRAY_END = _Anonymous_0.BCON_TYPE_ARRAY_END;
    enum BCON_TYPE_DOC_START = _Anonymous_0.BCON_TYPE_DOC_START;
    enum BCON_TYPE_DOC_END = _Anonymous_0.BCON_TYPE_DOC_END;
    enum BCON_TYPE_END = _Anonymous_0.BCON_TYPE_END;
    enum BCON_TYPE_RAW = _Anonymous_0.BCON_TYPE_RAW;
    enum BCON_TYPE_SKIP = _Anonymous_0.BCON_TYPE_SKIP;
    enum BCON_TYPE_ITER = _Anonymous_0.BCON_TYPE_ITER;
    enum BCON_TYPE_ERROR = _Anonymous_0.BCON_TYPE_ERROR;
    alias bcon_append_ctx_frame_t = bcon_append_ctx_frame;
    struct bcon_append_ctx_frame
    {
        int i;
        bool is_array;
        _bson_t bson;
    }
    alias bcon_extract_ctx_frame_t = bcon_extract_ctx_frame;
    struct bcon_extract_ctx_frame
    {
        int i;
        bool is_array;
        bson_iter_t iter;
    }
    alias bcon_append_ctx_t = _bcon_append_ctx_t;
    struct _bcon_append_ctx_t
    {
        bcon_append_ctx_frame[100] stack;
        int n;
    }
    alias bcon_extract_ctx_t = _bcon_extract_ctx_t;
    struct _bcon_extract_ctx_t
    {
        bcon_extract_ctx_frame[100] stack;
        int n;
    }
    void bcon_append(_bson_t*, ...) @nogc nothrow;
    void bcon_append_ctx(_bson_t*, _bcon_append_ctx_t*, ...) @nogc nothrow;
    void bcon_append_ctx_va(_bson_t*, _bcon_append_ctx_t*, va_list**) @nogc nothrow;
    void bcon_append_ctx_init(_bcon_append_ctx_t*) @nogc nothrow;
    void bcon_extract_ctx_init(_bcon_extract_ctx_t*) @nogc nothrow;
    void bcon_extract_ctx(_bson_t*, _bcon_extract_ctx_t*, ...) @nogc nothrow;
    bool bcon_extract_ctx_va(_bson_t*, _bcon_extract_ctx_t*, va_list**) @nogc nothrow;
    bool bcon_extract(_bson_t*, ...) @nogc nothrow;
    bool bcon_extract_va(_bson_t*, _bcon_extract_ctx_t*, ...) @nogc nothrow;
    _bson_t* bcon_new(void*, ...) @nogc nothrow;
    int timespec_get(timespec*, int) @nogc nothrow;
    int timer_getoverrun(void*) @nogc nothrow;
    const(char)* bson_bcon_magic() @nogc nothrow;
    const(char)* bson_bcone_magic() @nogc nothrow;
    int timer_gettime(void*, itimerspec*) @nogc nothrow;
    int timer_settime(void*, int, const(itimerspec)*, itimerspec*) @nogc nothrow;
    c_long bson_get_monotonic_time() @nogc nothrow;
    int bson_gettimeofday(timeval*) @nogc nothrow;
    int timer_delete(void*) @nogc nothrow;
    int timer_create(int, sigevent*, void**) @nogc nothrow;
    _bson_context_t* bson_context_new(bson_context_flags_t) @nogc nothrow;
    void bson_context_destroy(_bson_context_t*) @nogc nothrow;
    _bson_context_t* bson_context_get_default() @nogc nothrow;
    int clock_getcpuclockid(int, int*) @nogc nothrow;
    int clock_nanosleep(int, int, const(timespec)*, timespec*) @nogc nothrow;
    void bson_decimal128_to_string(const(bson_decimal128_t)*, char*) @nogc nothrow;
    bool bson_decimal128_from_string(const(char)*, bson_decimal128_t*) @nogc nothrow;
    bool bson_decimal128_from_string_w_len(const(char)*, int, bson_decimal128_t*) @nogc nothrow;
    int clock_settime(int, const(timespec)*) @nogc nothrow;
    int clock_gettime(int, timespec*) @nogc nothrow;
    int clock_getres(int, timespec*) @nogc nothrow;
    int nanosleep(const(timespec)*, timespec*) @nogc nothrow;
    int dysize(int) @nogc nothrow;
    c_long timelocal(tm*) @nogc nothrow;
    c_long timegm(tm*) @nogc nothrow;
    int stime(const(c_long)*) @nogc nothrow;
    pragma(mangle, "timezone") extern __gshared c_long timezone_;
    extern __gshared int daylight;
    static ushort __bson_uint16_swap_slow(ushort) @nogc nothrow;
    static uint __bson_uint32_swap_slow(uint) @nogc nothrow;
    static c_ulong __bson_uint64_swap_slow(c_ulong) @nogc nothrow;
    alias static_assert_test_210sizeof_uint64_t = char[1];
    static double __bson_double_swap_slow(double) @nogc nothrow;
    void tzset() @nogc nothrow;
    extern __gshared char*[2] tzname;
    void bson_set_error(_bson_error_t*, uint, uint, const(char)*, ...) @nogc nothrow;
    char* bson_strerror_r(int, char*, c_ulong) @nogc nothrow;
    extern __gshared c_long __timezone;
    extern __gshared int __daylight;
    extern __gshared char*[2] __tzname;
    char* ctime_r(const(c_long)*, char*) @nogc nothrow;
    char* asctime_r(const(tm)*, char*) @nogc nothrow;
    char* ctime(const(c_long)*) @nogc nothrow;
    char* asctime(const(tm)*) @nogc nothrow;
    tm* localtime_r(const(c_long)*, tm*) @nogc nothrow;
    tm* gmtime_r(const(c_long)*, tm*) @nogc nothrow;
    tm* localtime(const(c_long)*) @nogc nothrow;
    tm* gmtime(const(c_long)*) @nogc nothrow;
    c_ulong strftime_l(char*, c_ulong, const(char)*, const(tm)*, __locale_struct*) @nogc nothrow;
    const(_bson_value_t)* bson_iter_value(bson_iter_t*) @nogc nothrow;
    static uint bson_iter_utf8_len_unsafe(const(bson_iter_t)*) @nogc nothrow;
    void bson_iter_array(const(bson_iter_t)*, uint*, const(ubyte)**) @nogc nothrow;
    void bson_iter_binary(const(bson_iter_t)*, bson_subtype_t*, uint*, const(ubyte)**) @nogc nothrow;
    const(char)* bson_iter_code(const(bson_iter_t)*, uint*) @nogc nothrow;
    static const(char)* bson_iter_code_unsafe(const(bson_iter_t)*, uint*) @nogc nothrow;
    const(char)* bson_iter_codewscope(const(bson_iter_t)*, uint*, uint*, const(ubyte)**) @nogc nothrow;
    void bson_iter_dbpointer(const(bson_iter_t)*, uint*, const(char)**, const(bson_oid_t)**) @nogc nothrow;
    void bson_iter_document(const(bson_iter_t)*, uint*, const(ubyte)**) @nogc nothrow;
    double bson_iter_double(const(bson_iter_t)*) @nogc nothrow;
    double bson_iter_as_double(const(bson_iter_t)*) @nogc nothrow;
    static double bson_iter_double_unsafe(const(bson_iter_t)*) @nogc nothrow;
    bool bson_iter_init(bson_iter_t*, const(_bson_t)*) @nogc nothrow;
    bool bson_iter_init_from_data(bson_iter_t*, const(ubyte)*, c_ulong) @nogc nothrow;
    bool bson_iter_init_find(bson_iter_t*, const(_bson_t)*, const(char)*) @nogc nothrow;
    bool bson_iter_init_find_w_len(bson_iter_t*, const(_bson_t)*, const(char)*, int) @nogc nothrow;
    bool bson_iter_init_find_case(bson_iter_t*, const(_bson_t)*, const(char)*) @nogc nothrow;
    bool bson_iter_init_from_data_at_offset(bson_iter_t*, const(ubyte)*, c_ulong, uint, uint) @nogc nothrow;
    int bson_iter_int32(const(bson_iter_t)*) @nogc nothrow;
    static int bson_iter_int32_unsafe(const(bson_iter_t)*) @nogc nothrow;
    c_long bson_iter_int64(const(bson_iter_t)*) @nogc nothrow;
    c_long bson_iter_as_int64(const(bson_iter_t)*) @nogc nothrow;
    static c_long bson_iter_int64_unsafe(const(bson_iter_t)*) @nogc nothrow;
    bool bson_iter_find(bson_iter_t*, const(char)*) @nogc nothrow;
    bool bson_iter_find_w_len(bson_iter_t*, const(char)*, int) @nogc nothrow;
    bool bson_iter_find_case(bson_iter_t*, const(char)*) @nogc nothrow;
    bool bson_iter_find_descendant(bson_iter_t*, const(char)*, bson_iter_t*) @nogc nothrow;
    bool bson_iter_next(bson_iter_t*) @nogc nothrow;
    const(bson_oid_t)* bson_iter_oid(const(bson_iter_t)*) @nogc nothrow;
    static const(bson_oid_t)* bson_iter_oid_unsafe(const(bson_iter_t)*) @nogc nothrow;
    bool bson_iter_decimal128(const(bson_iter_t)*, bson_decimal128_t*) @nogc nothrow;
    static void bson_iter_decimal128_unsafe(const(bson_iter_t)*, bson_decimal128_t*) @nogc nothrow;
    const(char)* bson_iter_key(const(bson_iter_t)*) @nogc nothrow;
    uint bson_iter_key_len(const(bson_iter_t)*) @nogc nothrow;
    static const(char)* bson_iter_key_unsafe(const(bson_iter_t)*) @nogc nothrow;
    const(char)* bson_iter_utf8(const(bson_iter_t)*, uint*) @nogc nothrow;
    static const(char)* bson_iter_utf8_unsafe(const(bson_iter_t)*, c_ulong*) @nogc nothrow;
    char* bson_iter_dup_utf8(const(bson_iter_t)*, uint*) @nogc nothrow;
    c_long bson_iter_date_time(const(bson_iter_t)*) @nogc nothrow;
    c_long bson_iter_time_t(const(bson_iter_t)*) @nogc nothrow;
    static c_long bson_iter_time_t_unsafe(const(bson_iter_t)*) @nogc nothrow;
    void bson_iter_timeval(const(bson_iter_t)*, timeval*) @nogc nothrow;
    static void bson_iter_timeval_unsafe(const(bson_iter_t)*, timeval*) @nogc nothrow;
    void bson_iter_timestamp(const(bson_iter_t)*, uint*, uint*) @nogc nothrow;
    bool bson_iter_bool(const(bson_iter_t)*) @nogc nothrow;
    static bool bson_iter_bool_unsafe(const(bson_iter_t)*) @nogc nothrow;
    bool bson_iter_as_bool(const(bson_iter_t)*) @nogc nothrow;
    const(char)* bson_iter_regex(const(bson_iter_t)*, const(char)**) @nogc nothrow;
    const(char)* bson_iter_symbol(const(bson_iter_t)*, uint*) @nogc nothrow;
    bson_type_t bson_iter_type(const(bson_iter_t)*) @nogc nothrow;
    static bson_type_t bson_iter_type_unsafe(const(bson_iter_t)*) @nogc nothrow;
    bool bson_iter_recurse(const(bson_iter_t)*, bson_iter_t*) @nogc nothrow;
    void bson_iter_overwrite_int32(bson_iter_t*, int) @nogc nothrow;
    void bson_iter_overwrite_int64(bson_iter_t*, c_long) @nogc nothrow;
    void bson_iter_overwrite_double(bson_iter_t*, double) @nogc nothrow;
    void bson_iter_overwrite_decimal128(bson_iter_t*, const(bson_decimal128_t)*) @nogc nothrow;
    void bson_iter_overwrite_bool(bson_iter_t*, bool) @nogc nothrow;
    void bson_iter_overwrite_oid(bson_iter_t*, const(bson_oid_t)*) @nogc nothrow;
    void bson_iter_overwrite_timestamp(bson_iter_t*, uint, uint) @nogc nothrow;
    void bson_iter_overwrite_date_time(bson_iter_t*, c_long) @nogc nothrow;
    bool bson_iter_visit_all(bson_iter_t*, const(bson_visitor_t)*, void*) @nogc nothrow;
    uint bson_iter_offset(bson_iter_t*) @nogc nothrow;
    alias bson_json_reader_t = _bson_json_reader_t;
    struct _bson_json_reader_t;
    alias bson_json_error_code_t = _Anonymous_1;
    enum _Anonymous_1
    {
        BSON_JSON_ERROR_READ_CORRUPT_JS = 1,
        BSON_JSON_ERROR_READ_INVALID_PARAM = 2,
        BSON_JSON_ERROR_READ_CB_FAILURE = 3,
    }
    enum BSON_JSON_ERROR_READ_CORRUPT_JS = _Anonymous_1.BSON_JSON_ERROR_READ_CORRUPT_JS;
    enum BSON_JSON_ERROR_READ_INVALID_PARAM = _Anonymous_1.BSON_JSON_ERROR_READ_INVALID_PARAM;
    enum BSON_JSON_ERROR_READ_CB_FAILURE = _Anonymous_1.BSON_JSON_ERROR_READ_CB_FAILURE;
    alias bson_json_reader_cb = c_long function(void*, ubyte*, c_ulong);
    alias bson_json_destroy_cb = void function(void*);
    _bson_json_reader_t* bson_json_reader_new(void*, c_long function(void*, ubyte*, c_ulong), void function(void*), bool, c_ulong) @nogc nothrow;
    _bson_json_reader_t* bson_json_reader_new_from_fd(int, bool) @nogc nothrow;
    _bson_json_reader_t* bson_json_reader_new_from_file(const(char)*, _bson_error_t*) @nogc nothrow;
    void bson_json_reader_destroy(_bson_json_reader_t*) @nogc nothrow;
    int bson_json_reader_read(_bson_json_reader_t*, _bson_t*, _bson_error_t*) @nogc nothrow;
    _bson_json_reader_t* bson_json_data_reader_new(bool, c_ulong) @nogc nothrow;
    void bson_json_data_reader_ingest(_bson_json_reader_t*, const(ubyte)*, c_ulong) @nogc nothrow;
    c_ulong strftime(char*, c_ulong, const(char)*, const(tm)*) @nogc nothrow;
    c_ulong bson_uint32_to_string(uint, const(char)**, char*, c_ulong) @nogc nothrow;
    c_long mktime(tm*) @nogc nothrow;
    double difftime(c_long, c_long) @nogc nothrow;
    c_long time(c_long*) @nogc nothrow;
    c_long clock() @nogc nothrow;
    struct sigevent;
    alias fsfilcnt_t = c_ulong;
    alias fsblkcnt_t = c_ulong;
    alias blkcnt_t = c_long;
    alias blksize_t = c_long;
    alias register_t = c_long;
    struct bson_md5_t
    {
        uint[2] count;
        uint[4] abcd;
        ubyte[64] buf;
    }
    void bson_md5_init(bson_md5_t*) @nogc nothrow;
    void bson_md5_append(bson_md5_t*, const(ubyte)*, uint) @nogc nothrow;
    void bson_md5_finish(bson_md5_t*, ubyte*) @nogc nothrow;
    alias u_int64_t = c_ulong;
    alias bson_realloc_func = void* function(void*, c_ulong, void*);
    alias bson_mem_vtable_t = _bson_mem_vtable_t;
    struct _bson_mem_vtable_t
    {
        void* function(c_ulong) malloc;
        void* function(c_ulong, c_ulong) calloc;
        void* function(void*, c_ulong) realloc;
        void function(void*) free;
        void*[4] padding;
    }
    void bson_mem_set_vtable(const(_bson_mem_vtable_t)*) @nogc nothrow;
    void bson_mem_restore_vtable() @nogc nothrow;
    void* bson_malloc(c_ulong) @nogc nothrow;
    void* bson_malloc0(c_ulong) @nogc nothrow;
    void* bson_realloc(void*, c_ulong) @nogc nothrow;
    void* bson_realloc_ctx(void*, c_ulong, void*) @nogc nothrow;
    void bson_free(void*) @nogc nothrow;
    void bson_zero_free(void*, c_ulong) @nogc nothrow;
    alias u_int32_t = uint;
    int bson_oid_compare(const(bson_oid_t)*, const(bson_oid_t)*) @nogc nothrow;
    void bson_oid_copy(const(bson_oid_t)*, bson_oid_t*) @nogc nothrow;
    bool bson_oid_equal(const(bson_oid_t)*, const(bson_oid_t)*) @nogc nothrow;
    bool bson_oid_is_valid(const(char)*, c_ulong) @nogc nothrow;
    c_long bson_oid_get_time_t(const(bson_oid_t)*) @nogc nothrow;
    uint bson_oid_hash(const(bson_oid_t)*) @nogc nothrow;
    void bson_oid_init(bson_oid_t*, _bson_context_t*) @nogc nothrow;
    void bson_oid_init_from_data(bson_oid_t*, const(ubyte)*) @nogc nothrow;
    void bson_oid_init_from_string(bson_oid_t*, const(char)*) @nogc nothrow;
    void bson_oid_init_sequence(bson_oid_t*, _bson_context_t*) @nogc nothrow;
    void bson_oid_to_string(const(bson_oid_t)*, char*) @nogc nothrow;
    static int bson_oid_compare_unsafe(const(bson_oid_t)*, const(bson_oid_t)*) @nogc nothrow;
    static bool bson_oid_equal_unsafe(const(bson_oid_t)*, const(bson_oid_t)*) @nogc nothrow;
    static uint bson_oid_hash_unsafe(const(bson_oid_t)*) @nogc nothrow;
    static void bson_oid_copy_unsafe(const(bson_oid_t)*, bson_oid_t*) @nogc nothrow;
    static ubyte bson_oid_parse_hex_char(char) @nogc nothrow;
    static void bson_oid_init_from_string_unsafe(bson_oid_t*, const(char)*) @nogc nothrow;
    static c_long bson_oid_get_time_t_unsafe(const(bson_oid_t)*) @nogc nothrow;
    alias u_int16_t = ushort;
    alias u_int8_t = ubyte;
    alias bson_reader_read_func_t = c_long function(void*, void*, c_ulong);
    alias bson_reader_destroy_func_t = void function(void*);
    bson_reader_t* bson_reader_new_from_handle(void*, c_long function(void*, void*, c_ulong), void function(void*)) @nogc nothrow;
    bson_reader_t* bson_reader_new_from_fd(int, bool) @nogc nothrow;
    bson_reader_t* bson_reader_new_from_file(const(char)*, _bson_error_t*) @nogc nothrow;
    bson_reader_t* bson_reader_new_from_data(const(ubyte)*, c_ulong) @nogc nothrow;
    void bson_reader_destroy(bson_reader_t*) @nogc nothrow;
    void bson_reader_set_read_func(bson_reader_t*, c_long function(void*, void*, c_ulong)) @nogc nothrow;
    void bson_reader_set_destroy_func(bson_reader_t*, void function(void*)) @nogc nothrow;
    const(_bson_t)* bson_reader_read(bson_reader_t*, bool*) @nogc nothrow;
    c_long bson_reader_tell(bson_reader_t*) @nogc nothrow;
    void bson_reader_reset(bson_reader_t*) @nogc nothrow;
    struct bson_string_t
    {
        char* str;
        uint len;
        uint alloc;
    }
    bson_string_t* bson_string_new(const(char)*) @nogc nothrow;
    char* bson_string_free(bson_string_t*, bool) @nogc nothrow;
    void bson_string_append(bson_string_t*, const(char)*) @nogc nothrow;
    void bson_string_append_c(bson_string_t*, char) @nogc nothrow;
    void bson_string_append_unichar(bson_string_t*, uint) @nogc nothrow;
    void bson_string_append_printf(bson_string_t*, const(char)*, ...) @nogc nothrow;
    void bson_string_truncate(bson_string_t*, uint) @nogc nothrow;
    char* bson_strdup(const(char)*) @nogc nothrow;
    char* bson_strdup_printf(const(char)*, ...) @nogc nothrow;
    char* bson_strdupv_printf(const(char)*, va_list*) @nogc nothrow;
    char* bson_strndup(const(char)*, c_ulong) @nogc nothrow;
    void bson_strncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    int bson_vsnprintf(char*, c_ulong, const(char)*, va_list*) @nogc nothrow;
    int bson_snprintf(char*, c_ulong, const(char)*, ...) @nogc nothrow;
    void bson_strfreev(char**) @nogc nothrow;
    c_ulong bson_strnlen(const(char)*, c_ulong) @nogc nothrow;
    c_long bson_ascii_strtoll(const(char)*, char**, int) @nogc nothrow;
    int bson_strcasecmp(const(char)*, const(char)*) @nogc nothrow;
    alias bson_unichar_t = uint;
    alias bson_context_flags_t = _Anonymous_2;
    enum _Anonymous_2
    {
        BSON_CONTEXT_NONE = 0,
        BSON_CONTEXT_THREAD_SAFE = 1,
        BSON_CONTEXT_DISABLE_HOST_CACHE = 2,
        BSON_CONTEXT_DISABLE_PID_CACHE = 4,
        BSON_CONTEXT_USE_TASK_ID = 8,
    }
    enum BSON_CONTEXT_NONE = _Anonymous_2.BSON_CONTEXT_NONE;
    enum BSON_CONTEXT_THREAD_SAFE = _Anonymous_2.BSON_CONTEXT_THREAD_SAFE;
    enum BSON_CONTEXT_DISABLE_HOST_CACHE = _Anonymous_2.BSON_CONTEXT_DISABLE_HOST_CACHE;
    enum BSON_CONTEXT_DISABLE_PID_CACHE = _Anonymous_2.BSON_CONTEXT_DISABLE_PID_CACHE;
    enum BSON_CONTEXT_USE_TASK_ID = _Anonymous_2.BSON_CONTEXT_USE_TASK_ID;
    alias bson_context_t = _bson_context_t;
    struct _bson_context_t;
    alias bson_t = _bson_t;
    struct _bson_t
    {
        uint flags;
        uint len;
        ubyte[120] padding;
    }
    alias static_assert_test_167bson_t = char[1];
    struct bson_oid_t
    {
        ubyte[12] bytes;
    }
    alias static_assert_test_181oid_t = char[1];
    struct bson_decimal128_t
    {
        c_ulong low;
        c_ulong high;
    }
    alias bson_validate_flags_t = _Anonymous_3;
    enum _Anonymous_3
    {
        BSON_VALIDATE_NONE = 0,
        BSON_VALIDATE_UTF8 = 1,
        BSON_VALIDATE_DOLLAR_KEYS = 2,
        BSON_VALIDATE_DOT_KEYS = 4,
        BSON_VALIDATE_UTF8_ALLOW_NULL = 8,
        BSON_VALIDATE_EMPTY_KEYS = 16,
    }
    enum BSON_VALIDATE_NONE = _Anonymous_3.BSON_VALIDATE_NONE;
    enum BSON_VALIDATE_UTF8 = _Anonymous_3.BSON_VALIDATE_UTF8;
    enum BSON_VALIDATE_DOLLAR_KEYS = _Anonymous_3.BSON_VALIDATE_DOLLAR_KEYS;
    enum BSON_VALIDATE_DOT_KEYS = _Anonymous_3.BSON_VALIDATE_DOT_KEYS;
    enum BSON_VALIDATE_UTF8_ALLOW_NULL = _Anonymous_3.BSON_VALIDATE_UTF8_ALLOW_NULL;
    enum BSON_VALIDATE_EMPTY_KEYS = _Anonymous_3.BSON_VALIDATE_EMPTY_KEYS;
    alias bson_type_t = _Anonymous_4;
    enum _Anonymous_4
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
        BSON_TYPE_DECIMAL128 = 19,
        BSON_TYPE_MAXKEY = 127,
        BSON_TYPE_MINKEY = 255,
    }
    enum BSON_TYPE_EOD = _Anonymous_4.BSON_TYPE_EOD;
    enum BSON_TYPE_DOUBLE = _Anonymous_4.BSON_TYPE_DOUBLE;
    enum BSON_TYPE_UTF8 = _Anonymous_4.BSON_TYPE_UTF8;
    enum BSON_TYPE_DOCUMENT = _Anonymous_4.BSON_TYPE_DOCUMENT;
    enum BSON_TYPE_ARRAY = _Anonymous_4.BSON_TYPE_ARRAY;
    enum BSON_TYPE_BINARY = _Anonymous_4.BSON_TYPE_BINARY;
    enum BSON_TYPE_UNDEFINED = _Anonymous_4.BSON_TYPE_UNDEFINED;
    enum BSON_TYPE_OID = _Anonymous_4.BSON_TYPE_OID;
    enum BSON_TYPE_BOOL = _Anonymous_4.BSON_TYPE_BOOL;
    enum BSON_TYPE_DATE_TIME = _Anonymous_4.BSON_TYPE_DATE_TIME;
    enum BSON_TYPE_NULL = _Anonymous_4.BSON_TYPE_NULL;
    enum BSON_TYPE_REGEX = _Anonymous_4.BSON_TYPE_REGEX;
    enum BSON_TYPE_DBPOINTER = _Anonymous_4.BSON_TYPE_DBPOINTER;
    enum BSON_TYPE_CODE = _Anonymous_4.BSON_TYPE_CODE;
    enum BSON_TYPE_SYMBOL = _Anonymous_4.BSON_TYPE_SYMBOL;
    enum BSON_TYPE_CODEWSCOPE = _Anonymous_4.BSON_TYPE_CODEWSCOPE;
    enum BSON_TYPE_INT32 = _Anonymous_4.BSON_TYPE_INT32;
    enum BSON_TYPE_TIMESTAMP = _Anonymous_4.BSON_TYPE_TIMESTAMP;
    enum BSON_TYPE_INT64 = _Anonymous_4.BSON_TYPE_INT64;
    enum BSON_TYPE_DECIMAL128 = _Anonymous_4.BSON_TYPE_DECIMAL128;
    enum BSON_TYPE_MAXKEY = _Anonymous_4.BSON_TYPE_MAXKEY;
    enum BSON_TYPE_MINKEY = _Anonymous_4.BSON_TYPE_MINKEY;
    alias bson_subtype_t = _Anonymous_5;
    enum _Anonymous_5
    {
        BSON_SUBTYPE_BINARY = 0,
        BSON_SUBTYPE_FUNCTION = 1,
        BSON_SUBTYPE_BINARY_DEPRECATED = 2,
        BSON_SUBTYPE_UUID_DEPRECATED = 3,
        BSON_SUBTYPE_UUID = 4,
        BSON_SUBTYPE_MD5 = 5,
        BSON_SUBTYPE_USER = 128,
    }
    enum BSON_SUBTYPE_BINARY = _Anonymous_5.BSON_SUBTYPE_BINARY;
    enum BSON_SUBTYPE_FUNCTION = _Anonymous_5.BSON_SUBTYPE_FUNCTION;
    enum BSON_SUBTYPE_BINARY_DEPRECATED = _Anonymous_5.BSON_SUBTYPE_BINARY_DEPRECATED;
    enum BSON_SUBTYPE_UUID_DEPRECATED = _Anonymous_5.BSON_SUBTYPE_UUID_DEPRECATED;
    enum BSON_SUBTYPE_UUID = _Anonymous_5.BSON_SUBTYPE_UUID;
    enum BSON_SUBTYPE_MD5 = _Anonymous_5.BSON_SUBTYPE_MD5;
    enum BSON_SUBTYPE_USER = _Anonymous_5.BSON_SUBTYPE_USER;
    alias bson_value_t = _bson_value_t;
    struct _bson_value_t
    {
        bson_type_t value_type;
        int padding;
        static union _Anonymous_6
        {
            bson_oid_t v_oid;
            c_long v_int64;
            int v_int32;
            byte v_int8;
            double v_double;
            bool v_bool;
            c_long v_datetime;
            static struct _Anonymous_7
            {
                uint timestamp;
                uint increment;
            }
            _Anonymous_7 v_timestamp;
            static struct _Anonymous_8
            {
                char* str;
                uint len;
            }
            _Anonymous_8 v_utf8;
            static struct _Anonymous_9
            {
                ubyte* data;
                uint data_len;
            }
            _Anonymous_9 v_doc;
            static struct _Anonymous_10
            {
                ubyte* data;
                uint data_len;
                bson_subtype_t subtype;
            }
            _Anonymous_10 v_binary;
            static struct _Anonymous_11
            {
                char* regex;
                char* options;
            }
            _Anonymous_11 v_regex;
            static struct _Anonymous_12
            {
                char* collection;
                uint collection_len;
                bson_oid_t oid;
            }
            _Anonymous_12 v_dbpointer;
            static struct _Anonymous_13
            {
                char* code;
                uint code_len;
            }
            _Anonymous_13 v_code;
            static struct _Anonymous_14
            {
                char* code;
                ubyte* scope_data;
                uint code_len;
                uint scope_len;
            }
            _Anonymous_14 v_codewscope;
            static struct _Anonymous_15
            {
                char* symbol;
                uint len;
            }
            _Anonymous_15 v_symbol;
            bson_decimal128_t v_decimal128;
        }
        _Anonymous_6 value;
    }
    struct bson_iter_t
    {
        const(ubyte)* raw;
        uint len;
        uint off;
        uint type;
        uint key;
        uint d1;
        uint d2;
        uint d3;
        uint d4;
        uint next_off;
        uint err_off;
        _bson_value_t value;
    }
    struct bson_reader_t
    {
        uint type;
    }
    struct bson_visitor_t
    {
        bool function(const(bson_iter_t)*, const(char)*, void*) visit_before;
        bool function(const(bson_iter_t)*, const(char)*, void*) visit_after;
        void function(const(bson_iter_t)*, void*) visit_corrupt;
        bool function(const(bson_iter_t)*, const(char)*, double, void*) visit_double;
        bool function(const(bson_iter_t)*, const(char)*, c_ulong, const(char)*, void*) visit_utf8;
        bool function(const(bson_iter_t)*, const(char)*, const(_bson_t)*, void*) visit_document;
        bool function(const(bson_iter_t)*, const(char)*, const(_bson_t)*, void*) visit_array;
        bool function(const(bson_iter_t)*, const(char)*, bson_subtype_t, c_ulong, const(ubyte)*, void*) visit_binary;
        bool function(const(bson_iter_t)*, const(char)*, void*) visit_undefined;
        bool function(const(bson_iter_t)*, const(char)*, const(bson_oid_t)*, void*) visit_oid;
        bool function(const(bson_iter_t)*, const(char)*, bool, void*) visit_bool;
        bool function(const(bson_iter_t)*, const(char)*, c_long, void*) visit_date_time;
        bool function(const(bson_iter_t)*, const(char)*, void*) visit_null;
        bool function(const(bson_iter_t)*, const(char)*, const(char)*, const(char)*, void*) visit_regex;
        bool function(const(bson_iter_t)*, const(char)*, c_ulong, const(char)*, const(bson_oid_t)*, void*) visit_dbpointer;
        bool function(const(bson_iter_t)*, const(char)*, c_ulong, const(char)*, void*) visit_code;
        bool function(const(bson_iter_t)*, const(char)*, c_ulong, const(char)*, void*) visit_symbol;
        bool function(const(bson_iter_t)*, const(char)*, c_ulong, const(char)*, const(_bson_t)*, void*) visit_codewscope;
        bool function(const(bson_iter_t)*, const(char)*, int, void*) visit_int32;
        bool function(const(bson_iter_t)*, const(char)*, uint, uint, void*) visit_timestamp;
        bool function(const(bson_iter_t)*, const(char)*, c_long, void*) visit_int64;
        bool function(const(bson_iter_t)*, const(char)*, void*) visit_maxkey;
        bool function(const(bson_iter_t)*, const(char)*, void*) visit_minkey;
        void function(const(bson_iter_t)*, const(char)*, uint, void*) visit_unsupported_type;
        bool function(const(bson_iter_t)*, const(char)*, const(bson_decimal128_t)*, void*) visit_decimal128;
        void*[7] padding;
    }
    alias bson_error_t = _bson_error_t;
    struct _bson_error_t
    {
        uint domain;
        uint code;
        char[504] message;
    }
    alias static_assert_test_522error_t = char[1];
    static c_ulong bson_next_power_of_two(c_ulong) @nogc nothrow;
    static bool bson_is_power_of_two(uint) @nogc nothrow;
    bool bson_utf8_validate(const(char)*, c_ulong, bool) @nogc nothrow;
    char* bson_utf8_escape_for_json(const(char)*, c_long) @nogc nothrow;
    uint bson_utf8_get_char(const(char)*) @nogc nothrow;
    const(char)* bson_utf8_next_char(const(char)*) @nogc nothrow;
    void bson_utf8_from_unichar(uint, char*, uint*) @nogc nothrow;
    void bson_value_copy(const(_bson_value_t)*, _bson_value_t*) @nogc nothrow;
    void bson_value_destroy(_bson_value_t*) @nogc nothrow;
    int bson_get_major_version() @nogc nothrow;
    int bson_get_minor_version() @nogc nothrow;
    int bson_get_micro_version() @nogc nothrow;
    const(char)* bson_get_version() @nogc nothrow;
    bool bson_check_version(int, int, int) @nogc nothrow;
    alias bson_writer_t = _bson_writer_t;
    struct _bson_writer_t;
    _bson_writer_t* bson_writer_new(ubyte**, c_ulong*, c_ulong, void* function(void*, c_ulong, void*), void*) @nogc nothrow;
    void bson_writer_destroy(_bson_writer_t*) @nogc nothrow;
    c_ulong bson_writer_get_length(_bson_writer_t*) @nogc nothrow;
    bool bson_writer_begin(_bson_writer_t*, _bson_t**) @nogc nothrow;
    void bson_writer_end(_bson_writer_t*) @nogc nothrow;
    void bson_writer_rollback(_bson_writer_t*) @nogc nothrow;
    alias key_t = int;
    alias caddr_t = char*;
    alias daddr_t = int;
    alias id_t = uint;
    alias loff_t = c_long;
    alias fsid_t = __fsid_t;
    alias u_quad_t = c_ulong;
    alias quad_t = c_long;
    alias u_long = c_ulong;
    alias u_int = uint;
    alias u_short = ushort;
    alias u_char = ubyte;
    _bson_t* bson_new() @nogc nothrow;
    bool bson_init_from_json(_bson_t*, const(char)*, c_long, _bson_error_t*) @nogc nothrow;
    bool bson_init_static(_bson_t*, const(ubyte)*, c_ulong) @nogc nothrow;
    void bson_init(_bson_t*) @nogc nothrow;
    void bson_reinit(_bson_t*) @nogc nothrow;
    _bson_t* bson_new_from_data(const(ubyte)*, c_ulong) @nogc nothrow;
    _bson_t* bson_new_from_buffer(ubyte**, c_ulong*, void* function(void*, c_ulong, void*), void*) @nogc nothrow;
    _bson_t* bson_sized_new(c_ulong) @nogc nothrow;
    _bson_t* bson_copy(const(_bson_t)*) @nogc nothrow;
    void bson_copy_to(const(_bson_t)*, _bson_t*) @nogc nothrow;
    void bson_copy_to_excluding(const(_bson_t)*, _bson_t*, const(char)*, ...) @nogc nothrow;
    void bson_copy_to_excluding_noinit(const(_bson_t)*, _bson_t*, const(char)*, ...) @nogc nothrow;
    void bson_copy_to_excluding_noinit_va(const(_bson_t)*, _bson_t*, const(char)*, va_list*) @nogc nothrow;
    void bson_destroy(_bson_t*) @nogc nothrow;
    ubyte* bson_reserve_buffer(_bson_t*, uint) @nogc nothrow;
    bool bson_steal(_bson_t*, _bson_t*) @nogc nothrow;
    ubyte* bson_destroy_with_steal(_bson_t*, bool, uint*) @nogc nothrow;
    const(ubyte)* bson_get_data(const(_bson_t)*) @nogc nothrow;
    uint bson_count_keys(const(_bson_t)*) @nogc nothrow;
    bool bson_has_field(const(_bson_t)*, const(char)*) @nogc nothrow;
    int bson_compare(const(_bson_t)*, const(_bson_t)*) @nogc nothrow;
    bool bson_equal(const(_bson_t)*, const(_bson_t)*) @nogc nothrow;
    bool bson_validate(const(_bson_t)*, bson_validate_flags_t, c_ulong*) @nogc nothrow;
    bool bson_validate_with_error(const(_bson_t)*, bson_validate_flags_t, _bson_error_t*) @nogc nothrow;
    char* bson_as_canonical_extended_json(const(_bson_t)*, c_ulong*) @nogc nothrow;
    char* bson_as_json(const(_bson_t)*, c_ulong*) @nogc nothrow;
    char* bson_as_relaxed_extended_json(const(_bson_t)*, c_ulong*) @nogc nothrow;
    char* bson_array_as_json(const(_bson_t)*, c_ulong*) @nogc nothrow;
    bool bson_append_value(_bson_t*, const(char)*, int, const(_bson_value_t)*) @nogc nothrow;
    bool bson_append_array(_bson_t*, const(char)*, int, const(_bson_t)*) @nogc nothrow;
    bool bson_append_binary(_bson_t*, const(char)*, int, bson_subtype_t, const(ubyte)*, uint) @nogc nothrow;
    bool bson_append_bool(_bson_t*, const(char)*, int, bool) @nogc nothrow;
    bool bson_append_code(_bson_t*, const(char)*, int, const(char)*) @nogc nothrow;
    bool bson_append_code_with_scope(_bson_t*, const(char)*, int, const(char)*, const(_bson_t)*) @nogc nothrow;
    bool bson_append_dbpointer(_bson_t*, const(char)*, int, const(char)*, const(bson_oid_t)*) @nogc nothrow;
    bool bson_append_double(_bson_t*, const(char)*, int, double) @nogc nothrow;
    bool bson_append_document(_bson_t*, const(char)*, int, const(_bson_t)*) @nogc nothrow;
    bool bson_append_document_begin(_bson_t*, const(char)*, int, _bson_t*) @nogc nothrow;
    bool bson_append_document_end(_bson_t*, _bson_t*) @nogc nothrow;
    bool bson_append_array_begin(_bson_t*, const(char)*, int, _bson_t*) @nogc nothrow;
    bool bson_append_array_end(_bson_t*, _bson_t*) @nogc nothrow;
    bool bson_append_int32(_bson_t*, const(char)*, int, int) @nogc nothrow;
    bool bson_append_int64(_bson_t*, const(char)*, int, c_long) @nogc nothrow;
    bool bson_append_decimal128(_bson_t*, const(char)*, int, const(bson_decimal128_t)*) @nogc nothrow;
    bool bson_append_iter(_bson_t*, const(char)*, int, const(bson_iter_t)*) @nogc nothrow;
    bool bson_append_minkey(_bson_t*, const(char)*, int) @nogc nothrow;
    bool bson_append_maxkey(_bson_t*, const(char)*, int) @nogc nothrow;
    bool bson_append_null(_bson_t*, const(char)*, int) @nogc nothrow;
    bool bson_append_oid(_bson_t*, const(char)*, int, const(bson_oid_t)*) @nogc nothrow;
    bool bson_append_regex(_bson_t*, const(char)*, int, const(char)*, const(char)*) @nogc nothrow;
    bool bson_append_regex_w_len(_bson_t*, const(char)*, int, const(char)*, int, const(char)*) @nogc nothrow;
    bool bson_append_utf8(_bson_t*, const(char)*, int, const(char)*, int) @nogc nothrow;
    bool bson_append_symbol(_bson_t*, const(char)*, int, const(char)*, int) @nogc nothrow;
    bool bson_append_time_t(_bson_t*, const(char)*, int, c_long) @nogc nothrow;
    bool bson_append_timeval(_bson_t*, const(char)*, int, timeval*) @nogc nothrow;
    bool bson_append_date_time(_bson_t*, const(char)*, int, c_long) @nogc nothrow;
    bool bson_append_now_utc(_bson_t*, const(char)*, int) @nogc nothrow;
    bool bson_append_timestamp(_bson_t*, const(char)*, int, uint, uint) @nogc nothrow;
    bool bson_append_undefined(_bson_t*, const(char)*, int) @nogc nothrow;
    bool bson_concat(_bson_t*, const(_bson_t)*) @nogc nothrow;
    pragma(mangle, "alloca") void* alloca_(c_ulong) @nogc nothrow;
    int futimes(int, const(timeval)*) @nogc nothrow;
    int lutimes(const(char)*, const(timeval)*) @nogc nothrow;
    int utimes(const(char)*, const(timeval)*) @nogc nothrow;
    int setitimer(int, const(itimerval)*, itimerval*) @nogc nothrow;
    int getitimer(int, itimerval*) @nogc nothrow;
    alias __itimer_which_t = int;
    struct itimerval
    {
        timeval it_interval;
        timeval it_value;
    }
    enum __itimer_which
    {
        ITIMER_REAL = 0,
        ITIMER_VIRTUAL = 1,
        ITIMER_PROF = 2,
    }
    enum ITIMER_REAL = __itimer_which.ITIMER_REAL;
    enum ITIMER_VIRTUAL = __itimer_which.ITIMER_VIRTUAL;
    enum ITIMER_PROF = __itimer_which.ITIMER_PROF;
    int adjtime(const(timeval)*, timeval*) @nogc nothrow;
    int settimeofday(const(timeval)*, const(timezone)*) @nogc nothrow;
    int gettimeofday(timeval*, timezone*) @nogc nothrow;
    alias __timezone_ptr_t = timezone*;
    struct timezone
    {
        int tz_minuteswest;
        int tz_dsttime;
    }
    alias suseconds_t = c_long;
    int __xmknodat(int, int, const(char)*, uint, c_ulong*) @nogc nothrow;
    int __xmknod(int, const(char)*, uint, c_ulong*) @nogc nothrow;
    int __fxstatat(int, int, const(char)*, stat*, int) @nogc nothrow;
    int __lxstat(int, const(char)*, stat*) @nogc nothrow;
    int __xstat(int, const(char)*, stat*) @nogc nothrow;
    int __fxstat(int, int, stat*) @nogc nothrow;
    int futimens(int, const(timespec)*) @nogc nothrow;
    int utimensat(int, const(char)*, const(timespec)*, int) @nogc nothrow;
    int mkfifoat(int, const(char)*, uint) @nogc nothrow;
    int mkfifo(const(char)*, uint) @nogc nothrow;
    int mknodat(int, const(char)*, uint, c_ulong) @nogc nothrow;
    int mknod(const(char)*, uint, c_ulong) @nogc nothrow;
    int mkdirat(int, const(char)*, uint) @nogc nothrow;
    int mkdir(const(char)*, uint) @nogc nothrow;
    uint umask(uint) @nogc nothrow;
    int fchmodat(int, const(char)*, uint, int) @nogc nothrow;
    int fchmod(int, uint) @nogc nothrow;
    int lchmod(const(char)*, uint) @nogc nothrow;
    int chmod(const(char)*, uint) @nogc nothrow;
    int lstat(const(char)*, stat*) @nogc nothrow;
    int fstatat(int, const(char)*, stat*, int) @nogc nothrow;
    int fstat(int, stat*) @nogc nothrow;
    pragma(mangle, "stat") int stat_(const(char)*, stat*) @nogc nothrow;
    alias nlink_t = c_ulong;
    alias ino_t = c_ulong;
    alias dev_t = c_ulong;
    static ushort __bswap_16(ushort) @nogc nothrow;
    static uint __bswap_32(uint) @nogc nothrow;
    static c_ulong __bswap_64(c_ulong) @nogc nothrow;
    enum _Anonymous_16
    {
        _PC_LINK_MAX = 0,
        _PC_MAX_CANON = 1,
        _PC_MAX_INPUT = 2,
        _PC_NAME_MAX = 3,
        _PC_PATH_MAX = 4,
        _PC_PIPE_BUF = 5,
        _PC_CHOWN_RESTRICTED = 6,
        _PC_NO_TRUNC = 7,
        _PC_VDISABLE = 8,
        _PC_SYNC_IO = 9,
        _PC_ASYNC_IO = 10,
        _PC_PRIO_IO = 11,
        _PC_SOCK_MAXBUF = 12,
        _PC_FILESIZEBITS = 13,
        _PC_REC_INCR_XFER_SIZE = 14,
        _PC_REC_MAX_XFER_SIZE = 15,
        _PC_REC_MIN_XFER_SIZE = 16,
        _PC_REC_XFER_ALIGN = 17,
        _PC_ALLOC_SIZE_MIN = 18,
        _PC_SYMLINK_MAX = 19,
        _PC_2_SYMLINKS = 20,
    }
    enum _PC_LINK_MAX = _Anonymous_16._PC_LINK_MAX;
    enum _PC_MAX_CANON = _Anonymous_16._PC_MAX_CANON;
    enum _PC_MAX_INPUT = _Anonymous_16._PC_MAX_INPUT;
    enum _PC_NAME_MAX = _Anonymous_16._PC_NAME_MAX;
    enum _PC_PATH_MAX = _Anonymous_16._PC_PATH_MAX;
    enum _PC_PIPE_BUF = _Anonymous_16._PC_PIPE_BUF;
    enum _PC_CHOWN_RESTRICTED = _Anonymous_16._PC_CHOWN_RESTRICTED;
    enum _PC_NO_TRUNC = _Anonymous_16._PC_NO_TRUNC;
    enum _PC_VDISABLE = _Anonymous_16._PC_VDISABLE;
    enum _PC_SYNC_IO = _Anonymous_16._PC_SYNC_IO;
    enum _PC_ASYNC_IO = _Anonymous_16._PC_ASYNC_IO;
    enum _PC_PRIO_IO = _Anonymous_16._PC_PRIO_IO;
    enum _PC_SOCK_MAXBUF = _Anonymous_16._PC_SOCK_MAXBUF;
    enum _PC_FILESIZEBITS = _Anonymous_16._PC_FILESIZEBITS;
    enum _PC_REC_INCR_XFER_SIZE = _Anonymous_16._PC_REC_INCR_XFER_SIZE;
    enum _PC_REC_MAX_XFER_SIZE = _Anonymous_16._PC_REC_MAX_XFER_SIZE;
    enum _PC_REC_MIN_XFER_SIZE = _Anonymous_16._PC_REC_MIN_XFER_SIZE;
    enum _PC_REC_XFER_ALIGN = _Anonymous_16._PC_REC_XFER_ALIGN;
    enum _PC_ALLOC_SIZE_MIN = _Anonymous_16._PC_ALLOC_SIZE_MIN;
    enum _PC_SYMLINK_MAX = _Anonymous_16._PC_SYMLINK_MAX;
    enum _PC_2_SYMLINKS = _Anonymous_16._PC_2_SYMLINKS;
    int pselect(int, fd_set*, fd_set*, fd_set*, const(timespec)*, const(__sigset_t)*) @nogc nothrow;
    int select(int, fd_set*, fd_set*, fd_set*, timeval*) @nogc nothrow;
    alias fd_mask = c_long;
    struct fd_set
    {
        c_long[16] __fds_bits;
    }
    alias __fd_mask = c_long;
    enum _Anonymous_17
    {
        _SC_ARG_MAX = 0,
        _SC_CHILD_MAX = 1,
        _SC_CLK_TCK = 2,
        _SC_NGROUPS_MAX = 3,
        _SC_OPEN_MAX = 4,
        _SC_STREAM_MAX = 5,
        _SC_TZNAME_MAX = 6,
        _SC_JOB_CONTROL = 7,
        _SC_SAVED_IDS = 8,
        _SC_REALTIME_SIGNALS = 9,
        _SC_PRIORITY_SCHEDULING = 10,
        _SC_TIMERS = 11,
        _SC_ASYNCHRONOUS_IO = 12,
        _SC_PRIORITIZED_IO = 13,
        _SC_SYNCHRONIZED_IO = 14,
        _SC_FSYNC = 15,
        _SC_MAPPED_FILES = 16,
        _SC_MEMLOCK = 17,
        _SC_MEMLOCK_RANGE = 18,
        _SC_MEMORY_PROTECTION = 19,
        _SC_MESSAGE_PASSING = 20,
        _SC_SEMAPHORES = 21,
        _SC_SHARED_MEMORY_OBJECTS = 22,
        _SC_AIO_LISTIO_MAX = 23,
        _SC_AIO_MAX = 24,
        _SC_AIO_PRIO_DELTA_MAX = 25,
        _SC_DELAYTIMER_MAX = 26,
        _SC_MQ_OPEN_MAX = 27,
        _SC_MQ_PRIO_MAX = 28,
        _SC_VERSION = 29,
        _SC_PAGESIZE = 30,
        _SC_RTSIG_MAX = 31,
        _SC_SEM_NSEMS_MAX = 32,
        _SC_SEM_VALUE_MAX = 33,
        _SC_SIGQUEUE_MAX = 34,
        _SC_TIMER_MAX = 35,
        _SC_BC_BASE_MAX = 36,
        _SC_BC_DIM_MAX = 37,
        _SC_BC_SCALE_MAX = 38,
        _SC_BC_STRING_MAX = 39,
        _SC_COLL_WEIGHTS_MAX = 40,
        _SC_EQUIV_CLASS_MAX = 41,
        _SC_EXPR_NEST_MAX = 42,
        _SC_LINE_MAX = 43,
        _SC_RE_DUP_MAX = 44,
        _SC_CHARCLASS_NAME_MAX = 45,
        _SC_2_VERSION = 46,
        _SC_2_C_BIND = 47,
        _SC_2_C_DEV = 48,
        _SC_2_FORT_DEV = 49,
        _SC_2_FORT_RUN = 50,
        _SC_2_SW_DEV = 51,
        _SC_2_LOCALEDEF = 52,
        _SC_PII = 53,
        _SC_PII_XTI = 54,
        _SC_PII_SOCKET = 55,
        _SC_PII_INTERNET = 56,
        _SC_PII_OSI = 57,
        _SC_POLL = 58,
        _SC_SELECT = 59,
        _SC_UIO_MAXIOV = 60,
        _SC_IOV_MAX = 60,
        _SC_PII_INTERNET_STREAM = 61,
        _SC_PII_INTERNET_DGRAM = 62,
        _SC_PII_OSI_COTS = 63,
        _SC_PII_OSI_CLTS = 64,
        _SC_PII_OSI_M = 65,
        _SC_T_IOV_MAX = 66,
        _SC_THREADS = 67,
        _SC_THREAD_SAFE_FUNCTIONS = 68,
        _SC_GETGR_R_SIZE_MAX = 69,
        _SC_GETPW_R_SIZE_MAX = 70,
        _SC_LOGIN_NAME_MAX = 71,
        _SC_TTY_NAME_MAX = 72,
        _SC_THREAD_DESTRUCTOR_ITERATIONS = 73,
        _SC_THREAD_KEYS_MAX = 74,
        _SC_THREAD_STACK_MIN = 75,
        _SC_THREAD_THREADS_MAX = 76,
        _SC_THREAD_ATTR_STACKADDR = 77,
        _SC_THREAD_ATTR_STACKSIZE = 78,
        _SC_THREAD_PRIORITY_SCHEDULING = 79,
        _SC_THREAD_PRIO_INHERIT = 80,
        _SC_THREAD_PRIO_PROTECT = 81,
        _SC_THREAD_PROCESS_SHARED = 82,
        _SC_NPROCESSORS_CONF = 83,
        _SC_NPROCESSORS_ONLN = 84,
        _SC_PHYS_PAGES = 85,
        _SC_AVPHYS_PAGES = 86,
        _SC_ATEXIT_MAX = 87,
        _SC_PASS_MAX = 88,
        _SC_XOPEN_VERSION = 89,
        _SC_XOPEN_XCU_VERSION = 90,
        _SC_XOPEN_UNIX = 91,
        _SC_XOPEN_CRYPT = 92,
        _SC_XOPEN_ENH_I18N = 93,
        _SC_XOPEN_SHM = 94,
        _SC_2_CHAR_TERM = 95,
        _SC_2_C_VERSION = 96,
        _SC_2_UPE = 97,
        _SC_XOPEN_XPG2 = 98,
        _SC_XOPEN_XPG3 = 99,
        _SC_XOPEN_XPG4 = 100,
        _SC_CHAR_BIT = 101,
        _SC_CHAR_MAX = 102,
        _SC_CHAR_MIN = 103,
        _SC_INT_MAX = 104,
        _SC_INT_MIN = 105,
        _SC_LONG_BIT = 106,
        _SC_WORD_BIT = 107,
        _SC_MB_LEN_MAX = 108,
        _SC_NZERO = 109,
        _SC_SSIZE_MAX = 110,
        _SC_SCHAR_MAX = 111,
        _SC_SCHAR_MIN = 112,
        _SC_SHRT_MAX = 113,
        _SC_SHRT_MIN = 114,
        _SC_UCHAR_MAX = 115,
        _SC_UINT_MAX = 116,
        _SC_ULONG_MAX = 117,
        _SC_USHRT_MAX = 118,
        _SC_NL_ARGMAX = 119,
        _SC_NL_LANGMAX = 120,
        _SC_NL_MSGMAX = 121,
        _SC_NL_NMAX = 122,
        _SC_NL_SETMAX = 123,
        _SC_NL_TEXTMAX = 124,
        _SC_XBS5_ILP32_OFF32 = 125,
        _SC_XBS5_ILP32_OFFBIG = 126,
        _SC_XBS5_LP64_OFF64 = 127,
        _SC_XBS5_LPBIG_OFFBIG = 128,
        _SC_XOPEN_LEGACY = 129,
        _SC_XOPEN_REALTIME = 130,
        _SC_XOPEN_REALTIME_THREADS = 131,
        _SC_ADVISORY_INFO = 132,
        _SC_BARRIERS = 133,
        _SC_BASE = 134,
        _SC_C_LANG_SUPPORT = 135,
        _SC_C_LANG_SUPPORT_R = 136,
        _SC_CLOCK_SELECTION = 137,
        _SC_CPUTIME = 138,
        _SC_THREAD_CPUTIME = 139,
        _SC_DEVICE_IO = 140,
        _SC_DEVICE_SPECIFIC = 141,
        _SC_DEVICE_SPECIFIC_R = 142,
        _SC_FD_MGMT = 143,
        _SC_FIFO = 144,
        _SC_PIPE = 145,
        _SC_FILE_ATTRIBUTES = 146,
        _SC_FILE_LOCKING = 147,
        _SC_FILE_SYSTEM = 148,
        _SC_MONOTONIC_CLOCK = 149,
        _SC_MULTI_PROCESS = 150,
        _SC_SINGLE_PROCESS = 151,
        _SC_NETWORKING = 152,
        _SC_READER_WRITER_LOCKS = 153,
        _SC_SPIN_LOCKS = 154,
        _SC_REGEXP = 155,
        _SC_REGEX_VERSION = 156,
        _SC_SHELL = 157,
        _SC_SIGNALS = 158,
        _SC_SPAWN = 159,
        _SC_SPORADIC_SERVER = 160,
        _SC_THREAD_SPORADIC_SERVER = 161,
        _SC_SYSTEM_DATABASE = 162,
        _SC_SYSTEM_DATABASE_R = 163,
        _SC_TIMEOUTS = 164,
        _SC_TYPED_MEMORY_OBJECTS = 165,
        _SC_USER_GROUPS = 166,
        _SC_USER_GROUPS_R = 167,
        _SC_2_PBS = 168,
        _SC_2_PBS_ACCOUNTING = 169,
        _SC_2_PBS_LOCATE = 170,
        _SC_2_PBS_MESSAGE = 171,
        _SC_2_PBS_TRACK = 172,
        _SC_SYMLOOP_MAX = 173,
        _SC_STREAMS = 174,
        _SC_2_PBS_CHECKPOINT = 175,
        _SC_V6_ILP32_OFF32 = 176,
        _SC_V6_ILP32_OFFBIG = 177,
        _SC_V6_LP64_OFF64 = 178,
        _SC_V6_LPBIG_OFFBIG = 179,
        _SC_HOST_NAME_MAX = 180,
        _SC_TRACE = 181,
        _SC_TRACE_EVENT_FILTER = 182,
        _SC_TRACE_INHERIT = 183,
        _SC_TRACE_LOG = 184,
        _SC_LEVEL1_ICACHE_SIZE = 185,
        _SC_LEVEL1_ICACHE_ASSOC = 186,
        _SC_LEVEL1_ICACHE_LINESIZE = 187,
        _SC_LEVEL1_DCACHE_SIZE = 188,
        _SC_LEVEL1_DCACHE_ASSOC = 189,
        _SC_LEVEL1_DCACHE_LINESIZE = 190,
        _SC_LEVEL2_CACHE_SIZE = 191,
        _SC_LEVEL2_CACHE_ASSOC = 192,
        _SC_LEVEL2_CACHE_LINESIZE = 193,
        _SC_LEVEL3_CACHE_SIZE = 194,
        _SC_LEVEL3_CACHE_ASSOC = 195,
        _SC_LEVEL3_CACHE_LINESIZE = 196,
        _SC_LEVEL4_CACHE_SIZE = 197,
        _SC_LEVEL4_CACHE_ASSOC = 198,
        _SC_LEVEL4_CACHE_LINESIZE = 199,
        _SC_IPV6 = 235,
        _SC_RAW_SOCKETS = 236,
        _SC_V7_ILP32_OFF32 = 237,
        _SC_V7_ILP32_OFFBIG = 238,
        _SC_V7_LP64_OFF64 = 239,
        _SC_V7_LPBIG_OFFBIG = 240,
        _SC_SS_REPL_MAX = 241,
        _SC_TRACE_EVENT_NAME_MAX = 242,
        _SC_TRACE_NAME_MAX = 243,
        _SC_TRACE_SYS_MAX = 244,
        _SC_TRACE_USER_EVENT_MAX = 245,
        _SC_XOPEN_STREAMS = 246,
        _SC_THREAD_ROBUST_PRIO_INHERIT = 247,
        _SC_THREAD_ROBUST_PRIO_PROTECT = 248,
    }
    enum _SC_ARG_MAX = _Anonymous_17._SC_ARG_MAX;
    enum _SC_CHILD_MAX = _Anonymous_17._SC_CHILD_MAX;
    enum _SC_CLK_TCK = _Anonymous_17._SC_CLK_TCK;
    enum _SC_NGROUPS_MAX = _Anonymous_17._SC_NGROUPS_MAX;
    enum _SC_OPEN_MAX = _Anonymous_17._SC_OPEN_MAX;
    enum _SC_STREAM_MAX = _Anonymous_17._SC_STREAM_MAX;
    enum _SC_TZNAME_MAX = _Anonymous_17._SC_TZNAME_MAX;
    enum _SC_JOB_CONTROL = _Anonymous_17._SC_JOB_CONTROL;
    enum _SC_SAVED_IDS = _Anonymous_17._SC_SAVED_IDS;
    enum _SC_REALTIME_SIGNALS = _Anonymous_17._SC_REALTIME_SIGNALS;
    enum _SC_PRIORITY_SCHEDULING = _Anonymous_17._SC_PRIORITY_SCHEDULING;
    enum _SC_TIMERS = _Anonymous_17._SC_TIMERS;
    enum _SC_ASYNCHRONOUS_IO = _Anonymous_17._SC_ASYNCHRONOUS_IO;
    enum _SC_PRIORITIZED_IO = _Anonymous_17._SC_PRIORITIZED_IO;
    enum _SC_SYNCHRONIZED_IO = _Anonymous_17._SC_SYNCHRONIZED_IO;
    enum _SC_FSYNC = _Anonymous_17._SC_FSYNC;
    enum _SC_MAPPED_FILES = _Anonymous_17._SC_MAPPED_FILES;
    enum _SC_MEMLOCK = _Anonymous_17._SC_MEMLOCK;
    enum _SC_MEMLOCK_RANGE = _Anonymous_17._SC_MEMLOCK_RANGE;
    enum _SC_MEMORY_PROTECTION = _Anonymous_17._SC_MEMORY_PROTECTION;
    enum _SC_MESSAGE_PASSING = _Anonymous_17._SC_MESSAGE_PASSING;
    enum _SC_SEMAPHORES = _Anonymous_17._SC_SEMAPHORES;
    enum _SC_SHARED_MEMORY_OBJECTS = _Anonymous_17._SC_SHARED_MEMORY_OBJECTS;
    enum _SC_AIO_LISTIO_MAX = _Anonymous_17._SC_AIO_LISTIO_MAX;
    enum _SC_AIO_MAX = _Anonymous_17._SC_AIO_MAX;
    enum _SC_AIO_PRIO_DELTA_MAX = _Anonymous_17._SC_AIO_PRIO_DELTA_MAX;
    enum _SC_DELAYTIMER_MAX = _Anonymous_17._SC_DELAYTIMER_MAX;
    enum _SC_MQ_OPEN_MAX = _Anonymous_17._SC_MQ_OPEN_MAX;
    enum _SC_MQ_PRIO_MAX = _Anonymous_17._SC_MQ_PRIO_MAX;
    enum _SC_VERSION = _Anonymous_17._SC_VERSION;
    enum _SC_PAGESIZE = _Anonymous_17._SC_PAGESIZE;
    enum _SC_RTSIG_MAX = _Anonymous_17._SC_RTSIG_MAX;
    enum _SC_SEM_NSEMS_MAX = _Anonymous_17._SC_SEM_NSEMS_MAX;
    enum _SC_SEM_VALUE_MAX = _Anonymous_17._SC_SEM_VALUE_MAX;
    enum _SC_SIGQUEUE_MAX = _Anonymous_17._SC_SIGQUEUE_MAX;
    enum _SC_TIMER_MAX = _Anonymous_17._SC_TIMER_MAX;
    enum _SC_BC_BASE_MAX = _Anonymous_17._SC_BC_BASE_MAX;
    enum _SC_BC_DIM_MAX = _Anonymous_17._SC_BC_DIM_MAX;
    enum _SC_BC_SCALE_MAX = _Anonymous_17._SC_BC_SCALE_MAX;
    enum _SC_BC_STRING_MAX = _Anonymous_17._SC_BC_STRING_MAX;
    enum _SC_COLL_WEIGHTS_MAX = _Anonymous_17._SC_COLL_WEIGHTS_MAX;
    enum _SC_EQUIV_CLASS_MAX = _Anonymous_17._SC_EQUIV_CLASS_MAX;
    enum _SC_EXPR_NEST_MAX = _Anonymous_17._SC_EXPR_NEST_MAX;
    enum _SC_LINE_MAX = _Anonymous_17._SC_LINE_MAX;
    enum _SC_RE_DUP_MAX = _Anonymous_17._SC_RE_DUP_MAX;
    enum _SC_CHARCLASS_NAME_MAX = _Anonymous_17._SC_CHARCLASS_NAME_MAX;
    enum _SC_2_VERSION = _Anonymous_17._SC_2_VERSION;
    enum _SC_2_C_BIND = _Anonymous_17._SC_2_C_BIND;
    enum _SC_2_C_DEV = _Anonymous_17._SC_2_C_DEV;
    enum _SC_2_FORT_DEV = _Anonymous_17._SC_2_FORT_DEV;
    enum _SC_2_FORT_RUN = _Anonymous_17._SC_2_FORT_RUN;
    enum _SC_2_SW_DEV = _Anonymous_17._SC_2_SW_DEV;
    enum _SC_2_LOCALEDEF = _Anonymous_17._SC_2_LOCALEDEF;
    enum _SC_PII = _Anonymous_17._SC_PII;
    enum _SC_PII_XTI = _Anonymous_17._SC_PII_XTI;
    enum _SC_PII_SOCKET = _Anonymous_17._SC_PII_SOCKET;
    enum _SC_PII_INTERNET = _Anonymous_17._SC_PII_INTERNET;
    enum _SC_PII_OSI = _Anonymous_17._SC_PII_OSI;
    enum _SC_POLL = _Anonymous_17._SC_POLL;
    enum _SC_SELECT = _Anonymous_17._SC_SELECT;
    enum _SC_UIO_MAXIOV = _Anonymous_17._SC_UIO_MAXIOV;
    enum _SC_IOV_MAX = _Anonymous_17._SC_IOV_MAX;
    enum _SC_PII_INTERNET_STREAM = _Anonymous_17._SC_PII_INTERNET_STREAM;
    enum _SC_PII_INTERNET_DGRAM = _Anonymous_17._SC_PII_INTERNET_DGRAM;
    enum _SC_PII_OSI_COTS = _Anonymous_17._SC_PII_OSI_COTS;
    enum _SC_PII_OSI_CLTS = _Anonymous_17._SC_PII_OSI_CLTS;
    enum _SC_PII_OSI_M = _Anonymous_17._SC_PII_OSI_M;
    enum _SC_T_IOV_MAX = _Anonymous_17._SC_T_IOV_MAX;
    enum _SC_THREADS = _Anonymous_17._SC_THREADS;
    enum _SC_THREAD_SAFE_FUNCTIONS = _Anonymous_17._SC_THREAD_SAFE_FUNCTIONS;
    enum _SC_GETGR_R_SIZE_MAX = _Anonymous_17._SC_GETGR_R_SIZE_MAX;
    enum _SC_GETPW_R_SIZE_MAX = _Anonymous_17._SC_GETPW_R_SIZE_MAX;
    enum _SC_LOGIN_NAME_MAX = _Anonymous_17._SC_LOGIN_NAME_MAX;
    enum _SC_TTY_NAME_MAX = _Anonymous_17._SC_TTY_NAME_MAX;
    enum _SC_THREAD_DESTRUCTOR_ITERATIONS = _Anonymous_17._SC_THREAD_DESTRUCTOR_ITERATIONS;
    enum _SC_THREAD_KEYS_MAX = _Anonymous_17._SC_THREAD_KEYS_MAX;
    enum _SC_THREAD_STACK_MIN = _Anonymous_17._SC_THREAD_STACK_MIN;
    enum _SC_THREAD_THREADS_MAX = _Anonymous_17._SC_THREAD_THREADS_MAX;
    enum _SC_THREAD_ATTR_STACKADDR = _Anonymous_17._SC_THREAD_ATTR_STACKADDR;
    enum _SC_THREAD_ATTR_STACKSIZE = _Anonymous_17._SC_THREAD_ATTR_STACKSIZE;
    enum _SC_THREAD_PRIORITY_SCHEDULING = _Anonymous_17._SC_THREAD_PRIORITY_SCHEDULING;
    enum _SC_THREAD_PRIO_INHERIT = _Anonymous_17._SC_THREAD_PRIO_INHERIT;
    enum _SC_THREAD_PRIO_PROTECT = _Anonymous_17._SC_THREAD_PRIO_PROTECT;
    enum _SC_THREAD_PROCESS_SHARED = _Anonymous_17._SC_THREAD_PROCESS_SHARED;
    enum _SC_NPROCESSORS_CONF = _Anonymous_17._SC_NPROCESSORS_CONF;
    enum _SC_NPROCESSORS_ONLN = _Anonymous_17._SC_NPROCESSORS_ONLN;
    enum _SC_PHYS_PAGES = _Anonymous_17._SC_PHYS_PAGES;
    enum _SC_AVPHYS_PAGES = _Anonymous_17._SC_AVPHYS_PAGES;
    enum _SC_ATEXIT_MAX = _Anonymous_17._SC_ATEXIT_MAX;
    enum _SC_PASS_MAX = _Anonymous_17._SC_PASS_MAX;
    enum _SC_XOPEN_VERSION = _Anonymous_17._SC_XOPEN_VERSION;
    enum _SC_XOPEN_XCU_VERSION = _Anonymous_17._SC_XOPEN_XCU_VERSION;
    enum _SC_XOPEN_UNIX = _Anonymous_17._SC_XOPEN_UNIX;
    enum _SC_XOPEN_CRYPT = _Anonymous_17._SC_XOPEN_CRYPT;
    enum _SC_XOPEN_ENH_I18N = _Anonymous_17._SC_XOPEN_ENH_I18N;
    enum _SC_XOPEN_SHM = _Anonymous_17._SC_XOPEN_SHM;
    enum _SC_2_CHAR_TERM = _Anonymous_17._SC_2_CHAR_TERM;
    enum _SC_2_C_VERSION = _Anonymous_17._SC_2_C_VERSION;
    enum _SC_2_UPE = _Anonymous_17._SC_2_UPE;
    enum _SC_XOPEN_XPG2 = _Anonymous_17._SC_XOPEN_XPG2;
    enum _SC_XOPEN_XPG3 = _Anonymous_17._SC_XOPEN_XPG3;
    enum _SC_XOPEN_XPG4 = _Anonymous_17._SC_XOPEN_XPG4;
    enum _SC_CHAR_BIT = _Anonymous_17._SC_CHAR_BIT;
    enum _SC_CHAR_MAX = _Anonymous_17._SC_CHAR_MAX;
    enum _SC_CHAR_MIN = _Anonymous_17._SC_CHAR_MIN;
    enum _SC_INT_MAX = _Anonymous_17._SC_INT_MAX;
    enum _SC_INT_MIN = _Anonymous_17._SC_INT_MIN;
    enum _SC_LONG_BIT = _Anonymous_17._SC_LONG_BIT;
    enum _SC_WORD_BIT = _Anonymous_17._SC_WORD_BIT;
    enum _SC_MB_LEN_MAX = _Anonymous_17._SC_MB_LEN_MAX;
    enum _SC_NZERO = _Anonymous_17._SC_NZERO;
    enum _SC_SSIZE_MAX = _Anonymous_17._SC_SSIZE_MAX;
    enum _SC_SCHAR_MAX = _Anonymous_17._SC_SCHAR_MAX;
    enum _SC_SCHAR_MIN = _Anonymous_17._SC_SCHAR_MIN;
    enum _SC_SHRT_MAX = _Anonymous_17._SC_SHRT_MAX;
    enum _SC_SHRT_MIN = _Anonymous_17._SC_SHRT_MIN;
    enum _SC_UCHAR_MAX = _Anonymous_17._SC_UCHAR_MAX;
    enum _SC_UINT_MAX = _Anonymous_17._SC_UINT_MAX;
    enum _SC_ULONG_MAX = _Anonymous_17._SC_ULONG_MAX;
    enum _SC_USHRT_MAX = _Anonymous_17._SC_USHRT_MAX;
    enum _SC_NL_ARGMAX = _Anonymous_17._SC_NL_ARGMAX;
    enum _SC_NL_LANGMAX = _Anonymous_17._SC_NL_LANGMAX;
    enum _SC_NL_MSGMAX = _Anonymous_17._SC_NL_MSGMAX;
    enum _SC_NL_NMAX = _Anonymous_17._SC_NL_NMAX;
    enum _SC_NL_SETMAX = _Anonymous_17._SC_NL_SETMAX;
    enum _SC_NL_TEXTMAX = _Anonymous_17._SC_NL_TEXTMAX;
    enum _SC_XBS5_ILP32_OFF32 = _Anonymous_17._SC_XBS5_ILP32_OFF32;
    enum _SC_XBS5_ILP32_OFFBIG = _Anonymous_17._SC_XBS5_ILP32_OFFBIG;
    enum _SC_XBS5_LP64_OFF64 = _Anonymous_17._SC_XBS5_LP64_OFF64;
    enum _SC_XBS5_LPBIG_OFFBIG = _Anonymous_17._SC_XBS5_LPBIG_OFFBIG;
    enum _SC_XOPEN_LEGACY = _Anonymous_17._SC_XOPEN_LEGACY;
    enum _SC_XOPEN_REALTIME = _Anonymous_17._SC_XOPEN_REALTIME;
    enum _SC_XOPEN_REALTIME_THREADS = _Anonymous_17._SC_XOPEN_REALTIME_THREADS;
    enum _SC_ADVISORY_INFO = _Anonymous_17._SC_ADVISORY_INFO;
    enum _SC_BARRIERS = _Anonymous_17._SC_BARRIERS;
    enum _SC_BASE = _Anonymous_17._SC_BASE;
    enum _SC_C_LANG_SUPPORT = _Anonymous_17._SC_C_LANG_SUPPORT;
    enum _SC_C_LANG_SUPPORT_R = _Anonymous_17._SC_C_LANG_SUPPORT_R;
    enum _SC_CLOCK_SELECTION = _Anonymous_17._SC_CLOCK_SELECTION;
    enum _SC_CPUTIME = _Anonymous_17._SC_CPUTIME;
    enum _SC_THREAD_CPUTIME = _Anonymous_17._SC_THREAD_CPUTIME;
    enum _SC_DEVICE_IO = _Anonymous_17._SC_DEVICE_IO;
    enum _SC_DEVICE_SPECIFIC = _Anonymous_17._SC_DEVICE_SPECIFIC;
    enum _SC_DEVICE_SPECIFIC_R = _Anonymous_17._SC_DEVICE_SPECIFIC_R;
    enum _SC_FD_MGMT = _Anonymous_17._SC_FD_MGMT;
    enum _SC_FIFO = _Anonymous_17._SC_FIFO;
    enum _SC_PIPE = _Anonymous_17._SC_PIPE;
    enum _SC_FILE_ATTRIBUTES = _Anonymous_17._SC_FILE_ATTRIBUTES;
    enum _SC_FILE_LOCKING = _Anonymous_17._SC_FILE_LOCKING;
    enum _SC_FILE_SYSTEM = _Anonymous_17._SC_FILE_SYSTEM;
    enum _SC_MONOTONIC_CLOCK = _Anonymous_17._SC_MONOTONIC_CLOCK;
    enum _SC_MULTI_PROCESS = _Anonymous_17._SC_MULTI_PROCESS;
    enum _SC_SINGLE_PROCESS = _Anonymous_17._SC_SINGLE_PROCESS;
    enum _SC_NETWORKING = _Anonymous_17._SC_NETWORKING;
    enum _SC_READER_WRITER_LOCKS = _Anonymous_17._SC_READER_WRITER_LOCKS;
    enum _SC_SPIN_LOCKS = _Anonymous_17._SC_SPIN_LOCKS;
    enum _SC_REGEXP = _Anonymous_17._SC_REGEXP;
    enum _SC_REGEX_VERSION = _Anonymous_17._SC_REGEX_VERSION;
    enum _SC_SHELL = _Anonymous_17._SC_SHELL;
    enum _SC_SIGNALS = _Anonymous_17._SC_SIGNALS;
    enum _SC_SPAWN = _Anonymous_17._SC_SPAWN;
    enum _SC_SPORADIC_SERVER = _Anonymous_17._SC_SPORADIC_SERVER;
    enum _SC_THREAD_SPORADIC_SERVER = _Anonymous_17._SC_THREAD_SPORADIC_SERVER;
    enum _SC_SYSTEM_DATABASE = _Anonymous_17._SC_SYSTEM_DATABASE;
    enum _SC_SYSTEM_DATABASE_R = _Anonymous_17._SC_SYSTEM_DATABASE_R;
    enum _SC_TIMEOUTS = _Anonymous_17._SC_TIMEOUTS;
    enum _SC_TYPED_MEMORY_OBJECTS = _Anonymous_17._SC_TYPED_MEMORY_OBJECTS;
    enum _SC_USER_GROUPS = _Anonymous_17._SC_USER_GROUPS;
    enum _SC_USER_GROUPS_R = _Anonymous_17._SC_USER_GROUPS_R;
    enum _SC_2_PBS = _Anonymous_17._SC_2_PBS;
    enum _SC_2_PBS_ACCOUNTING = _Anonymous_17._SC_2_PBS_ACCOUNTING;
    enum _SC_2_PBS_LOCATE = _Anonymous_17._SC_2_PBS_LOCATE;
    enum _SC_2_PBS_MESSAGE = _Anonymous_17._SC_2_PBS_MESSAGE;
    enum _SC_2_PBS_TRACK = _Anonymous_17._SC_2_PBS_TRACK;
    enum _SC_SYMLOOP_MAX = _Anonymous_17._SC_SYMLOOP_MAX;
    enum _SC_STREAMS = _Anonymous_17._SC_STREAMS;
    enum _SC_2_PBS_CHECKPOINT = _Anonymous_17._SC_2_PBS_CHECKPOINT;
    enum _SC_V6_ILP32_OFF32 = _Anonymous_17._SC_V6_ILP32_OFF32;
    enum _SC_V6_ILP32_OFFBIG = _Anonymous_17._SC_V6_ILP32_OFFBIG;
    enum _SC_V6_LP64_OFF64 = _Anonymous_17._SC_V6_LP64_OFF64;
    enum _SC_V6_LPBIG_OFFBIG = _Anonymous_17._SC_V6_LPBIG_OFFBIG;
    enum _SC_HOST_NAME_MAX = _Anonymous_17._SC_HOST_NAME_MAX;
    enum _SC_TRACE = _Anonymous_17._SC_TRACE;
    enum _SC_TRACE_EVENT_FILTER = _Anonymous_17._SC_TRACE_EVENT_FILTER;
    enum _SC_TRACE_INHERIT = _Anonymous_17._SC_TRACE_INHERIT;
    enum _SC_TRACE_LOG = _Anonymous_17._SC_TRACE_LOG;
    enum _SC_LEVEL1_ICACHE_SIZE = _Anonymous_17._SC_LEVEL1_ICACHE_SIZE;
    enum _SC_LEVEL1_ICACHE_ASSOC = _Anonymous_17._SC_LEVEL1_ICACHE_ASSOC;
    enum _SC_LEVEL1_ICACHE_LINESIZE = _Anonymous_17._SC_LEVEL1_ICACHE_LINESIZE;
    enum _SC_LEVEL1_DCACHE_SIZE = _Anonymous_17._SC_LEVEL1_DCACHE_SIZE;
    enum _SC_LEVEL1_DCACHE_ASSOC = _Anonymous_17._SC_LEVEL1_DCACHE_ASSOC;
    enum _SC_LEVEL1_DCACHE_LINESIZE = _Anonymous_17._SC_LEVEL1_DCACHE_LINESIZE;
    enum _SC_LEVEL2_CACHE_SIZE = _Anonymous_17._SC_LEVEL2_CACHE_SIZE;
    enum _SC_LEVEL2_CACHE_ASSOC = _Anonymous_17._SC_LEVEL2_CACHE_ASSOC;
    enum _SC_LEVEL2_CACHE_LINESIZE = _Anonymous_17._SC_LEVEL2_CACHE_LINESIZE;
    enum _SC_LEVEL3_CACHE_SIZE = _Anonymous_17._SC_LEVEL3_CACHE_SIZE;
    enum _SC_LEVEL3_CACHE_ASSOC = _Anonymous_17._SC_LEVEL3_CACHE_ASSOC;
    enum _SC_LEVEL3_CACHE_LINESIZE = _Anonymous_17._SC_LEVEL3_CACHE_LINESIZE;
    enum _SC_LEVEL4_CACHE_SIZE = _Anonymous_17._SC_LEVEL4_CACHE_SIZE;
    enum _SC_LEVEL4_CACHE_ASSOC = _Anonymous_17._SC_LEVEL4_CACHE_ASSOC;
    enum _SC_LEVEL4_CACHE_LINESIZE = _Anonymous_17._SC_LEVEL4_CACHE_LINESIZE;
    enum _SC_IPV6 = _Anonymous_17._SC_IPV6;
    enum _SC_RAW_SOCKETS = _Anonymous_17._SC_RAW_SOCKETS;
    enum _SC_V7_ILP32_OFF32 = _Anonymous_17._SC_V7_ILP32_OFF32;
    enum _SC_V7_ILP32_OFFBIG = _Anonymous_17._SC_V7_ILP32_OFFBIG;
    enum _SC_V7_LP64_OFF64 = _Anonymous_17._SC_V7_LP64_OFF64;
    enum _SC_V7_LPBIG_OFFBIG = _Anonymous_17._SC_V7_LPBIG_OFFBIG;
    enum _SC_SS_REPL_MAX = _Anonymous_17._SC_SS_REPL_MAX;
    enum _SC_TRACE_EVENT_NAME_MAX = _Anonymous_17._SC_TRACE_EVENT_NAME_MAX;
    enum _SC_TRACE_NAME_MAX = _Anonymous_17._SC_TRACE_NAME_MAX;
    enum _SC_TRACE_SYS_MAX = _Anonymous_17._SC_TRACE_SYS_MAX;
    enum _SC_TRACE_USER_EVENT_MAX = _Anonymous_17._SC_TRACE_USER_EVENT_MAX;
    enum _SC_XOPEN_STREAMS = _Anonymous_17._SC_XOPEN_STREAMS;
    enum _SC_THREAD_ROBUST_PRIO_INHERIT = _Anonymous_17._SC_THREAD_ROBUST_PRIO_INHERIT;
    enum _SC_THREAD_ROBUST_PRIO_PROTECT = _Anonymous_17._SC_THREAD_ROBUST_PRIO_PROTECT;
    int strncasecmp_l(const(char)*, const(char)*, c_ulong, __locale_struct*) @nogc nothrow;
    int strcasecmp_l(const(char)*, const(char)*, __locale_struct*) @nogc nothrow;
    int strncasecmp(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    int strcasecmp(const(char)*, const(char)*) @nogc nothrow;
    int ffsll(long) @nogc nothrow;
    int ffsl(c_long) @nogc nothrow;
    int ffs(int) @nogc nothrow;
    char* rindex(const(char)*, int) @nogc nothrow;
    char* index(const(char)*, int) @nogc nothrow;
    void bzero(void*, c_ulong) @nogc nothrow;
    void bcopy(const(void)*, void*, c_ulong) @nogc nothrow;
    int bcmp(const(void)*, const(void)*, c_ulong) @nogc nothrow;
    char* stpncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* __stpncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* stpcpy(char*, const(char)*) @nogc nothrow;
    char* __stpcpy(char*, const(char)*) @nogc nothrow;
    char* strsignal(int) @nogc nothrow;
    char* strsep(char**, const(char)*) @nogc nothrow;
    void explicit_bzero(void*, c_ulong) @nogc nothrow;
    char* strerror_l(int, __locale_struct*) @nogc nothrow;
    int strerror_r(int, char*, c_ulong) @nogc nothrow;
    char* strerror(int) @nogc nothrow;
    c_ulong strnlen(const(char)*, c_ulong) @nogc nothrow;
    c_ulong strlen(const(char)*) @nogc nothrow;
    char* strtok_r(char*, const(char)*, char**) @nogc nothrow;
    char* __strtok_r(char*, const(char)*, char**) @nogc nothrow;
    char* strtok(char*, const(char)*) @nogc nothrow;
    char* strstr(const(char)*, const(char)*) @nogc nothrow;
    char* strpbrk(const(char)*, const(char)*) @nogc nothrow;
    c_ulong strspn(const(char)*, const(char)*) @nogc nothrow;
    c_ulong strcspn(const(char)*, const(char)*) @nogc nothrow;
    char* strrchr(const(char)*, int) @nogc nothrow;
    char* strchr(const(char)*, int) @nogc nothrow;
    char* strndup(const(char)*, c_ulong) @nogc nothrow;
    char* strdup(const(char)*) @nogc nothrow;
    enum _Anonymous_18
    {
        _CS_PATH = 0,
        _CS_V6_WIDTH_RESTRICTED_ENVS = 1,
        _CS_GNU_LIBC_VERSION = 2,
        _CS_GNU_LIBPTHREAD_VERSION = 3,
        _CS_V5_WIDTH_RESTRICTED_ENVS = 4,
        _CS_V7_WIDTH_RESTRICTED_ENVS = 5,
        _CS_LFS_CFLAGS = 1000,
        _CS_LFS_LDFLAGS = 1001,
        _CS_LFS_LIBS = 1002,
        _CS_LFS_LINTFLAGS = 1003,
        _CS_LFS64_CFLAGS = 1004,
        _CS_LFS64_LDFLAGS = 1005,
        _CS_LFS64_LIBS = 1006,
        _CS_LFS64_LINTFLAGS = 1007,
        _CS_XBS5_ILP32_OFF32_CFLAGS = 1100,
        _CS_XBS5_ILP32_OFF32_LDFLAGS = 1101,
        _CS_XBS5_ILP32_OFF32_LIBS = 1102,
        _CS_XBS5_ILP32_OFF32_LINTFLAGS = 1103,
        _CS_XBS5_ILP32_OFFBIG_CFLAGS = 1104,
        _CS_XBS5_ILP32_OFFBIG_LDFLAGS = 1105,
        _CS_XBS5_ILP32_OFFBIG_LIBS = 1106,
        _CS_XBS5_ILP32_OFFBIG_LINTFLAGS = 1107,
        _CS_XBS5_LP64_OFF64_CFLAGS = 1108,
        _CS_XBS5_LP64_OFF64_LDFLAGS = 1109,
        _CS_XBS5_LP64_OFF64_LIBS = 1110,
        _CS_XBS5_LP64_OFF64_LINTFLAGS = 1111,
        _CS_XBS5_LPBIG_OFFBIG_CFLAGS = 1112,
        _CS_XBS5_LPBIG_OFFBIG_LDFLAGS = 1113,
        _CS_XBS5_LPBIG_OFFBIG_LIBS = 1114,
        _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = 1115,
        _CS_POSIX_V6_ILP32_OFF32_CFLAGS = 1116,
        _CS_POSIX_V6_ILP32_OFF32_LDFLAGS = 1117,
        _CS_POSIX_V6_ILP32_OFF32_LIBS = 1118,
        _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = 1119,
        _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = 1120,
        _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = 1121,
        _CS_POSIX_V6_ILP32_OFFBIG_LIBS = 1122,
        _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = 1123,
        _CS_POSIX_V6_LP64_OFF64_CFLAGS = 1124,
        _CS_POSIX_V6_LP64_OFF64_LDFLAGS = 1125,
        _CS_POSIX_V6_LP64_OFF64_LIBS = 1126,
        _CS_POSIX_V6_LP64_OFF64_LINTFLAGS = 1127,
        _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = 1128,
        _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = 1129,
        _CS_POSIX_V6_LPBIG_OFFBIG_LIBS = 1130,
        _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = 1131,
        _CS_POSIX_V7_ILP32_OFF32_CFLAGS = 1132,
        _CS_POSIX_V7_ILP32_OFF32_LDFLAGS = 1133,
        _CS_POSIX_V7_ILP32_OFF32_LIBS = 1134,
        _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = 1135,
        _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = 1136,
        _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = 1137,
        _CS_POSIX_V7_ILP32_OFFBIG_LIBS = 1138,
        _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = 1139,
        _CS_POSIX_V7_LP64_OFF64_CFLAGS = 1140,
        _CS_POSIX_V7_LP64_OFF64_LDFLAGS = 1141,
        _CS_POSIX_V7_LP64_OFF64_LIBS = 1142,
        _CS_POSIX_V7_LP64_OFF64_LINTFLAGS = 1143,
        _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = 1144,
        _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = 1145,
        _CS_POSIX_V7_LPBIG_OFFBIG_LIBS = 1146,
        _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = 1147,
        _CS_V6_ENV = 1148,
        _CS_V7_ENV = 1149,
    }
    enum _CS_PATH = _Anonymous_18._CS_PATH;
    enum _CS_V6_WIDTH_RESTRICTED_ENVS = _Anonymous_18._CS_V6_WIDTH_RESTRICTED_ENVS;
    enum _CS_GNU_LIBC_VERSION = _Anonymous_18._CS_GNU_LIBC_VERSION;
    enum _CS_GNU_LIBPTHREAD_VERSION = _Anonymous_18._CS_GNU_LIBPTHREAD_VERSION;
    enum _CS_V5_WIDTH_RESTRICTED_ENVS = _Anonymous_18._CS_V5_WIDTH_RESTRICTED_ENVS;
    enum _CS_V7_WIDTH_RESTRICTED_ENVS = _Anonymous_18._CS_V7_WIDTH_RESTRICTED_ENVS;
    enum _CS_LFS_CFLAGS = _Anonymous_18._CS_LFS_CFLAGS;
    enum _CS_LFS_LDFLAGS = _Anonymous_18._CS_LFS_LDFLAGS;
    enum _CS_LFS_LIBS = _Anonymous_18._CS_LFS_LIBS;
    enum _CS_LFS_LINTFLAGS = _Anonymous_18._CS_LFS_LINTFLAGS;
    enum _CS_LFS64_CFLAGS = _Anonymous_18._CS_LFS64_CFLAGS;
    enum _CS_LFS64_LDFLAGS = _Anonymous_18._CS_LFS64_LDFLAGS;
    enum _CS_LFS64_LIBS = _Anonymous_18._CS_LFS64_LIBS;
    enum _CS_LFS64_LINTFLAGS = _Anonymous_18._CS_LFS64_LINTFLAGS;
    enum _CS_XBS5_ILP32_OFF32_CFLAGS = _Anonymous_18._CS_XBS5_ILP32_OFF32_CFLAGS;
    enum _CS_XBS5_ILP32_OFF32_LDFLAGS = _Anonymous_18._CS_XBS5_ILP32_OFF32_LDFLAGS;
    enum _CS_XBS5_ILP32_OFF32_LIBS = _Anonymous_18._CS_XBS5_ILP32_OFF32_LIBS;
    enum _CS_XBS5_ILP32_OFF32_LINTFLAGS = _Anonymous_18._CS_XBS5_ILP32_OFF32_LINTFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_CFLAGS = _Anonymous_18._CS_XBS5_ILP32_OFFBIG_CFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_LDFLAGS = _Anonymous_18._CS_XBS5_ILP32_OFFBIG_LDFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_LIBS = _Anonymous_18._CS_XBS5_ILP32_OFFBIG_LIBS;
    enum _CS_XBS5_ILP32_OFFBIG_LINTFLAGS = _Anonymous_18._CS_XBS5_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_XBS5_LP64_OFF64_CFLAGS = _Anonymous_18._CS_XBS5_LP64_OFF64_CFLAGS;
    enum _CS_XBS5_LP64_OFF64_LDFLAGS = _Anonymous_18._CS_XBS5_LP64_OFF64_LDFLAGS;
    enum _CS_XBS5_LP64_OFF64_LIBS = _Anonymous_18._CS_XBS5_LP64_OFF64_LIBS;
    enum _CS_XBS5_LP64_OFF64_LINTFLAGS = _Anonymous_18._CS_XBS5_LP64_OFF64_LINTFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_CFLAGS = _Anonymous_18._CS_XBS5_LPBIG_OFFBIG_CFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_LDFLAGS = _Anonymous_18._CS_XBS5_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_LIBS = _Anonymous_18._CS_XBS5_LPBIG_OFFBIG_LIBS;
    enum _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_18._CS_XBS5_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_CFLAGS = _Anonymous_18._CS_POSIX_V6_ILP32_OFF32_CFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_LDFLAGS = _Anonymous_18._CS_POSIX_V6_ILP32_OFF32_LDFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_LIBS = _Anonymous_18._CS_POSIX_V6_ILP32_OFF32_LIBS;
    enum _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = _Anonymous_18._CS_POSIX_V6_ILP32_OFF32_LINTFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = _Anonymous_18._CS_POSIX_V6_ILP32_OFFBIG_CFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = _Anonymous_18._CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LIBS = _Anonymous_18._CS_POSIX_V6_ILP32_OFFBIG_LIBS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = _Anonymous_18._CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_CFLAGS = _Anonymous_18._CS_POSIX_V6_LP64_OFF64_CFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_LDFLAGS = _Anonymous_18._CS_POSIX_V6_LP64_OFF64_LDFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_LIBS = _Anonymous_18._CS_POSIX_V6_LP64_OFF64_LIBS;
    enum _CS_POSIX_V6_LP64_OFF64_LINTFLAGS = _Anonymous_18._CS_POSIX_V6_LP64_OFF64_LINTFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = _Anonymous_18._CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = _Anonymous_18._CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LIBS = _Anonymous_18._CS_POSIX_V6_LPBIG_OFFBIG_LIBS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_18._CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_CFLAGS = _Anonymous_18._CS_POSIX_V7_ILP32_OFF32_CFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_LDFLAGS = _Anonymous_18._CS_POSIX_V7_ILP32_OFF32_LDFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_LIBS = _Anonymous_18._CS_POSIX_V7_ILP32_OFF32_LIBS;
    enum _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = _Anonymous_18._CS_POSIX_V7_ILP32_OFF32_LINTFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = _Anonymous_18._CS_POSIX_V7_ILP32_OFFBIG_CFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = _Anonymous_18._CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LIBS = _Anonymous_18._CS_POSIX_V7_ILP32_OFFBIG_LIBS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = _Anonymous_18._CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_CFLAGS = _Anonymous_18._CS_POSIX_V7_LP64_OFF64_CFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_LDFLAGS = _Anonymous_18._CS_POSIX_V7_LP64_OFF64_LDFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_LIBS = _Anonymous_18._CS_POSIX_V7_LP64_OFF64_LIBS;
    enum _CS_POSIX_V7_LP64_OFF64_LINTFLAGS = _Anonymous_18._CS_POSIX_V7_LP64_OFF64_LINTFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = _Anonymous_18._CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = _Anonymous_18._CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LIBS = _Anonymous_18._CS_POSIX_V7_LPBIG_OFFBIG_LIBS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_18._CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_V6_ENV = _Anonymous_18._CS_V6_ENV;
    enum _CS_V7_ENV = _Anonymous_18._CS_V7_ENV;
    c_ulong strxfrm_l(char*, const(char)*, c_ulong, __locale_struct*) @nogc nothrow;
    int strcoll_l(const(char)*, const(char)*, __locale_struct*) @nogc nothrow;
    c_ulong strxfrm(char*, const(char)*, c_ulong) @nogc nothrow;
    int strcoll(const(char)*, const(char)*) @nogc nothrow;
    int strncmp(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    int strcmp(const(char)*, const(char)*) @nogc nothrow;
    char* strncat(char*, const(char)*, c_ulong) @nogc nothrow;
    char* strcat(char*, const(char)*) @nogc nothrow;
    char* strncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* strcpy(char*, const(char)*) @nogc nothrow;
    void* memchr(const(void)*, int, c_ulong) @nogc nothrow;
    int memcmp(const(void)*, const(void)*, c_ulong) @nogc nothrow;
    void* memset(void*, int, c_ulong) @nogc nothrow;
    void* memccpy(void*, const(void)*, int, c_ulong) @nogc nothrow;
    void* memmove(void*, const(void)*, c_ulong) @nogc nothrow;
    void* memcpy(void*, const(void)*, c_ulong) @nogc nothrow;
    int getloadavg(double*, int) @nogc nothrow;
    int getsubopt(char**, char**, char**) @nogc nothrow;
    int rpmatch(const(char)*) @nogc nothrow;
    c_ulong wcstombs(char*, const(int)*, c_ulong) @nogc nothrow;
    c_ulong mbstowcs(int*, const(char)*, c_ulong) @nogc nothrow;
    int wctomb(char*, int) @nogc nothrow;
    int mbtowc(int*, const(char)*, c_ulong) @nogc nothrow;
    int mblen(const(char)*, c_ulong) @nogc nothrow;
    int qfcvt_r(real, int, int*, int*, char*, c_ulong) @nogc nothrow;
    int qecvt_r(real, int, int*, int*, char*, c_ulong) @nogc nothrow;
    int fcvt_r(double, int, int*, int*, char*, c_ulong) @nogc nothrow;
    int ecvt_r(double, int, int*, int*, char*, c_ulong) @nogc nothrow;
    char* qgcvt(real, int, char*) @nogc nothrow;
    char* qfcvt(real, int, int*, int*) @nogc nothrow;
    char* qecvt(real, int, int*, int*) @nogc nothrow;
    char* gcvt(double, int, char*) @nogc nothrow;
    char* fcvt(double, int, int*, int*) @nogc nothrow;
    char* ecvt(double, int, int*, int*) @nogc nothrow;
    lldiv_t lldiv(long, long) @nogc nothrow;
    ldiv_t ldiv(c_long, c_long) @nogc nothrow;
    div_t div(int, int) @nogc nothrow;
    long llabs(long) @nogc nothrow;
    c_long labs(c_long) @nogc nothrow;
    int abs(int) @nogc nothrow;
    void qsort(void*, c_ulong, c_ulong, int function(const(void)*, const(void)*)) @nogc nothrow;
    struct flock
    {
        short l_type;
        short l_whence;
        c_long l_start;
        c_long l_len;
        int l_pid;
    }
    void* bsearch(const(void)*, const(void)*, c_ulong, c_ulong, int function(const(void)*, const(void)*)) @nogc nothrow;
    alias __compar_fn_t = int function(const(void)*, const(void)*);
    char* realpath(const(char)*, char*) @nogc nothrow;
    int system(const(char)*) @nogc nothrow;
    char* mkdtemp(char*) @nogc nothrow;
    int mkstemps(char*, int) @nogc nothrow;
    int mkstemp(char*) @nogc nothrow;
    alias _Float32 = float;
    char* mktemp(char*) @nogc nothrow;
    alias _Float64 = double;
    int clearenv() @nogc nothrow;
    alias _Float32x = double;
    int unsetenv(const(char)*) @nogc nothrow;
    alias _Float64x = real;
    int setenv(const(char)*, const(char)*, int) @nogc nothrow;
    int putenv(char*) @nogc nothrow;
    extern __gshared char* optarg;
    extern __gshared int optind;
    extern __gshared int opterr;
    extern __gshared int optopt;
    int getopt(int, char**, const(char)*) @nogc nothrow;
    char* getenv(const(char)*) @nogc nothrow;
    void _Exit(int) @nogc nothrow;
    void quick_exit(int) @nogc nothrow;
    void exit(int) @nogc nothrow;
    int on_exit(void function(int, void*), void*) @nogc nothrow;
    int at_quick_exit(void function()) @nogc nothrow;
    int atexit(void function()) @nogc nothrow;
    void abort() @nogc nothrow;
    void* aligned_alloc(c_ulong, c_ulong) @nogc nothrow;
    int posix_memalign(void**, c_ulong, c_ulong) @nogc nothrow;
    void* valloc(c_ulong) @nogc nothrow;
    void free(void*) @nogc nothrow;
    void* reallocarray(void*, c_ulong, c_ulong) @nogc nothrow;
    void* realloc(void*, c_ulong) @nogc nothrow;
    void* calloc(c_ulong, c_ulong) @nogc nothrow;
    void* malloc(c_ulong) @nogc nothrow;
    int lcong48_r(ushort*, drand48_data*) @nogc nothrow;
    int seed48_r(ushort*, drand48_data*) @nogc nothrow;
    int srand48_r(c_long, drand48_data*) @nogc nothrow;
    int jrand48_r(ushort*, drand48_data*, c_long*) @nogc nothrow;
    int mrand48_r(drand48_data*, c_long*) @nogc nothrow;
    int nrand48_r(ushort*, drand48_data*, c_long*) @nogc nothrow;
    int lrand48_r(drand48_data*, c_long*) @nogc nothrow;
    int erand48_r(ushort*, drand48_data*, double*) @nogc nothrow;
    int drand48_r(drand48_data*, double*) @nogc nothrow;
    struct drand48_data
    {
        ushort[3] __x;
        ushort[3] __old_x;
        ushort __c;
        ushort __init;
        ulong __a;
    }
    void lcong48(ushort*) @nogc nothrow;
    ushort* seed48(ushort*) @nogc nothrow;
    void srand48(c_long) @nogc nothrow;
    c_long jrand48(ushort*) @nogc nothrow;
    c_long mrand48() @nogc nothrow;
    c_long nrand48(ushort*) @nogc nothrow;
    c_long lrand48() @nogc nothrow;
    double erand48(ushort*) @nogc nothrow;
    double drand48() @nogc nothrow;
    int rand_r(uint*) @nogc nothrow;
    void srand(uint) @nogc nothrow;
    int rand() @nogc nothrow;
    int setstate_r(char*, random_data*) @nogc nothrow;
    int initstate_r(uint, char*, c_ulong, random_data*) @nogc nothrow;
    int srandom_r(uint, random_data*) @nogc nothrow;
    int random_r(random_data*, int*) @nogc nothrow;
    struct random_data
    {
        int* fptr;
        int* rptr;
        int* state;
        int rand_type;
        int rand_deg;
        int rand_sep;
        int* end_ptr;
    }
    char* setstate(char*) @nogc nothrow;
    char* initstate(uint, char*, c_ulong) @nogc nothrow;
    void srandom(uint) @nogc nothrow;
    c_long random() @nogc nothrow;
    c_long a64l(const(char)*) @nogc nothrow;
    char* l64a(c_long) @nogc nothrow;
    struct __pthread_rwlock_arch_t
    {
        uint __readers;
        uint __writers;
        uint __wrphase_futex;
        uint __writers_futex;
        uint __pad3;
        uint __pad4;
        int __cur_writer;
        int __shared;
        byte __rwelision;
        ubyte[7] __pad1;
        c_ulong __pad2;
        uint __flags;
    }
    ulong strtoull(const(char)*, char**, int) @nogc nothrow;
    alias pthread_t = c_ulong;
    union pthread_mutexattr_t
    {
        char[4] __size;
        int __align;
    }
    union pthread_condattr_t
    {
        char[4] __size;
        int __align;
    }
    alias pthread_key_t = uint;
    alias pthread_once_t = int;
    union pthread_attr_t
    {
        char[56] __size;
        c_long __align;
    }
    union pthread_mutex_t
    {
        __pthread_mutex_s __data;
        char[40] __size;
        c_long __align;
    }
    union pthread_cond_t
    {
        __pthread_cond_s __data;
        char[48] __size;
        long __align;
    }
    union pthread_rwlock_t
    {
        __pthread_rwlock_arch_t __data;
        char[56] __size;
        c_long __align;
    }
    union pthread_rwlockattr_t
    {
        char[8] __size;
        c_long __align;
    }
    alias pthread_spinlock_t = int;
    union pthread_barrier_t
    {
        char[32] __size;
        c_long __align;
    }
    union pthread_barrierattr_t
    {
        char[4] __size;
        int __align;
    }
    long strtoll(const(char)*, char**, int) @nogc nothrow;
    ulong strtouq(const(char)*, char**, int) @nogc nothrow;
    long strtoq(const(char)*, char**, int) @nogc nothrow;
    struct stat
    {
        c_ulong st_dev;
        c_ulong st_ino;
        c_ulong st_nlink;
        uint st_mode;
        uint st_uid;
        uint st_gid;
        int __pad0;
        c_ulong st_rdev;
        c_long st_size;
        c_long st_blksize;
        c_long st_blocks;
        timespec st_atim;
        timespec st_mtim;
        timespec st_ctim;
        c_long[3] __glibc_reserved;
    }
    c_ulong strtoul(const(char)*, char**, int) @nogc nothrow;
    c_long strtol(const(char)*, char**, int) @nogc nothrow;
    real strtold(const(char)*, char**) @nogc nothrow;
    float strtof(const(char)*, char**) @nogc nothrow;
    alias int8_t = byte;
    alias int16_t = short;
    alias int32_t = int;
    alias int64_t = c_long;
    alias uint8_t = ubyte;
    alias uint16_t = ushort;
    alias uint32_t = uint;
    alias uint64_t = ulong;
    double strtod(const(char)*, char**) @nogc nothrow;
    extern __gshared int sys_nerr;
    extern __gshared const(const(char)*)[0] sys_errlist;
    long atoll(const(char)*) @nogc nothrow;
    alias __pthread_list_t = __pthread_internal_list;
    struct __pthread_internal_list
    {
        __pthread_internal_list* __prev;
        __pthread_internal_list* __next;
    }
    struct __pthread_mutex_s
    {
        int __lock;
        uint __count;
        int __owner;
        uint __nusers;
        int __kind;
        short __spins;
        short __elision;
        __pthread_internal_list __list;
    }
    struct __pthread_cond_s
    {
        static union _Anonymous_19
        {
            ulong __wseq;
            static struct _Anonymous_20
            {
                uint __low;
                uint __high;
            }
            _Anonymous_20 __wseq32;
        }
        _Anonymous_19 _anonymous_21;
        auto __wseq() @property @nogc pure nothrow { return _anonymous_21.__wseq; }
        void __wseq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_21.__wseq = val; }
        auto __wseq32() @property @nogc pure nothrow { return _anonymous_21.__wseq32; }
        void __wseq32(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_21.__wseq32 = val; }
        static union _Anonymous_22
        {
            ulong __g1_start;
            static struct _Anonymous_23
            {
                uint __low;
                uint __high;
            }
            _Anonymous_23 __g1_start32;
        }
        _Anonymous_22 _anonymous_24;
        auto __g1_start() @property @nogc pure nothrow { return _anonymous_24.__g1_start; }
        void __g1_start(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_24.__g1_start = val; }
        auto __g1_start32() @property @nogc pure nothrow { return _anonymous_24.__g1_start32; }
        void __g1_start32(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_24.__g1_start32 = val; }
        uint[2] __g_refs;
        uint[2] __g_size;
        uint __g1_orig_size;
        uint __wrefs;
        uint[2] __g_signals;
    }
    c_long atol(const(char)*) @nogc nothrow;
    int atoi(const(char)*) @nogc nothrow;
    double atof(const(char)*) @nogc nothrow;
    c_ulong __ctype_get_mb_cur_max() @nogc nothrow;
    struct lldiv_t
    {
        long quot;
        long rem;
    }
    alias __u_char = ubyte;
    alias __u_short = ushort;
    alias __u_int = uint;
    alias __u_long = c_ulong;
    alias __int8_t = byte;
    alias __uint8_t = ubyte;
    alias __int16_t = short;
    alias __uint16_t = ushort;
    alias __int32_t = int;
    alias __uint32_t = uint;
    alias __int64_t = c_long;
    alias __uint64_t = c_ulong;
    alias __int_least8_t = byte;
    alias __uint_least8_t = ubyte;
    alias __int_least16_t = short;
    alias __uint_least16_t = ushort;
    alias __int_least32_t = int;
    alias __uint_least32_t = uint;
    alias __int_least64_t = c_long;
    alias __uint_least64_t = c_ulong;
    alias __quad_t = c_long;
    alias __u_quad_t = c_ulong;
    alias __intmax_t = c_long;
    alias __uintmax_t = c_ulong;
    struct ldiv_t
    {
        c_long quot;
        c_long rem;
    }
    struct div_t
    {
        int quot;
        int rem;
    }
    alias __dev_t = c_ulong;
    alias __uid_t = uint;
    alias __gid_t = uint;
    alias __ino_t = c_ulong;
    alias __ino64_t = c_ulong;
    alias __mode_t = uint;
    alias __nlink_t = c_ulong;
    alias __off_t = c_long;
    alias __off64_t = c_long;
    alias __pid_t = int;
    struct __fsid_t
    {
        int[2] __val;
    }
    alias __clock_t = c_long;
    alias __rlim_t = c_ulong;
    alias __rlim64_t = c_ulong;
    alias __id_t = uint;
    alias __time_t = c_long;
    alias __useconds_t = uint;
    alias __suseconds_t = c_long;
    alias __daddr_t = int;
    alias __key_t = int;
    alias __clockid_t = int;
    alias __timer_t = void*;
    alias __blksize_t = c_long;
    alias __blkcnt_t = c_long;
    alias __blkcnt64_t = c_long;
    alias __fsblkcnt_t = c_ulong;
    alias __fsblkcnt64_t = c_ulong;
    alias __fsfilcnt_t = c_ulong;
    alias __fsfilcnt64_t = c_ulong;
    alias __fsword_t = c_long;
    alias __ssize_t = c_long;
    alias __syscall_slong_t = c_long;
    alias __syscall_ulong_t = c_ulong;
    alias __loff_t = c_long;
    alias __caddr_t = char*;
    alias __intptr_t = c_long;
    alias __socklen_t = uint;
    alias __sig_atomic_t = int;
    int __overflow(_IO_FILE*, int) @nogc nothrow;
    alias FILE = _IO_FILE;
    int __uflow(_IO_FILE*) @nogc nothrow;
    struct _IO_FILE
    {
        int _flags;
        char* _IO_read_ptr;
        char* _IO_read_end;
        char* _IO_read_base;
        char* _IO_write_base;
        char* _IO_write_ptr;
        char* _IO_write_end;
        char* _IO_buf_base;
        char* _IO_buf_end;
        char* _IO_save_base;
        char* _IO_backup_base;
        char* _IO_save_end;
        _IO_marker* _markers;
        _IO_FILE* _chain;
        int _fileno;
        int _flags2;
        c_long _old_offset;
        ushort _cur_column;
        byte _vtable_offset;
        char[1] _shortbuf;
        void* _lock;
        c_long _offset;
        _IO_codecvt* _codecvt;
        _IO_wide_data* _wide_data;
        _IO_FILE* _freeres_list;
        void* _freeres_buf;
        c_ulong __pad5;
        int _mode;
        char[20] _unused2;
    }
    alias __FILE = _IO_FILE;
    alias __fpos64_t = _G_fpos64_t;
    struct _G_fpos64_t
    {
        c_long __pos;
        __mbstate_t __state;
    }
    alias __fpos_t = _G_fpos_t;
    struct _G_fpos_t
    {
        c_long __pos;
        __mbstate_t __state;
    }
    void funlockfile(_IO_FILE*) @nogc nothrow;
    struct __locale_struct
    {
        __locale_data*[13] __locales;
        const(ushort)* __ctype_b;
        const(int)* __ctype_tolower;
        const(int)* __ctype_toupper;
        const(char)*[13] __names;
    }
    alias __locale_t = __locale_struct*;
    struct __mbstate_t
    {
        int __count;
        static union _Anonymous_25
        {
            uint __wch;
            char[4] __wchb;
        }
        _Anonymous_25 __value;
    }
    int ftrylockfile(_IO_FILE*) @nogc nothrow;
    struct __sigset_t
    {
        c_ulong[16] __val;
    }
    alias clock_t = c_long;
    void flockfile(_IO_FILE*) @nogc nothrow;
    alias clockid_t = int;
    alias locale_t = __locale_struct*;
    alias sigset_t = __sigset_t;
    struct _IO_marker;
    struct _IO_codecvt;
    struct _IO_wide_data;
    alias _IO_lock_t = void;
    char* ctermid(char*) @nogc nothrow;
    int pclose(_IO_FILE*) @nogc nothrow;
    _IO_FILE* popen(const(char)*, const(char)*) @nogc nothrow;
    struct itimerspec
    {
        timespec it_interval;
        timespec it_value;
    }
    int fileno_unlocked(_IO_FILE*) @nogc nothrow;
    struct timespec
    {
        c_long tv_sec;
        c_long tv_nsec;
    }
    struct timeval
    {
        c_long tv_sec;
        c_long tv_usec;
    }
    struct tm
    {
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        int tm_year;
        int tm_wday;
        int tm_yday;
        int tm_isdst;
        c_long tm_gmtoff;
        const(char)* tm_zone;
    }
    alias time_t = c_long;
    int fileno(_IO_FILE*) @nogc nothrow;
    alias timer_t = void*;
    void perror(const(char)*) @nogc nothrow;
    int ferror_unlocked(_IO_FILE*) @nogc nothrow;
    int feof_unlocked(_IO_FILE*) @nogc nothrow;
    void clearerr_unlocked(_IO_FILE*) @nogc nothrow;
    int ferror(_IO_FILE*) @nogc nothrow;
    int feof(_IO_FILE*) @nogc nothrow;
    void clearerr(_IO_FILE*) @nogc nothrow;
    int fsetpos(_IO_FILE*, const(_G_fpos_t)*) @nogc nothrow;
    int fgetpos(_IO_FILE*, _G_fpos_t*) @nogc nothrow;
    c_long ftello(_IO_FILE*) @nogc nothrow;
    int fseeko(_IO_FILE*, c_long, int) @nogc nothrow;
    void rewind(_IO_FILE*) @nogc nothrow;
    c_long ftell(_IO_FILE*) @nogc nothrow;
    int fseek(_IO_FILE*, c_long, int) @nogc nothrow;
    c_ulong fwrite_unlocked(const(void)*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    c_ulong fread_unlocked(void*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    c_ulong fwrite(const(void)*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    c_ulong fread(void*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    int ungetc(int, _IO_FILE*) @nogc nothrow;
    int puts(const(char)*) @nogc nothrow;
    int fputs(const(char)*, _IO_FILE*) @nogc nothrow;
    static ushort __uint16_identity(ushort) @nogc nothrow;
    static uint __uint32_identity(uint) @nogc nothrow;
    static c_ulong __uint64_identity(c_ulong) @nogc nothrow;
    c_long getline(char**, c_ulong*, _IO_FILE*) @nogc nothrow;
    c_long getdelim(char**, c_ulong*, int, _IO_FILE*) @nogc nothrow;
    c_long __getdelim(char**, c_ulong*, int, _IO_FILE*) @nogc nothrow;
    char* fgets(char*, int, _IO_FILE*) @nogc nothrow;
    int putw(int, _IO_FILE*) @nogc nothrow;
    int getw(_IO_FILE*) @nogc nothrow;
    int putchar_unlocked(int) @nogc nothrow;
    int putc_unlocked(int, _IO_FILE*) @nogc nothrow;
    int fputc_unlocked(int, _IO_FILE*) @nogc nothrow;
    int putchar(int) @nogc nothrow;
    int putc(int, _IO_FILE*) @nogc nothrow;
    int fputc(int, _IO_FILE*) @nogc nothrow;
    int fgetc_unlocked(_IO_FILE*) @nogc nothrow;
    int getchar_unlocked() @nogc nothrow;
    int getc_unlocked(_IO_FILE*) @nogc nothrow;
    int getchar() @nogc nothrow;
    int getc(_IO_FILE*) @nogc nothrow;
    int fgetc(_IO_FILE*) @nogc nothrow;
    int vsscanf(const(char)*, const(char)*, va_list*) @nogc nothrow;
    int vscanf(const(char)*, va_list*) @nogc nothrow;
    int vfscanf(_IO_FILE*, const(char)*, va_list*) @nogc nothrow;
    enum _Anonymous_26
    {
        _ISupper = 256,
        _ISlower = 512,
        _ISalpha = 1024,
        _ISdigit = 2048,
        _ISxdigit = 4096,
        _ISspace = 8192,
        _ISprint = 16384,
        _ISgraph = 32768,
        _ISblank = 1,
        _IScntrl = 2,
        _ISpunct = 4,
        _ISalnum = 8,
    }
    enum _ISupper = _Anonymous_26._ISupper;
    enum _ISlower = _Anonymous_26._ISlower;
    enum _ISalpha = _Anonymous_26._ISalpha;
    enum _ISdigit = _Anonymous_26._ISdigit;
    enum _ISxdigit = _Anonymous_26._ISxdigit;
    enum _ISspace = _Anonymous_26._ISspace;
    enum _ISprint = _Anonymous_26._ISprint;
    enum _ISgraph = _Anonymous_26._ISgraph;
    enum _ISblank = _Anonymous_26._ISblank;
    enum _IScntrl = _Anonymous_26._IScntrl;
    enum _ISpunct = _Anonymous_26._ISpunct;
    enum _ISalnum = _Anonymous_26._ISalnum;
    const(ushort)** __ctype_b_loc() @nogc nothrow;
    const(int)** __ctype_tolower_loc() @nogc nothrow;
    const(int)** __ctype_toupper_loc() @nogc nothrow;
    pragma(mangle, "isalnum") int isalnum_(int) @nogc nothrow;
    pragma(mangle, "isalpha") int isalpha_(int) @nogc nothrow;
    pragma(mangle, "iscntrl") int iscntrl_(int) @nogc nothrow;
    pragma(mangle, "isdigit") int isdigit_(int) @nogc nothrow;
    pragma(mangle, "islower") int islower_(int) @nogc nothrow;
    pragma(mangle, "isgraph") int isgraph_(int) @nogc nothrow;
    pragma(mangle, "isprint") int isprint_(int) @nogc nothrow;
    pragma(mangle, "ispunct") int ispunct_(int) @nogc nothrow;
    pragma(mangle, "isspace") int isspace_(int) @nogc nothrow;
    pragma(mangle, "isupper") int isupper_(int) @nogc nothrow;
    pragma(mangle, "isxdigit") int isxdigit_(int) @nogc nothrow;
    int tolower(int) @nogc nothrow;
    int toupper(int) @nogc nothrow;
    pragma(mangle, "isblank") int isblank_(int) @nogc nothrow;
    pragma(mangle, "isascii") int isascii_(int) @nogc nothrow;
    pragma(mangle, "toascii") int toascii_(int) @nogc nothrow;
    pragma(mangle, "_toupper") int _toupper_(int) @nogc nothrow;
    pragma(mangle, "_tolower") int _tolower_(int) @nogc nothrow;
    int sscanf(const(char)*, const(char)*, ...) @nogc nothrow;
    int scanf(const(char)*, ...) @nogc nothrow;
    int fscanf(_IO_FILE*, const(char)*, ...) @nogc nothrow;
    int dprintf(int, const(char)*, ...) @nogc nothrow;
    int vdprintf(int, const(char)*, va_list*) @nogc nothrow;
    int vsnprintf(char*, c_ulong, const(char)*, va_list*) @nogc nothrow;
    int snprintf(char*, c_ulong, const(char)*, ...) @nogc nothrow;
    int vsprintf(char*, const(char)*, va_list*) @nogc nothrow;
    int vprintf(const(char)*, va_list*) @nogc nothrow;
    pragma(mangle, "isalnum_l") int isalnum_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isalpha_l") int isalpha_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "iscntrl_l") int iscntrl_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isdigit_l") int isdigit_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "islower_l") int islower_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isgraph_l") int isgraph_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isprint_l") int isprint_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "ispunct_l") int ispunct_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isspace_l") int isspace_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isupper_l") int isupper_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isxdigit_l") int isxdigit_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isblank_l") int isblank_l_(int, __locale_struct*) @nogc nothrow;
    int __tolower_l(int, __locale_struct*) @nogc nothrow;
    int tolower_l(int, __locale_struct*) @nogc nothrow;
    int __toupper_l(int, __locale_struct*) @nogc nothrow;
    int toupper_l(int, __locale_struct*) @nogc nothrow;
    int vfprintf(_IO_FILE*, const(char)*, va_list*) @nogc nothrow;
    int sprintf(char*, const(char)*, ...) @nogc nothrow;
    int printf(const(char)*, ...) @nogc nothrow;
    int fprintf(_IO_FILE*, const(char)*, ...) @nogc nothrow;
    void setlinebuf(_IO_FILE*) @nogc nothrow;
    void setbuffer(_IO_FILE*, char*, c_ulong) @nogc nothrow;
    int setvbuf(_IO_FILE*, char*, int, c_ulong) @nogc nothrow;
    void setbuf(_IO_FILE*, char*) @nogc nothrow;
    _IO_FILE* open_memstream(char**, c_ulong*) @nogc nothrow;
    _IO_FILE* fmemopen(void*, c_ulong, const(char)*) @nogc nothrow;
    _IO_FILE* fdopen(int, const(char)*) @nogc nothrow;
    _IO_FILE* freopen(const(char)*, const(char)*, _IO_FILE*) @nogc nothrow;
    _IO_FILE* fopen(const(char)*, const(char)*) @nogc nothrow;
    int fflush_unlocked(_IO_FILE*) @nogc nothrow;
    int fflush(_IO_FILE*) @nogc nothrow;
    int fclose(_IO_FILE*) @nogc nothrow;
    char* tempnam(const(char)*, const(char)*) @nogc nothrow;
    char* tmpnam_r(char*) @nogc nothrow;
    char* tmpnam(char*) @nogc nothrow;
    _IO_FILE* tmpfile() @nogc nothrow;
    int renameat(int, const(char)*, int, const(char)*) @nogc nothrow;
    int* __errno_location() @nogc nothrow;
    int rename(const(char)*, const(char)*) @nogc nothrow;
    alias mode_t = uint;
    int remove(const(char)*) @nogc nothrow;
    extern __gshared _IO_FILE* stderr;
    extern __gshared _IO_FILE* stdout;
    extern __gshared _IO_FILE* stdin;
    alias fpos_t = _G_fpos_t;
    alias ssize_t = c_long;
    alias off_t = c_long;
    int fcntl(int, int, ...) @nogc nothrow;
    int open(const(char)*, int, ...) @nogc nothrow;
    int openat(int, const(char)*, int, ...) @nogc nothrow;
    int creat(const(char)*, uint) @nogc nothrow;
    int posix_fadvise(int, c_long, c_long, int) @nogc nothrow;
    int posix_fallocate(int, c_long, c_long) @nogc nothrow;
    alias uintmax_t = c_ulong;
    alias intmax_t = c_long;
    alias uintptr_t = c_ulong;
    alias uint_fast64_t = c_ulong;
    alias uint_fast32_t = c_ulong;
    alias uint_fast16_t = c_ulong;
    alias uint_fast8_t = ubyte;
    alias int_fast64_t = c_long;
    alias int_fast32_t = c_long;
    alias int_fast16_t = c_long;
    alias int_fast8_t = byte;
    alias uint_least64_t = c_ulong;
    alias uint_least32_t = uint;
    alias uint_least16_t = ushort;
    alias uint_least8_t = ubyte;
    alias int_least64_t = c_long;
    alias int_least32_t = int;
    alias int_least16_t = short;
    alias int_least8_t = byte;
    alias __gwchar_t = int;
    c_ulong wcstoumax(const(int)*, int**, int) @nogc nothrow;
    c_long wcstoimax(const(int)*, int**, int) @nogc nothrow;
    c_ulong strtoumax(const(char)*, char**, int) @nogc nothrow;
    c_long strtoimax(const(char)*, char**, int) @nogc nothrow;
    imaxdiv_t imaxdiv(c_long, c_long) @nogc nothrow;
    c_long imaxabs(c_long) @nogc nothrow;
    struct imaxdiv_t
    {
        c_long quot;
        c_long rem;
    }




    static if(!is(typeof(PRIi16))) {
        enum PRIi16 = "i";
    }




    static if(!is(typeof(PRIi32))) {
        enum PRIi32 = "i";
    }






    static if(!is(typeof(PRIiLEAST8))) {
        enum PRIiLEAST8 = "i";
    }




    static if(!is(typeof(PRIiLEAST16))) {
        enum PRIiLEAST16 = "i";
    }




    static if(!is(typeof(PRIiLEAST32))) {
        enum PRIiLEAST32 = "i";
    }






    static if(!is(typeof(PRIiFAST8))) {
        enum PRIiFAST8 = "i";
    }
    static if(!is(typeof(PRIo8))) {
        enum PRIo8 = "o";
    }




    static if(!is(typeof(PRIo16))) {
        enum PRIo16 = "o";
    }




    static if(!is(typeof(PRIo32))) {
        enum PRIo32 = "o";
    }






    static if(!is(typeof(PRIoLEAST8))) {
        enum PRIoLEAST8 = "o";
    }




    static if(!is(typeof(PRIoLEAST16))) {
        enum PRIoLEAST16 = "o";
    }




    static if(!is(typeof(PRIoLEAST32))) {
        enum PRIoLEAST32 = "o";
    }






    static if(!is(typeof(PRIoFAST8))) {
        enum PRIoFAST8 = "o";
    }
    static if(!is(typeof(PRIu8))) {
        enum PRIu8 = "u";
    }




    static if(!is(typeof(PRIu16))) {
        enum PRIu16 = "u";
    }




    static if(!is(typeof(PRIu32))) {
        enum PRIu32 = "u";
    }






    static if(!is(typeof(PRIuLEAST8))) {
        enum PRIuLEAST8 = "u";
    }




    static if(!is(typeof(PRIuLEAST16))) {
        enum PRIuLEAST16 = "u";
    }




    static if(!is(typeof(PRIuLEAST32))) {
        enum PRIuLEAST32 = "u";
    }






    static if(!is(typeof(PRIuFAST8))) {
        enum PRIuFAST8 = "u";
    }
    static if(!is(typeof(PRIx8))) {
        enum PRIx8 = "x";
    }




    static if(!is(typeof(PRIx16))) {
        enum PRIx16 = "x";
    }




    static if(!is(typeof(PRIx32))) {
        enum PRIx32 = "x";
    }






    static if(!is(typeof(PRIxLEAST8))) {
        enum PRIxLEAST8 = "x";
    }




    static if(!is(typeof(PRIxLEAST16))) {
        enum PRIxLEAST16 = "x";
    }




    static if(!is(typeof(PRIxLEAST32))) {
        enum PRIxLEAST32 = "x";
    }






    static if(!is(typeof(PRIxFAST8))) {
        enum PRIxFAST8 = "x";
    }
    static if(!is(typeof(PRIX8))) {
        enum PRIX8 = "X";
    }




    static if(!is(typeof(PRIX16))) {
        enum PRIX16 = "X";
    }




    static if(!is(typeof(PRIX32))) {
        enum PRIX32 = "X";
    }






    static if(!is(typeof(PRIXLEAST8))) {
        enum PRIXLEAST8 = "X";
    }




    static if(!is(typeof(PRIXLEAST16))) {
        enum PRIXLEAST16 = "X";
    }




    static if(!is(typeof(PRIXLEAST32))) {
        enum PRIXLEAST32 = "X";
    }






    static if(!is(typeof(PRIXFAST8))) {
        enum PRIXFAST8 = "X";
    }
    static if(!is(typeof(SCNd8))) {
        enum SCNd8 = "hhd";
    }




    static if(!is(typeof(SCNd16))) {
        enum SCNd16 = "hd";
    }




    static if(!is(typeof(SCNd32))) {
        enum SCNd32 = "d";
    }






    static if(!is(typeof(SCNdLEAST8))) {
        enum SCNdLEAST8 = "hhd";
    }




    static if(!is(typeof(SCNdLEAST16))) {
        enum SCNdLEAST16 = "hd";
    }




    static if(!is(typeof(SCNdLEAST32))) {
        enum SCNdLEAST32 = "d";
    }






    static if(!is(typeof(SCNdFAST8))) {
        enum SCNdFAST8 = "hhd";
    }
    static if(!is(typeof(SCNi8))) {
        enum SCNi8 = "hhi";
    }




    static if(!is(typeof(SCNi16))) {
        enum SCNi16 = "hi";
    }




    static if(!is(typeof(SCNi32))) {
        enum SCNi32 = "i";
    }






    static if(!is(typeof(SCNiLEAST8))) {
        enum SCNiLEAST8 = "hhi";
    }




    static if(!is(typeof(SCNiLEAST16))) {
        enum SCNiLEAST16 = "hi";
    }




    static if(!is(typeof(SCNiLEAST32))) {
        enum SCNiLEAST32 = "i";
    }






    static if(!is(typeof(SCNiFAST8))) {
        enum SCNiFAST8 = "hhi";
    }
    static if(!is(typeof(SCNu8))) {
        enum SCNu8 = "hhu";
    }




    static if(!is(typeof(SCNu16))) {
        enum SCNu16 = "hu";
    }




    static if(!is(typeof(SCNu32))) {
        enum SCNu32 = "u";
    }






    static if(!is(typeof(SCNuLEAST8))) {
        enum SCNuLEAST8 = "hhu";
    }




    static if(!is(typeof(SCNuLEAST16))) {
        enum SCNuLEAST16 = "hu";
    }




    static if(!is(typeof(SCNuLEAST32))) {
        enum SCNuLEAST32 = "u";
    }






    static if(!is(typeof(SCNuFAST8))) {
        enum SCNuFAST8 = "hhu";
    }
    static if(!is(typeof(SCNo8))) {
        enum SCNo8 = "hho";
    }




    static if(!is(typeof(SCNo16))) {
        enum SCNo16 = "ho";
    }




    static if(!is(typeof(SCNo32))) {
        enum SCNo32 = "o";
    }






    static if(!is(typeof(SCNoLEAST8))) {
        enum SCNoLEAST8 = "hho";
    }




    static if(!is(typeof(SCNoLEAST16))) {
        enum SCNoLEAST16 = "ho";
    }




    static if(!is(typeof(SCNoLEAST32))) {
        enum SCNoLEAST32 = "o";
    }






    static if(!is(typeof(SCNoFAST8))) {
        enum SCNoFAST8 = "hho";
    }
    static if(!is(typeof(SCNx8))) {
        enum SCNx8 = "hhx";
    }




    static if(!is(typeof(SCNx16))) {
        enum SCNx16 = "hx";
    }




    static if(!is(typeof(SCNx32))) {
        enum SCNx32 = "x";
    }






    static if(!is(typeof(SCNxLEAST8))) {
        enum SCNxLEAST8 = "hhx";
    }




    static if(!is(typeof(SCNxLEAST16))) {
        enum SCNxLEAST16 = "hx";
    }




    static if(!is(typeof(SCNxLEAST32))) {
        enum SCNxLEAST32 = "x";
    }






    static if(!is(typeof(SCNxFAST8))) {
        enum SCNxFAST8 = "hhx";
    }
    static if(!is(typeof(PRIi8))) {
        enum PRIi8 = "i";
    }
    static if(!is(typeof(PRIdFAST8))) {
        enum PRIdFAST8 = "d";
    }






    static if(!is(typeof(PRIdLEAST32))) {
        enum PRIdLEAST32 = "d";
    }




    static if(!is(typeof(PRIdLEAST16))) {
        enum PRIdLEAST16 = "d";
    }




    static if(!is(typeof(PRIdLEAST8))) {
        enum PRIdLEAST8 = "d";
    }






    static if(!is(typeof(PRId32))) {
        enum PRId32 = "d";
    }




    static if(!is(typeof(PRId16))) {
        enum PRId16 = "d";
    }




    static if(!is(typeof(PRId8))) {
        enum PRId8 = "d";
    }




    static if(!is(typeof(__PRIPTR_PREFIX))) {
        enum __PRIPTR_PREFIX = "l";
    }




    static if(!is(typeof(__PRI64_PREFIX))) {
        enum __PRI64_PREFIX = "l";
    }




    static if(!is(typeof(____gwchar_t_defined))) {
        enum ____gwchar_t_defined = 1;
    }




    static if(!is(typeof(_INTTYPES_H))) {
        enum _INTTYPES_H = 1;
    }




    static if(!is(typeof(_LIBC_LIMITS_H_))) {
        enum _LIBC_LIMITS_H_ = 1;
    }
    static if(!is(typeof(MB_LEN_MAX))) {
        enum MB_LEN_MAX = 16;
    }
    static if(!is(typeof(NR_OPEN))) {
        enum NR_OPEN = 1024;
    }




    static if(!is(typeof(NGROUPS_MAX))) {
        enum NGROUPS_MAX = 65536;
    }




    static if(!is(typeof(ARG_MAX))) {
        enum ARG_MAX = 131072;
    }




    static if(!is(typeof(LINK_MAX))) {
        enum LINK_MAX = 127;
    }




    static if(!is(typeof(MAX_CANON))) {
        enum MAX_CANON = 255;
    }




    static if(!is(typeof(MAX_INPUT))) {
        enum MAX_INPUT = 255;
    }




    static if(!is(typeof(NAME_MAX))) {
        enum NAME_MAX = 255;
    }




    static if(!is(typeof(PATH_MAX))) {
        enum PATH_MAX = 4096;
    }




    static if(!is(typeof(PIPE_BUF))) {
        enum PIPE_BUF = 4096;
    }




    static if(!is(typeof(XATTR_NAME_MAX))) {
        enum XATTR_NAME_MAX = 255;
    }




    static if(!is(typeof(XATTR_SIZE_MAX))) {
        enum XATTR_SIZE_MAX = 65536;
    }




    static if(!is(typeof(XATTR_LIST_MAX))) {
        enum XATTR_LIST_MAX = 65536;
    }




    static if(!is(typeof(RTSIG_MAX))) {
        enum RTSIG_MAX = 32;
    }




    static if(!is(typeof(_STDC_PREDEF_H))) {
        enum _STDC_PREDEF_H = 1;
    }




    static if(!is(typeof(_STDINT_H))) {
        enum _STDINT_H = 1;
    }
    static if(!is(typeof(__GLIBC_MINOR__))) {
        enum __GLIBC_MINOR__ = 29;
    }




    static if(!is(typeof(__GLIBC__))) {
        enum __GLIBC__ = 2;
    }




    static if(!is(typeof(__GNU_LIBRARY__))) {
        enum __GNU_LIBRARY__ = 6;
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_SCANF))) {
        enum __GLIBC_USE_DEPRECATED_SCANF = 0;
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_GETS))) {
        enum __GLIBC_USE_DEPRECATED_GETS = 0;
    }




    static if(!is(typeof(__USE_FORTIFY_LEVEL))) {
        enum __USE_FORTIFY_LEVEL = 0;
    }




    static if(!is(typeof(__USE_ATFILE))) {
        enum __USE_ATFILE = 1;
    }




    static if(!is(typeof(__USE_MISC))) {
        enum __USE_MISC = 1;
    }




    static if(!is(typeof(_ATFILE_SOURCE))) {
        enum _ATFILE_SOURCE = 1;
    }




    static if(!is(typeof(__USE_XOPEN2K8))) {
        enum __USE_XOPEN2K8 = 1;
    }




    static if(!is(typeof(__USE_ISOC99))) {
        enum __USE_ISOC99 = 1;
    }




    static if(!is(typeof(__USE_ISOC95))) {
        enum __USE_ISOC95 = 1;
    }




    static if(!is(typeof(__USE_XOPEN2K))) {
        enum __USE_XOPEN2K = 1;
    }




    static if(!is(typeof(__USE_POSIX199506))) {
        enum __USE_POSIX199506 = 1;
    }




    static if(!is(typeof(__USE_POSIX199309))) {
        enum __USE_POSIX199309 = 1;
    }




    static if(!is(typeof(__USE_POSIX2))) {
        enum __USE_POSIX2 = 1;
    }




    static if(!is(typeof(__USE_POSIX))) {
        enum __USE_POSIX = 1;
    }




    static if(!is(typeof(_POSIX_C_SOURCE))) {
        enum _POSIX_C_SOURCE = 200809L;
    }




    static if(!is(typeof(_POSIX_SOURCE))) {
        enum _POSIX_SOURCE = 1;
    }




    static if(!is(typeof(__USE_POSIX_IMPLICITLY))) {
        enum __USE_POSIX_IMPLICITLY = 1;
    }




    static if(!is(typeof(__USE_ISOC11))) {
        enum __USE_ISOC11 = 1;
    }




    static if(!is(typeof(_DEFAULT_SOURCE))) {
        enum _DEFAULT_SOURCE = 1;
    }
    static if(!is(typeof(_FEATURES_H))) {
        enum _FEATURES_H = 1;
    }
    static if(!is(typeof(AT_EACCESS))) {
        enum AT_EACCESS = 0x200;
    }
    static if(!is(typeof(AT_SYMLINK_FOLLOW))) {
        enum AT_SYMLINK_FOLLOW = 0x400;
    }
    static if(!is(typeof(AT_REMOVEDIR))) {
        enum AT_REMOVEDIR = 0x200;
    }
    static if(!is(typeof(AT_SYMLINK_NOFOLLOW))) {
        enum AT_SYMLINK_NOFOLLOW = 0x100;
    }
    static if(!is(typeof(SEEK_END))) {
        enum SEEK_END = 2;
    }
    static if(!is(typeof(SEEK_CUR))) {
        enum SEEK_CUR = 1;
    }






    static if(!is(typeof(SEEK_SET))) {
        enum SEEK_SET = 0;
    }
    static if(!is(typeof(_STDIO_H))) {
        enum _STDIO_H = 1;
    }
    static if(!is(typeof(_IOFBF))) {
        enum _IOFBF = 0;
    }




    static if(!is(typeof(_IOLBF))) {
        enum _IOLBF = 1;
    }




    static if(!is(typeof(_IONBF))) {
        enum _IONBF = 2;
    }




    static if(!is(typeof(BUFSIZ))) {
        enum BUFSIZ = 8192;
    }
    static if(!is(typeof(P_tmpdir))) {
        enum P_tmpdir = "/tmp";
    }
    static if(!is(typeof(_FCNTL_H))) {
        enum _FCNTL_H = 1;
    }






    static if(!is(typeof(_ERRNO_H))) {
        enum _ERRNO_H = 1;
    }
    static if(!is(typeof(__PDP_ENDIAN))) {
        enum __PDP_ENDIAN = 3412;
    }




    static if(!is(typeof(__BIG_ENDIAN))) {
        enum __BIG_ENDIAN = 4321;
    }




    static if(!is(typeof(__LITTLE_ENDIAN))) {
        enum __LITTLE_ENDIAN = 1234;
    }




    static if(!is(typeof(_ENDIAN_H))) {
        enum _ENDIAN_H = 1;
    }
    static if(!is(typeof(_CTYPE_H))) {
        enum _CTYPE_H = 1;
    }




    static if(!is(typeof(__SYSCALL_WORDSIZE))) {
        enum __SYSCALL_WORDSIZE = 64;
    }




    static if(!is(typeof(__WORDSIZE_TIME64_COMPAT32))) {
        enum __WORDSIZE_TIME64_COMPAT32 = 1;
    }




    static if(!is(typeof(__WORDSIZE))) {
        enum __WORDSIZE = 64;
    }
    static if(!is(typeof(_BITS_WCHAR_H))) {
        enum _BITS_WCHAR_H = 1;
    }




    static if(!is(typeof(__WCOREFLAG))) {
        enum __WCOREFLAG = 0x80;
    }




    static if(!is(typeof(__W_CONTINUED))) {
        enum __W_CONTINUED = 0xffff;
    }
    static if(!is(typeof(__WCLONE))) {
        enum __WCLONE = 0x80000000;
    }




    static if(!is(typeof(__WALL))) {
        enum __WALL = 0x40000000;
    }




    static if(!is(typeof(__WNOTHREAD))) {
        enum __WNOTHREAD = 0x20000000;
    }




    static if(!is(typeof(WNOWAIT))) {
        enum WNOWAIT = 0x01000000;
    }




    static if(!is(typeof(WCONTINUED))) {
        enum WCONTINUED = 8;
    }




    static if(!is(typeof(WEXITED))) {
        enum WEXITED = 4;
    }




    static if(!is(typeof(WSTOPPED))) {
        enum WSTOPPED = 2;
    }




    static if(!is(typeof(WUNTRACED))) {
        enum WUNTRACED = 2;
    }




    static if(!is(typeof(WNOHANG))) {
        enum WNOHANG = 1;
    }




    static if(!is(typeof(_BITS_UINTN_IDENTITY_H))) {
        enum _BITS_UINTN_IDENTITY_H = 1;
    }




    static if(!is(typeof(__FD_SETSIZE))) {
        enum __FD_SETSIZE = 1024;
    }




    static if(!is(typeof(__RLIM_T_MATCHES_RLIM64_T))) {
        enum __RLIM_T_MATCHES_RLIM64_T = 1;
    }




    static if(!is(typeof(__INO_T_MATCHES_INO64_T))) {
        enum __INO_T_MATCHES_INO64_T = 1;
    }




    static if(!is(typeof(__OFF_T_MATCHES_OFF64_T))) {
        enum __OFF_T_MATCHES_OFF64_T = 1;
    }
    static if(!is(typeof(_BITS_TYPESIZES_H))) {
        enum _BITS_TYPESIZES_H = 1;
    }




    static if(!is(typeof(__timer_t_defined))) {
        enum __timer_t_defined = 1;
    }




    static if(!is(typeof(__time_t_defined))) {
        enum __time_t_defined = 1;
    }




    static if(!is(typeof(__struct_tm_defined))) {
        enum __struct_tm_defined = 1;
    }




    static if(!is(typeof(__timeval_defined))) {
        enum __timeval_defined = 1;
    }




    static if(!is(typeof(_STRUCT_TIMESPEC))) {
        enum _STRUCT_TIMESPEC = 1;
    }




    static if(!is(typeof(__itimerspec_defined))) {
        enum __itimerspec_defined = 1;
    }




    static if(!is(typeof(_IO_USER_LOCK))) {
        enum _IO_USER_LOCK = 0x8000;
    }






    static if(!is(typeof(_IO_ERR_SEEN))) {
        enum _IO_ERR_SEEN = 0x0020;
    }






    static if(!is(typeof(_IO_EOF_SEEN))) {
        enum _IO_EOF_SEEN = 0x0010;
    }
    static if(!is(typeof(__struct_FILE_defined))) {
        enum __struct_FILE_defined = 1;
    }




    static if(!is(typeof(__sigset_t_defined))) {
        enum __sigset_t_defined = 1;
    }




    static if(!is(typeof(_BITS_TYPES_LOCALE_T_H))) {
        enum _BITS_TYPES_LOCALE_T_H = 1;
    }




    static if(!is(typeof(__clockid_t_defined))) {
        enum __clockid_t_defined = 1;
    }




    static if(!is(typeof(__clock_t_defined))) {
        enum __clock_t_defined = 1;
    }
    static if(!is(typeof(____mbstate_t_defined))) {
        enum ____mbstate_t_defined = 1;
    }




    static if(!is(typeof(_BITS_TYPES___LOCALE_T_H))) {
        enum _BITS_TYPES___LOCALE_T_H = 1;
    }




    static if(!is(typeof(_____fpos_t_defined))) {
        enum _____fpos_t_defined = 1;
    }




    static if(!is(typeof(_____fpos64_t_defined))) {
        enum _____fpos64_t_defined = 1;
    }




    static if(!is(typeof(____FILE_defined))) {
        enum ____FILE_defined = 1;
    }




    static if(!is(typeof(__FILE_defined))) {
        enum __FILE_defined = 1;
    }
    static if(!is(typeof(_STDLIB_H))) {
        enum _STDLIB_H = 1;
    }
    static if(!is(typeof(__ldiv_t_defined))) {
        enum __ldiv_t_defined = 1;
    }






    static if(!is(typeof(_BITS_TYPES_H))) {
        enum _BITS_TYPES_H = 1;
    }






    static if(!is(typeof(__lldiv_t_defined))) {
        enum __lldiv_t_defined = 1;
    }




    static if(!is(typeof(RAND_MAX))) {
        enum RAND_MAX = 2147483647;
    }




    static if(!is(typeof(EXIT_FAILURE))) {
        enum EXIT_FAILURE = 1;
    }




    static if(!is(typeof(EXIT_SUCCESS))) {
        enum EXIT_SUCCESS = 0;
    }
    static if(!is(typeof(_BITS_TIME64_H))) {
        enum _BITS_TIME64_H = 1;
    }




    static if(!is(typeof(TIMER_ABSTIME))) {
        enum TIMER_ABSTIME = 1;
    }




    static if(!is(typeof(CLOCK_TAI))) {
        enum CLOCK_TAI = 11;
    }




    static if(!is(typeof(CLOCK_BOOTTIME_ALARM))) {
        enum CLOCK_BOOTTIME_ALARM = 9;
    }




    static if(!is(typeof(CLOCK_REALTIME_ALARM))) {
        enum CLOCK_REALTIME_ALARM = 8;
    }




    static if(!is(typeof(CLOCK_BOOTTIME))) {
        enum CLOCK_BOOTTIME = 7;
    }




    static if(!is(typeof(CLOCK_MONOTONIC_COARSE))) {
        enum CLOCK_MONOTONIC_COARSE = 6;
    }




    static if(!is(typeof(CLOCK_REALTIME_COARSE))) {
        enum CLOCK_REALTIME_COARSE = 5;
    }




    static if(!is(typeof(CLOCK_MONOTONIC_RAW))) {
        enum CLOCK_MONOTONIC_RAW = 4;
    }




    static if(!is(typeof(CLOCK_THREAD_CPUTIME_ID))) {
        enum CLOCK_THREAD_CPUTIME_ID = 3;
    }




    static if(!is(typeof(CLOCK_PROCESS_CPUTIME_ID))) {
        enum CLOCK_PROCESS_CPUTIME_ID = 2;
    }




    static if(!is(typeof(CLOCK_MONOTONIC))) {
        enum CLOCK_MONOTONIC = 1;
    }




    static if(!is(typeof(CLOCK_REALTIME))) {
        enum CLOCK_REALTIME = 0;
    }






    static if(!is(typeof(_BITS_TIME_H))) {
        enum _BITS_TIME_H = 1;
    }




    static if(!is(typeof(__PTHREAD_MUTEX_HAVE_PREV))) {
        enum __PTHREAD_MUTEX_HAVE_PREV = 1;
    }
    static if(!is(typeof(_THREAD_SHARED_TYPES_H))) {
        enum _THREAD_SHARED_TYPES_H = 1;
    }




    static if(!is(typeof(FOPEN_MAX))) {
        enum FOPEN_MAX = 16;
    }




    static if(!is(typeof(L_ctermid))) {
        enum L_ctermid = 9;
    }




    static if(!is(typeof(FILENAME_MAX))) {
        enum FILENAME_MAX = 4096;
    }




    static if(!is(typeof(TMP_MAX))) {
        enum TMP_MAX = 238328;
    }




    static if(!is(typeof(L_tmpnam))) {
        enum L_tmpnam = 20;
    }




    static if(!is(typeof(_BITS_STDIO_LIM_H))) {
        enum _BITS_STDIO_LIM_H = 1;
    }




    static if(!is(typeof(_BITS_STDINT_UINTN_H))) {
        enum _BITS_STDINT_UINTN_H = 1;
    }




    static if(!is(typeof(_BITS_STDINT_INTN_H))) {
        enum _BITS_STDINT_INTN_H = 1;
    }
    static if(!is(typeof(__S_IEXEC))) {
        enum __S_IEXEC = std.conv.octal!100;
    }




    static if(!is(typeof(__S_IWRITE))) {
        enum __S_IWRITE = std.conv.octal!200;
    }




    static if(!is(typeof(__S_IREAD))) {
        enum __S_IREAD = std.conv.octal!400;
    }




    static if(!is(typeof(__S_ISVTX))) {
        enum __S_ISVTX = std.conv.octal!1000;
    }




    static if(!is(typeof(__S_ISGID))) {
        enum __S_ISGID = std.conv.octal!2000;
    }




    static if(!is(typeof(__S_ISUID))) {
        enum __S_ISUID = std.conv.octal!4000;
    }
    static if(!is(typeof(__S_IFSOCK))) {
        enum __S_IFSOCK = std.conv.octal!140000;
    }




    static if(!is(typeof(__S_IFLNK))) {
        enum __S_IFLNK = std.conv.octal!120000;
    }




    static if(!is(typeof(__S_IFIFO))) {
        enum __S_IFIFO = std.conv.octal!10000;
    }




    static if(!is(typeof(__S_IFREG))) {
        enum __S_IFREG = std.conv.octal!100000;
    }




    static if(!is(typeof(__S_IFBLK))) {
        enum __S_IFBLK = std.conv.octal!60000;
    }




    static if(!is(typeof(__S_IFCHR))) {
        enum __S_IFCHR = std.conv.octal!20000;
    }




    static if(!is(typeof(__S_IFDIR))) {
        enum __S_IFDIR = std.conv.octal!40000;
    }




    static if(!is(typeof(__S_IFMT))) {
        enum __S_IFMT = std.conv.octal!170000;
    }
    static if(!is(typeof(_MKNOD_VER_LINUX))) {
        enum _MKNOD_VER_LINUX = 0;
    }




    static if(!is(typeof(_STAT_VER_LINUX))) {
        enum _STAT_VER_LINUX = 1;
    }




    static if(!is(typeof(_STAT_VER_KERNEL))) {
        enum _STAT_VER_KERNEL = 0;
    }




    static if(!is(typeof(_BITS_STAT_H))) {
        enum _BITS_STAT_H = 1;
    }
    static if(!is(typeof(__FD_ZERO_STOS))) {
        enum __FD_ZERO_STOS = "stosq";
    }




    static if(!is(typeof(__have_pthread_attr_t))) {
        enum __have_pthread_attr_t = 1;
    }




    static if(!is(typeof(_BITS_PTHREADTYPES_COMMON_H))) {
        enum _BITS_PTHREADTYPES_COMMON_H = 1;
    }




    static if(!is(typeof(__PTHREAD_RWLOCK_INT_FLAGS_SHARED))) {
        enum __PTHREAD_RWLOCK_INT_FLAGS_SHARED = 1;
    }
    static if(!is(typeof(__PTHREAD_MUTEX_USE_UNION))) {
        enum __PTHREAD_MUTEX_USE_UNION = 0;
    }




    static if(!is(typeof(__PTHREAD_MUTEX_NUSERS_AFTER_KIND))) {
        enum __PTHREAD_MUTEX_NUSERS_AFTER_KIND = 0;
    }




    static if(!is(typeof(__PTHREAD_MUTEX_LOCK_ELISION))) {
        enum __PTHREAD_MUTEX_LOCK_ELISION = 1;
    }
    static if(!is(typeof(__SIZEOF_PTHREAD_BARRIERATTR_T))) {
        enum __SIZEOF_PTHREAD_BARRIERATTR_T = 4;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_RWLOCKATTR_T))) {
        enum __SIZEOF_PTHREAD_RWLOCKATTR_T = 8;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_CONDATTR_T))) {
        enum __SIZEOF_PTHREAD_CONDATTR_T = 4;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_COND_T))) {
        enum __SIZEOF_PTHREAD_COND_T = 48;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_MUTEXATTR_T))) {
        enum __SIZEOF_PTHREAD_MUTEXATTR_T = 4;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_BARRIER_T))) {
        enum __SIZEOF_PTHREAD_BARRIER_T = 32;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_RWLOCK_T))) {
        enum __SIZEOF_PTHREAD_RWLOCK_T = 56;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_MUTEX_T))) {
        enum __SIZEOF_PTHREAD_MUTEX_T = 40;
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_ATTR_T))) {
        enum __SIZEOF_PTHREAD_ATTR_T = 56;
    }




    static if(!is(typeof(_BITS_PTHREADTYPES_ARCH_H))) {
        enum _BITS_PTHREADTYPES_ARCH_H = 1;
    }
    static if(!is(typeof(_POSIX2_CHAR_TERM))) {
        enum _POSIX2_CHAR_TERM = 200809L;
    }




    static if(!is(typeof(_POSIX_RAW_SOCKETS))) {
        enum _POSIX_RAW_SOCKETS = 200809L;
    }




    static if(!is(typeof(_POSIX_IPV6))) {
        enum _POSIX_IPV6 = 200809L;
    }




    static if(!is(typeof(_POSIX_ADVISORY_INFO))) {
        enum _POSIX_ADVISORY_INFO = 200809L;
    }




    static if(!is(typeof(_POSIX_CLOCK_SELECTION))) {
        enum _POSIX_CLOCK_SELECTION = 200809L;
    }




    static if(!is(typeof(_POSIX_MONOTONIC_CLOCK))) {
        enum _POSIX_MONOTONIC_CLOCK = 0;
    }




    static if(!is(typeof(_POSIX_THREAD_PROCESS_SHARED))) {
        enum _POSIX_THREAD_PROCESS_SHARED = 200809L;
    }




    static if(!is(typeof(_POSIX_MESSAGE_PASSING))) {
        enum _POSIX_MESSAGE_PASSING = 200809L;
    }




    static if(!is(typeof(_POSIX_BARRIERS))) {
        enum _POSIX_BARRIERS = 200809L;
    }




    static if(!is(typeof(_POSIX_TIMERS))) {
        enum _POSIX_TIMERS = 200809L;
    }




    static if(!is(typeof(_POSIX_SPAWN))) {
        enum _POSIX_SPAWN = 200809L;
    }




    static if(!is(typeof(_POSIX_SPIN_LOCKS))) {
        enum _POSIX_SPIN_LOCKS = 200809L;
    }




    static if(!is(typeof(_POSIX_TIMEOUTS))) {
        enum _POSIX_TIMEOUTS = 200809L;
    }




    static if(!is(typeof(_POSIX_SHELL))) {
        enum _POSIX_SHELL = 1;
    }




    static if(!is(typeof(_POSIX_READER_WRITER_LOCKS))) {
        enum _POSIX_READER_WRITER_LOCKS = 200809L;
    }




    static if(!is(typeof(_POSIX_REGEXP))) {
        enum _POSIX_REGEXP = 1;
    }




    static if(!is(typeof(_POSIX_THREAD_CPUTIME))) {
        enum _POSIX_THREAD_CPUTIME = 0;
    }




    static if(!is(typeof(_POSIX_CPUTIME))) {
        enum _POSIX_CPUTIME = 0;
    }




    static if(!is(typeof(_POSIX_SHARED_MEMORY_OBJECTS))) {
        enum _POSIX_SHARED_MEMORY_OBJECTS = 200809L;
    }




    static if(!is(typeof(_LFS64_STDIO))) {
        enum _LFS64_STDIO = 1;
    }




    static if(!is(typeof(_LFS64_LARGEFILE))) {
        enum _LFS64_LARGEFILE = 1;
    }




    static if(!is(typeof(_LFS_LARGEFILE))) {
        enum _LFS_LARGEFILE = 1;
    }




    static if(!is(typeof(_LFS64_ASYNCHRONOUS_IO))) {
        enum _LFS64_ASYNCHRONOUS_IO = 1;
    }




    static if(!is(typeof(_POSIX_PRIORITIZED_IO))) {
        enum _POSIX_PRIORITIZED_IO = 200809L;
    }




    static if(!is(typeof(_LFS_ASYNCHRONOUS_IO))) {
        enum _LFS_ASYNCHRONOUS_IO = 1;
    }




    static if(!is(typeof(_POSIX_ASYNC_IO))) {
        enum _POSIX_ASYNC_IO = 1;
    }




    static if(!is(typeof(_POSIX_ASYNCHRONOUS_IO))) {
        enum _POSIX_ASYNCHRONOUS_IO = 200809L;
    }




    static if(!is(typeof(_POSIX_REALTIME_SIGNALS))) {
        enum _POSIX_REALTIME_SIGNALS = 200809L;
    }




    static if(!is(typeof(_POSIX_SEMAPHORES))) {
        enum _POSIX_SEMAPHORES = 200809L;
    }






    static if(!is(typeof(_POSIX_THREAD_ROBUST_PRIO_INHERIT))) {
        enum _POSIX_THREAD_ROBUST_PRIO_INHERIT = 200809L;
    }




    static if(!is(typeof(_POSIX_THREAD_PRIO_PROTECT))) {
        enum _POSIX_THREAD_PRIO_PROTECT = 200809L;
    }




    static if(!is(typeof(_POSIX_THREAD_PRIO_INHERIT))) {
        enum _POSIX_THREAD_PRIO_INHERIT = 200809L;
    }




    static if(!is(typeof(_POSIX_THREAD_ATTR_STACKADDR))) {
        enum _POSIX_THREAD_ATTR_STACKADDR = 200809L;
    }




    static if(!is(typeof(_POSIX_THREAD_ATTR_STACKSIZE))) {
        enum _POSIX_THREAD_ATTR_STACKSIZE = 200809L;
    }




    static if(!is(typeof(_POSIX_THREAD_PRIORITY_SCHEDULING))) {
        enum _POSIX_THREAD_PRIORITY_SCHEDULING = 200809L;
    }




    static if(!is(typeof(_POSIX_THREAD_SAFE_FUNCTIONS))) {
        enum _POSIX_THREAD_SAFE_FUNCTIONS = 200809L;
    }




    static if(!is(typeof(_POSIX_REENTRANT_FUNCTIONS))) {
        enum _POSIX_REENTRANT_FUNCTIONS = 1;
    }




    static if(!is(typeof(_POSIX_THREADS))) {
        enum _POSIX_THREADS = 200809L;
    }




    static if(!is(typeof(_XOPEN_SHM))) {
        enum _XOPEN_SHM = 1;
    }




    static if(!is(typeof(_XOPEN_REALTIME_THREADS))) {
        enum _XOPEN_REALTIME_THREADS = 1;
    }




    static if(!is(typeof(_XOPEN_REALTIME))) {
        enum _XOPEN_REALTIME = 1;
    }




    static if(!is(typeof(_POSIX_NO_TRUNC))) {
        enum _POSIX_NO_TRUNC = 1;
    }




    static if(!is(typeof(_POSIX_VDISABLE))) {
        enum _POSIX_VDISABLE = '\0';
    }




    static if(!is(typeof(_POSIX_CHOWN_RESTRICTED))) {
        enum _POSIX_CHOWN_RESTRICTED = 0;
    }




    static if(!is(typeof(_POSIX_MEMORY_PROTECTION))) {
        enum _POSIX_MEMORY_PROTECTION = 200809L;
    }




    static if(!is(typeof(_POSIX_MEMLOCK_RANGE))) {
        enum _POSIX_MEMLOCK_RANGE = 200809L;
    }




    static if(!is(typeof(_POSIX_MEMLOCK))) {
        enum _POSIX_MEMLOCK = 200809L;
    }




    static if(!is(typeof(_POSIX_MAPPED_FILES))) {
        enum _POSIX_MAPPED_FILES = 200809L;
    }




    static if(!is(typeof(_POSIX_FSYNC))) {
        enum _POSIX_FSYNC = 200809L;
    }




    static if(!is(typeof(_POSIX_SYNCHRONIZED_IO))) {
        enum _POSIX_SYNCHRONIZED_IO = 200809L;
    }




    static if(!is(typeof(_POSIX_PRIORITY_SCHEDULING))) {
        enum _POSIX_PRIORITY_SCHEDULING = 200809L;
    }




    static if(!is(typeof(_POSIX_SAVED_IDS))) {
        enum _POSIX_SAVED_IDS = 1;
    }




    static if(!is(typeof(_POSIX_JOB_CONTROL))) {
        enum _POSIX_JOB_CONTROL = 1;
    }




    static if(!is(typeof(_BITS_POSIX_OPT_H))) {
        enum _BITS_POSIX_OPT_H = 1;
    }






    static if(!is(typeof(CHARCLASS_NAME_MAX))) {
        enum CHARCLASS_NAME_MAX = 2048;
    }
    static if(!is(typeof(COLL_WEIGHTS_MAX))) {
        enum COLL_WEIGHTS_MAX = 255;
    }
    static if(!is(typeof(_POSIX2_CHARCLASS_NAME_MAX))) {
        enum _POSIX2_CHARCLASS_NAME_MAX = 14;
    }




    static if(!is(typeof(_POSIX2_RE_DUP_MAX))) {
        enum _POSIX2_RE_DUP_MAX = 255;
    }




    static if(!is(typeof(_POSIX2_LINE_MAX))) {
        enum _POSIX2_LINE_MAX = 2048;
    }




    static if(!is(typeof(_POSIX2_EXPR_NEST_MAX))) {
        enum _POSIX2_EXPR_NEST_MAX = 32;
    }




    static if(!is(typeof(_POSIX2_COLL_WEIGHTS_MAX))) {
        enum _POSIX2_COLL_WEIGHTS_MAX = 2;
    }




    static if(!is(typeof(_POSIX2_BC_STRING_MAX))) {
        enum _POSIX2_BC_STRING_MAX = 1000;
    }




    static if(!is(typeof(_POSIX2_BC_SCALE_MAX))) {
        enum _POSIX2_BC_SCALE_MAX = 99;
    }




    static if(!is(typeof(_POSIX2_BC_DIM_MAX))) {
        enum _POSIX2_BC_DIM_MAX = 2048;
    }




    static if(!is(typeof(_POSIX2_BC_BASE_MAX))) {
        enum _POSIX2_BC_BASE_MAX = 99;
    }




    static if(!is(typeof(_BITS_POSIX2_LIM_H))) {
        enum _BITS_POSIX2_LIM_H = 1;
    }






    static if(!is(typeof(_POSIX_CLOCKRES_MIN))) {
        enum _POSIX_CLOCKRES_MIN = 20000000;
    }




    static if(!is(typeof(_POSIX_TZNAME_MAX))) {
        enum _POSIX_TZNAME_MAX = 6;
    }




    static if(!is(typeof(_POSIX_TTY_NAME_MAX))) {
        enum _POSIX_TTY_NAME_MAX = 9;
    }




    static if(!is(typeof(_POSIX_TIMER_MAX))) {
        enum _POSIX_TIMER_MAX = 32;
    }




    static if(!is(typeof(_POSIX_SYMLOOP_MAX))) {
        enum _POSIX_SYMLOOP_MAX = 8;
    }




    static if(!is(typeof(_POSIX_SYMLINK_MAX))) {
        enum _POSIX_SYMLINK_MAX = 255;
    }




    static if(!is(typeof(_POSIX_STREAM_MAX))) {
        enum _POSIX_STREAM_MAX = 8;
    }




    static if(!is(typeof(_POSIX_SSIZE_MAX))) {
        enum _POSIX_SSIZE_MAX = 32767;
    }




    static if(!is(typeof(_POSIX_SIGQUEUE_MAX))) {
        enum _POSIX_SIGQUEUE_MAX = 32;
    }




    static if(!is(typeof(_POSIX_SEM_VALUE_MAX))) {
        enum _POSIX_SEM_VALUE_MAX = 32767;
    }




    static if(!is(typeof(_POSIX_SEM_NSEMS_MAX))) {
        enum _POSIX_SEM_NSEMS_MAX = 256;
    }




    static if(!is(typeof(_POSIX_RTSIG_MAX))) {
        enum _POSIX_RTSIG_MAX = 8;
    }




    static if(!is(typeof(_POSIX_RE_DUP_MAX))) {
        enum _POSIX_RE_DUP_MAX = 255;
    }




    static if(!is(typeof(_POSIX_PIPE_BUF))) {
        enum _POSIX_PIPE_BUF = 512;
    }




    static if(!is(typeof(_POSIX_PATH_MAX))) {
        enum _POSIX_PATH_MAX = 256;
    }




    static if(!is(typeof(_POSIX_OPEN_MAX))) {
        enum _POSIX_OPEN_MAX = 20;
    }




    static if(!is(typeof(_POSIX_NGROUPS_MAX))) {
        enum _POSIX_NGROUPS_MAX = 8;
    }




    static if(!is(typeof(_POSIX_NAME_MAX))) {
        enum _POSIX_NAME_MAX = 14;
    }




    static if(!is(typeof(_POSIX_MQ_PRIO_MAX))) {
        enum _POSIX_MQ_PRIO_MAX = 32;
    }




    static if(!is(typeof(_POSIX_MQ_OPEN_MAX))) {
        enum _POSIX_MQ_OPEN_MAX = 8;
    }




    static if(!is(typeof(_POSIX_MAX_INPUT))) {
        enum _POSIX_MAX_INPUT = 255;
    }




    static if(!is(typeof(_POSIX_MAX_CANON))) {
        enum _POSIX_MAX_CANON = 255;
    }




    static if(!is(typeof(_POSIX_LOGIN_NAME_MAX))) {
        enum _POSIX_LOGIN_NAME_MAX = 9;
    }




    static if(!is(typeof(_POSIX_LINK_MAX))) {
        enum _POSIX_LINK_MAX = 8;
    }




    static if(!is(typeof(_POSIX_HOST_NAME_MAX))) {
        enum _POSIX_HOST_NAME_MAX = 255;
    }




    static if(!is(typeof(_POSIX_DELAYTIMER_MAX))) {
        enum _POSIX_DELAYTIMER_MAX = 32;
    }




    static if(!is(typeof(_POSIX_CHILD_MAX))) {
        enum _POSIX_CHILD_MAX = 25;
    }




    static if(!is(typeof(_POSIX_ARG_MAX))) {
        enum _POSIX_ARG_MAX = 4096;
    }




    static if(!is(typeof(_POSIX_AIO_MAX))) {
        enum _POSIX_AIO_MAX = 1;
    }




    static if(!is(typeof(_POSIX_AIO_LISTIO_MAX))) {
        enum _POSIX_AIO_LISTIO_MAX = 2;
    }




    static if(!is(typeof(_BITS_POSIX1_LIM_H))) {
        enum _BITS_POSIX1_LIM_H = 1;
    }






    static if(!is(typeof(MQ_PRIO_MAX))) {
        enum MQ_PRIO_MAX = 32768;
    }




    static if(!is(typeof(HOST_NAME_MAX))) {
        enum HOST_NAME_MAX = 64;
    }




    static if(!is(typeof(LOGIN_NAME_MAX))) {
        enum LOGIN_NAME_MAX = 256;
    }




    static if(!is(typeof(TTY_NAME_MAX))) {
        enum TTY_NAME_MAX = 32;
    }




    static if(!is(typeof(DELAYTIMER_MAX))) {
        enum DELAYTIMER_MAX = 2147483647;
    }




    static if(!is(typeof(PTHREAD_STACK_MIN))) {
        enum PTHREAD_STACK_MIN = 16384;
    }




    static if(!is(typeof(AIO_PRIO_DELTA_MAX))) {
        enum AIO_PRIO_DELTA_MAX = 20;
    }




    static if(!is(typeof(_POSIX_THREAD_THREADS_MAX))) {
        enum _POSIX_THREAD_THREADS_MAX = 64;
    }






    static if(!is(typeof(_POSIX_THREAD_DESTRUCTOR_ITERATIONS))) {
        enum _POSIX_THREAD_DESTRUCTOR_ITERATIONS = 4;
    }




    static if(!is(typeof(PTHREAD_KEYS_MAX))) {
        enum PTHREAD_KEYS_MAX = 1024;
    }




    static if(!is(typeof(_POSIX_THREAD_KEYS_MAX))) {
        enum _POSIX_THREAD_KEYS_MAX = 128;
    }
    static if(!is(typeof(__GLIBC_USE_IEC_60559_TYPES_EXT))) {
        enum __GLIBC_USE_IEC_60559_TYPES_EXT = 0;
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_FUNCS_EXT))) {
        enum __GLIBC_USE_IEC_60559_FUNCS_EXT = 0;
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_BFP_EXT))) {
        enum __GLIBC_USE_IEC_60559_BFP_EXT = 0;
    }




    static if(!is(typeof(__GLIBC_USE_LIB_EXT2))) {
        enum __GLIBC_USE_LIB_EXT2 = 0;
    }




    static if(!is(typeof(_GETOPT_POSIX_H))) {
        enum _GETOPT_POSIX_H = 1;
    }




    static if(!is(typeof(_GETOPT_CORE_H))) {
        enum _GETOPT_CORE_H = 1;
    }




    static if(!is(typeof(__HAVE_FLOAT64X_LONG_DOUBLE))) {
        enum __HAVE_FLOAT64X_LONG_DOUBLE = 1;
    }




    static if(!is(typeof(__HAVE_FLOAT64X))) {
        enum __HAVE_FLOAT64X = 1;
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT128))) {
        enum __HAVE_DISTINCT_FLOAT128 = 0;
    }




    static if(!is(typeof(__HAVE_FLOAT128))) {
        enum __HAVE_FLOAT128 = 0;
    }
    static if(!is(typeof(__HAVE_FLOATN_NOT_TYPEDEF))) {
        enum __HAVE_FLOATN_NOT_TYPEDEF = 0;
    }
    static if(!is(typeof(__HAVE_DISTINCT_FLOAT64X))) {
        enum __HAVE_DISTINCT_FLOAT64X = 0;
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT32X))) {
        enum __HAVE_DISTINCT_FLOAT32X = 0;
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT64))) {
        enum __HAVE_DISTINCT_FLOAT64 = 0;
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT32))) {
        enum __HAVE_DISTINCT_FLOAT32 = 0;
    }






    static if(!is(typeof(__HAVE_FLOAT128X))) {
        enum __HAVE_FLOAT128X = 0;
    }




    static if(!is(typeof(__HAVE_FLOAT32X))) {
        enum __HAVE_FLOAT32X = 1;
    }




    static if(!is(typeof(__HAVE_FLOAT64))) {
        enum __HAVE_FLOAT64 = 1;
    }






    static if(!is(typeof(__HAVE_FLOAT32))) {
        enum __HAVE_FLOAT32 = 1;
    }




    static if(!is(typeof(__HAVE_FLOAT16))) {
        enum __HAVE_FLOAT16 = 0;
    }






    static if(!is(typeof(F_SETLKW64))) {
        enum F_SETLKW64 = 7;
    }




    static if(!is(typeof(F_SETLK64))) {
        enum F_SETLK64 = 6;
    }




    static if(!is(typeof(F_GETLK64))) {
        enum F_GETLK64 = 5;
    }




    static if(!is(typeof(__O_LARGEFILE))) {
        enum __O_LARGEFILE = 0;
    }
    static if(!is(typeof(POSIX_FADV_WILLNEED))) {
        enum POSIX_FADV_WILLNEED = 3;
    }




    static if(!is(typeof(POSIX_FADV_SEQUENTIAL))) {
        enum POSIX_FADV_SEQUENTIAL = 2;
    }




    static if(!is(typeof(POSIX_FADV_RANDOM))) {
        enum POSIX_FADV_RANDOM = 1;
    }




    static if(!is(typeof(POSIX_FADV_NORMAL))) {
        enum POSIX_FADV_NORMAL = 0;
    }




    static if(!is(typeof(__POSIX_FADV_NOREUSE))) {
        enum __POSIX_FADV_NOREUSE = 5;
    }




    static if(!is(typeof(__POSIX_FADV_DONTNEED))) {
        enum __POSIX_FADV_DONTNEED = 4;
    }
    static if(!is(typeof(LOCK_UN))) {
        enum LOCK_UN = 8;
    }




    static if(!is(typeof(LOCK_NB))) {
        enum LOCK_NB = 4;
    }




    static if(!is(typeof(LOCK_EX))) {
        enum LOCK_EX = 2;
    }




    static if(!is(typeof(LOCK_SH))) {
        enum LOCK_SH = 1;
    }




    static if(!is(typeof(F_SHLCK))) {
        enum F_SHLCK = 8;
    }




    static if(!is(typeof(F_EXLCK))) {
        enum F_EXLCK = 4;
    }




    static if(!is(typeof(F_UNLCK))) {
        enum F_UNLCK = 2;
    }




    static if(!is(typeof(F_WRLCK))) {
        enum F_WRLCK = 1;
    }




    static if(!is(typeof(F_RDLCK))) {
        enum F_RDLCK = 0;
    }




    static if(!is(typeof(FD_CLOEXEC))) {
        enum FD_CLOEXEC = 1;
    }




    static if(!is(typeof(F_DUPFD_CLOEXEC))) {
        enum F_DUPFD_CLOEXEC = 1030;
    }




    static if(!is(typeof(__F_GETOWN_EX))) {
        enum __F_GETOWN_EX = 16;
    }




    static if(!is(typeof(__F_SETOWN_EX))) {
        enum __F_SETOWN_EX = 15;
    }




    static if(!is(typeof(__F_GETSIG))) {
        enum __F_GETSIG = 11;
    }




    static if(!is(typeof(__F_SETSIG))) {
        enum __F_SETSIG = 10;
    }
    static if(!is(typeof(__F_GETOWN))) {
        enum __F_GETOWN = 9;
    }




    static if(!is(typeof(__F_SETOWN))) {
        enum __F_SETOWN = 8;
    }




    static if(!is(typeof(F_SETFL))) {
        enum F_SETFL = 4;
    }




    static if(!is(typeof(F_GETFL))) {
        enum F_GETFL = 3;
    }




    static if(!is(typeof(F_SETFD))) {
        enum F_SETFD = 2;
    }




    static if(!is(typeof(F_GETFD))) {
        enum F_GETFD = 1;
    }




    static if(!is(typeof(F_DUPFD))) {
        enum F_DUPFD = 0;
    }
    static if(!is(typeof(F_SETLKW))) {
        enum F_SETLKW = 7;
    }




    static if(!is(typeof(F_SETLK))) {
        enum F_SETLK = 6;
    }




    static if(!is(typeof(F_GETLK))) {
        enum F_GETLK = 5;
    }






    static if(!is(typeof(__O_DSYNC))) {
        enum __O_DSYNC = std.conv.octal!10000;
    }




    static if(!is(typeof(__O_PATH))) {
        enum __O_PATH = std.conv.octal!10000000;
    }




    static if(!is(typeof(__O_NOATIME))) {
        enum __O_NOATIME = std.conv.octal!1000000;
    }




    static if(!is(typeof(__O_DIRECT))) {
        enum __O_DIRECT = std.conv.octal!40000;
    }




    static if(!is(typeof(__O_CLOEXEC))) {
        enum __O_CLOEXEC = std.conv.octal!2000000;
    }




    static if(!is(typeof(__O_NOFOLLOW))) {
        enum __O_NOFOLLOW = std.conv.octal!400000;
    }




    static if(!is(typeof(__O_DIRECTORY))) {
        enum __O_DIRECTORY = std.conv.octal!200000;
    }




    static if(!is(typeof(O_ASYNC))) {
        enum O_ASYNC = std.conv.octal!20000;
    }






    static if(!is(typeof(O_SYNC))) {
        enum O_SYNC = std.conv.octal!4010000;
    }






    static if(!is(typeof(O_NONBLOCK))) {
        enum O_NONBLOCK = std.conv.octal!4000;
    }




    static if(!is(typeof(O_APPEND))) {
        enum O_APPEND = std.conv.octal!2000;
    }




    static if(!is(typeof(O_TRUNC))) {
        enum O_TRUNC = std.conv.octal!1000;
    }




    static if(!is(typeof(O_NOCTTY))) {
        enum O_NOCTTY = std.conv.octal!400;
    }




    static if(!is(typeof(O_EXCL))) {
        enum O_EXCL = std.conv.octal!200;
    }




    static if(!is(typeof(O_CREAT))) {
        enum O_CREAT = std.conv.octal!100;
    }




    static if(!is(typeof(O_RDWR))) {
        enum O_RDWR = std.conv.octal!2;
    }




    static if(!is(typeof(O_WRONLY))) {
        enum O_WRONLY = std.conv.octal!1;
    }




    static if(!is(typeof(O_RDONLY))) {
        enum O_RDONLY = 0;
    }




    static if(!is(typeof(O_ACCMODE))) {
        enum O_ACCMODE = std.conv.octal!3;
    }






    static if(!is(typeof(_BITS_ERRNO_H))) {
        enum _BITS_ERRNO_H = 1;
    }




    static if(!is(typeof(__LP64_OFF64_LDFLAGS))) {
        enum __LP64_OFF64_LDFLAGS = "-m64";
    }




    static if(!is(typeof(__LP64_OFF64_CFLAGS))) {
        enum __LP64_OFF64_CFLAGS = "-m64";
    }




    static if(!is(typeof(__ILP32_OFFBIG_LDFLAGS))) {
        enum __ILP32_OFFBIG_LDFLAGS = "-m32";
    }




    static if(!is(typeof(__ILP32_OFFBIG_CFLAGS))) {
        enum __ILP32_OFFBIG_CFLAGS = "-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64";
    }




    static if(!is(typeof(__ILP32_OFF32_LDFLAGS))) {
        enum __ILP32_OFF32_LDFLAGS = "-m32";
    }




    static if(!is(typeof(__ILP32_OFF32_CFLAGS))) {
        enum __ILP32_OFF32_CFLAGS = "-m32";
    }




    static if(!is(typeof(_XBS5_LP64_OFF64))) {
        enum _XBS5_LP64_OFF64 = 1;
    }




    static if(!is(typeof(_POSIX_V6_LP64_OFF64))) {
        enum _POSIX_V6_LP64_OFF64 = 1;
    }




    static if(!is(typeof(_POSIX_V7_LP64_OFF64))) {
        enum _POSIX_V7_LP64_OFF64 = 1;
    }
    static if(!is(typeof(_STRING_H))) {
        enum _STRING_H = 1;
    }
    static if(!is(typeof(_STRINGS_H))) {
        enum _STRINGS_H = 1;
    }
    static if(!is(typeof(_SYS_CDEFS_H))) {
        enum _SYS_CDEFS_H = 1;
    }
    static if(!is(typeof(__glibc_c99_flexarr_available))) {
        enum __glibc_c99_flexarr_available = 1;
    }
    static if(!is(typeof(__HAVE_GENERIC_SELECTION))) {
        enum __HAVE_GENERIC_SELECTION = 1;
    }




    static if(!is(typeof(_SYS_SELECT_H))) {
        enum _SYS_SELECT_H = 1;
    }
    static if(!is(typeof(_SYS_STAT_H))) {
        enum _SYS_STAT_H = 1;
    }
    static if(!is(typeof(_BITS_BYTESWAP_H))) {
        enum _BITS_BYTESWAP_H = 1;
    }






    static if(!is(typeof(EHWPOISON))) {
        enum EHWPOISON = 133;
    }




    static if(!is(typeof(ERFKILL))) {
        enum ERFKILL = 132;
    }






    static if(!is(typeof(ENOTRECOVERABLE))) {
        enum ENOTRECOVERABLE = 131;
    }




    static if(!is(typeof(EOWNERDEAD))) {
        enum EOWNERDEAD = 130;
    }






    static if(!is(typeof(EKEYREJECTED))) {
        enum EKEYREJECTED = 129;
    }




    static if(!is(typeof(EKEYREVOKED))) {
        enum EKEYREVOKED = 128;
    }




    static if(!is(typeof(EKEYEXPIRED))) {
        enum EKEYEXPIRED = 127;
    }




    static if(!is(typeof(ENOKEY))) {
        enum ENOKEY = 126;
    }




    static if(!is(typeof(ECANCELED))) {
        enum ECANCELED = 125;
    }




    static if(!is(typeof(EMEDIUMTYPE))) {
        enum EMEDIUMTYPE = 124;
    }




    static if(!is(typeof(ENOMEDIUM))) {
        enum ENOMEDIUM = 123;
    }




    static if(!is(typeof(EDQUOT))) {
        enum EDQUOT = 122;
    }




    static if(!is(typeof(EREMOTEIO))) {
        enum EREMOTEIO = 121;
    }
    static if(!is(typeof(EISNAM))) {
        enum EISNAM = 120;
    }






    static if(!is(typeof(ENAVAIL))) {
        enum ENAVAIL = 119;
    }






    static if(!is(typeof(ENOTNAM))) {
        enum ENOTNAM = 118;
    }




    static if(!is(typeof(EUCLEAN))) {
        enum EUCLEAN = 117;
    }




    static if(!is(typeof(ESTALE))) {
        enum ESTALE = 116;
    }




    static if(!is(typeof(EINPROGRESS))) {
        enum EINPROGRESS = 115;
    }






    static if(!is(typeof(EALREADY))) {
        enum EALREADY = 114;
    }
    static if(!is(typeof(EHOSTUNREACH))) {
        enum EHOSTUNREACH = 113;
    }




    static if(!is(typeof(EHOSTDOWN))) {
        enum EHOSTDOWN = 112;
    }
    static if(!is(typeof(ECONNREFUSED))) {
        enum ECONNREFUSED = 111;
    }
    static if(!is(typeof(S_BLKSIZE))) {
        enum S_BLKSIZE = 512;
    }




    static if(!is(typeof(ETIMEDOUT))) {
        enum ETIMEDOUT = 110;
    }




    static if(!is(typeof(ETOOMANYREFS))) {
        enum ETOOMANYREFS = 109;
    }




    static if(!is(typeof(ESHUTDOWN))) {
        enum ESHUTDOWN = 108;
    }




    static if(!is(typeof(ENOTCONN))) {
        enum ENOTCONN = 107;
    }




    static if(!is(typeof(EISCONN))) {
        enum EISCONN = 106;
    }




    static if(!is(typeof(ENOBUFS))) {
        enum ENOBUFS = 105;
    }




    static if(!is(typeof(ECONNRESET))) {
        enum ECONNRESET = 104;
    }




    static if(!is(typeof(ECONNABORTED))) {
        enum ECONNABORTED = 103;
    }




    static if(!is(typeof(ENETRESET))) {
        enum ENETRESET = 102;
    }




    static if(!is(typeof(ENETUNREACH))) {
        enum ENETUNREACH = 101;
    }




    static if(!is(typeof(ENETDOWN))) {
        enum ENETDOWN = 100;
    }




    static if(!is(typeof(EADDRNOTAVAIL))) {
        enum EADDRNOTAVAIL = 99;
    }




    static if(!is(typeof(EADDRINUSE))) {
        enum EADDRINUSE = 98;
    }




    static if(!is(typeof(EAFNOSUPPORT))) {
        enum EAFNOSUPPORT = 97;
    }




    static if(!is(typeof(EPFNOSUPPORT))) {
        enum EPFNOSUPPORT = 96;
    }




    static if(!is(typeof(EOPNOTSUPP))) {
        enum EOPNOTSUPP = 95;
    }




    static if(!is(typeof(ESOCKTNOSUPPORT))) {
        enum ESOCKTNOSUPPORT = 94;
    }




    static if(!is(typeof(EPROTONOSUPPORT))) {
        enum EPROTONOSUPPORT = 93;
    }




    static if(!is(typeof(ENOPROTOOPT))) {
        enum ENOPROTOOPT = 92;
    }




    static if(!is(typeof(EPROTOTYPE))) {
        enum EPROTOTYPE = 91;
    }




    static if(!is(typeof(EMSGSIZE))) {
        enum EMSGSIZE = 90;
    }




    static if(!is(typeof(EDESTADDRREQ))) {
        enum EDESTADDRREQ = 89;
    }




    static if(!is(typeof(ENOTSOCK))) {
        enum ENOTSOCK = 88;
    }




    static if(!is(typeof(EUSERS))) {
        enum EUSERS = 87;
    }




    static if(!is(typeof(ESTRPIPE))) {
        enum ESTRPIPE = 86;
    }




    static if(!is(typeof(ERESTART))) {
        enum ERESTART = 85;
    }




    static if(!is(typeof(EILSEQ))) {
        enum EILSEQ = 84;
    }




    static if(!is(typeof(ELIBEXEC))) {
        enum ELIBEXEC = 83;
    }




    static if(!is(typeof(ELIBMAX))) {
        enum ELIBMAX = 82;
    }




    static if(!is(typeof(ELIBSCN))) {
        enum ELIBSCN = 81;
    }




    static if(!is(typeof(ELIBBAD))) {
        enum ELIBBAD = 80;
    }




    static if(!is(typeof(ELIBACC))) {
        enum ELIBACC = 79;
    }




    static if(!is(typeof(EREMCHG))) {
        enum EREMCHG = 78;
    }




    static if(!is(typeof(EBADFD))) {
        enum EBADFD = 77;
    }




    static if(!is(typeof(ENOTUNIQ))) {
        enum ENOTUNIQ = 76;
    }




    static if(!is(typeof(EOVERFLOW))) {
        enum EOVERFLOW = 75;
    }




    static if(!is(typeof(EBADMSG))) {
        enum EBADMSG = 74;
    }




    static if(!is(typeof(EDOTDOT))) {
        enum EDOTDOT = 73;
    }




    static if(!is(typeof(EMULTIHOP))) {
        enum EMULTIHOP = 72;
    }




    static if(!is(typeof(EPROTO))) {
        enum EPROTO = 71;
    }




    static if(!is(typeof(ECOMM))) {
        enum ECOMM = 70;
    }




    static if(!is(typeof(ESRMNT))) {
        enum ESRMNT = 69;
    }




    static if(!is(typeof(EADV))) {
        enum EADV = 68;
    }




    static if(!is(typeof(ENOLINK))) {
        enum ENOLINK = 67;
    }




    static if(!is(typeof(EREMOTE))) {
        enum EREMOTE = 66;
    }




    static if(!is(typeof(ENOPKG))) {
        enum ENOPKG = 65;
    }




    static if(!is(typeof(ENONET))) {
        enum ENONET = 64;
    }




    static if(!is(typeof(ENOSR))) {
        enum ENOSR = 63;
    }




    static if(!is(typeof(ETIME))) {
        enum ETIME = 62;
    }




    static if(!is(typeof(ENODATA))) {
        enum ENODATA = 61;
    }




    static if(!is(typeof(ENOSTR))) {
        enum ENOSTR = 60;
    }




    static if(!is(typeof(EBFONT))) {
        enum EBFONT = 59;
    }






    static if(!is(typeof(EBADSLT))) {
        enum EBADSLT = 57;
    }




    static if(!is(typeof(EBADRQC))) {
        enum EBADRQC = 56;
    }




    static if(!is(typeof(ENOANO))) {
        enum ENOANO = 55;
    }




    static if(!is(typeof(EXFULL))) {
        enum EXFULL = 54;
    }




    static if(!is(typeof(EBADR))) {
        enum EBADR = 53;
    }




    static if(!is(typeof(EBADE))) {
        enum EBADE = 52;
    }




    static if(!is(typeof(EL2HLT))) {
        enum EL2HLT = 51;
    }




    static if(!is(typeof(ENOCSI))) {
        enum ENOCSI = 50;
    }




    static if(!is(typeof(_MKNOD_VER))) {
        enum _MKNOD_VER = 0;
    }




    static if(!is(typeof(EUNATCH))) {
        enum EUNATCH = 49;
    }




    static if(!is(typeof(ELNRNG))) {
        enum ELNRNG = 48;
    }




    static if(!is(typeof(EL3RST))) {
        enum EL3RST = 47;
    }




    static if(!is(typeof(EL3HLT))) {
        enum EL3HLT = 46;
    }




    static if(!is(typeof(EL2NSYNC))) {
        enum EL2NSYNC = 45;
    }




    static if(!is(typeof(ECHRNG))) {
        enum ECHRNG = 44;
    }




    static if(!is(typeof(EIDRM))) {
        enum EIDRM = 43;
    }




    static if(!is(typeof(ENOMSG))) {
        enum ENOMSG = 42;
    }






    static if(!is(typeof(ELOOP))) {
        enum ELOOP = 40;
    }




    static if(!is(typeof(ENOTEMPTY))) {
        enum ENOTEMPTY = 39;
    }




    static if(!is(typeof(ENOSYS))) {
        enum ENOSYS = 38;
    }




    static if(!is(typeof(ENOLCK))) {
        enum ENOLCK = 37;
    }




    static if(!is(typeof(ENAMETOOLONG))) {
        enum ENAMETOOLONG = 36;
    }




    static if(!is(typeof(EDEADLK))) {
        enum EDEADLK = 35;
    }






    static if(!is(typeof(ERANGE))) {
        enum ERANGE = 34;
    }




    static if(!is(typeof(EDOM))) {
        enum EDOM = 33;
    }




    static if(!is(typeof(EPIPE))) {
        enum EPIPE = 32;
    }




    static if(!is(typeof(_SYS_TIME_H))) {
        enum _SYS_TIME_H = 1;
    }




    static if(!is(typeof(EMLINK))) {
        enum EMLINK = 31;
    }




    static if(!is(typeof(EROFS))) {
        enum EROFS = 30;
    }




    static if(!is(typeof(ESPIPE))) {
        enum ESPIPE = 29;
    }




    static if(!is(typeof(ENOSPC))) {
        enum ENOSPC = 28;
    }




    static if(!is(typeof(EFBIG))) {
        enum EFBIG = 27;
    }






    static if(!is(typeof(ETXTBSY))) {
        enum ETXTBSY = 26;
    }




    static if(!is(typeof(ENOTTY))) {
        enum ENOTTY = 25;
    }




    static if(!is(typeof(EMFILE))) {
        enum EMFILE = 24;
    }




    static if(!is(typeof(ENFILE))) {
        enum ENFILE = 23;
    }




    static if(!is(typeof(EINVAL))) {
        enum EINVAL = 22;
    }




    static if(!is(typeof(EISDIR))) {
        enum EISDIR = 21;
    }




    static if(!is(typeof(ENOTDIR))) {
        enum ENOTDIR = 20;
    }




    static if(!is(typeof(ENODEV))) {
        enum ENODEV = 19;
    }




    static if(!is(typeof(EXDEV))) {
        enum EXDEV = 18;
    }




    static if(!is(typeof(EEXIST))) {
        enum EEXIST = 17;
    }




    static if(!is(typeof(EBUSY))) {
        enum EBUSY = 16;
    }




    static if(!is(typeof(ENOTBLK))) {
        enum ENOTBLK = 15;
    }




    static if(!is(typeof(EFAULT))) {
        enum EFAULT = 14;
    }




    static if(!is(typeof(EACCES))) {
        enum EACCES = 13;
    }
    static if(!is(typeof(ENOMEM))) {
        enum ENOMEM = 12;
    }




    static if(!is(typeof(EAGAIN))) {
        enum EAGAIN = 11;
    }




    static if(!is(typeof(ECHILD))) {
        enum ECHILD = 10;
    }




    static if(!is(typeof(EBADF))) {
        enum EBADF = 9;
    }




    static if(!is(typeof(ENOEXEC))) {
        enum ENOEXEC = 8;
    }




    static if(!is(typeof(E2BIG))) {
        enum E2BIG = 7;
    }




    static if(!is(typeof(ENXIO))) {
        enum ENXIO = 6;
    }




    static if(!is(typeof(EIO))) {
        enum EIO = 5;
    }




    static if(!is(typeof(EINTR))) {
        enum EINTR = 4;
    }




    static if(!is(typeof(ESRCH))) {
        enum ESRCH = 3;
    }




    static if(!is(typeof(ENOENT))) {
        enum ENOENT = 2;
    }




    static if(!is(typeof(EPERM))) {
        enum EPERM = 1;
    }
    static if(!is(typeof(_ALLOCA_H))) {
        enum _ALLOCA_H = 1;
    }
    static if(!is(typeof(_SYS_TYPES_H))) {
        enum _SYS_TYPES_H = 1;
    }
    static if(!is(typeof(BSON_ERROR_BUFFER_SIZE))) {
        enum BSON_ERROR_BUFFER_SIZE = 504;
    }
    static if(!is(typeof(BSON_ERROR_READER_BADFD))) {
        enum BSON_ERROR_READER_BADFD = 1;
    }
    static if(!is(typeof(__BIT_TYPES_DEFINED__))) {
        enum __BIT_TYPES_DEFINED__ = 1;
    }
    static if(!is(typeof(BSON_WORD_SIZE))) {
        enum BSON_WORD_SIZE = 64;
    }
    static if(!is(typeof(_TIME_H))) {
        enum _TIME_H = 1;
    }
    static if(!is(typeof(TIME_UTC))) {
        enum TIME_UTC = 1;
    }
    static if(!is(typeof(BSON_ERROR_INVALID))) {
        enum BSON_ERROR_INVALID = 3;
    }




    static if(!is(typeof(BSON_ERROR_READER))) {
        enum BSON_ERROR_READER = 2;
    }




    static if(!is(typeof(BSON_ERROR_JSON))) {
        enum BSON_ERROR_JSON = 1;
    }
    static if(!is(typeof(BSON_LITTLE_ENDIAN))) {
        enum BSON_LITTLE_ENDIAN = 1234;
    }




    static if(!is(typeof(BSON_BIG_ENDIAN))) {
        enum BSON_BIG_ENDIAN = 4321;
    }






    static if(!is(typeof(BSON_DECIMAL128_NAN))) {
        enum BSON_DECIMAL128_NAN = "NaN";
    }




    static if(!is(typeof(BSON_DECIMAL128_INF))) {
        enum BSON_DECIMAL128_INF = "Infinity";
    }




    static if(!is(typeof(BSON_DECIMAL128_STRING))) {
        enum BSON_DECIMAL128_STRING = 43;
    }
    static if(!is(typeof(_UNISTD_H))) {
        enum _UNISTD_H = 1;
    }
    static if(!is(typeof(_POSIX_VERSION))) {
        enum _POSIX_VERSION = 200809L;
    }






    static if(!is(typeof(__POSIX2_THIS_VERSION))) {
        enum __POSIX2_THIS_VERSION = 200809L;
    }
    static if(!is(typeof(_XOPEN_VERSION))) {
        enum _XOPEN_VERSION = 700;
    }




    static if(!is(typeof(_XOPEN_XCU_VERSION))) {
        enum _XOPEN_XCU_VERSION = 4;
    }




    static if(!is(typeof(_XOPEN_XPG2))) {
        enum _XOPEN_XPG2 = 1;
    }




    static if(!is(typeof(_XOPEN_XPG3))) {
        enum _XOPEN_XPG3 = 1;
    }




    static if(!is(typeof(_XOPEN_XPG4))) {
        enum _XOPEN_XPG4 = 1;
    }




    static if(!is(typeof(_XOPEN_UNIX))) {
        enum _XOPEN_UNIX = 1;
    }




    static if(!is(typeof(_XOPEN_ENH_I18N))) {
        enum _XOPEN_ENH_I18N = 1;
    }




    static if(!is(typeof(_XOPEN_LEGACY))) {
        enum _XOPEN_LEGACY = 1;
    }
    static if(!is(typeof(STDIN_FILENO))) {
        enum STDIN_FILENO = 0;
    }




    static if(!is(typeof(STDOUT_FILENO))) {
        enum STDOUT_FILENO = 1;
    }




    static if(!is(typeof(STDERR_FILENO))) {
        enum STDERR_FILENO = 2;
    }
    static if(!is(typeof(R_OK))) {
        enum R_OK = 4;
    }




    static if(!is(typeof(W_OK))) {
        enum W_OK = 2;
    }




    static if(!is(typeof(X_OK))) {
        enum X_OK = 1;
    }




    static if(!is(typeof(F_OK))) {
        enum F_OK = 0;
    }
    static if(!is(typeof(BCON_STACK_MAX))) {
        enum BCON_STACK_MAX = 100;
    }
    static if(!is(typeof(BSON_VERSION_S))) {
        enum BSON_VERSION_S = "1.11.1-pre";
    }
    static if(!is(typeof(BSON_HAVE_RAND_R))) {
        enum BSON_HAVE_RAND_R = 1;
    }




    static if(!is(typeof(BSON_HAVE_SYSCALL_TID))) {
        enum BSON_HAVE_SYSCALL_TID = 1;
    }




    static if(!is(typeof(BSON_EXTRA_ALIGN))) {
        enum BSON_EXTRA_ALIGN = 1;
    }




    static if(!is(typeof(BSON_HAVE_TIMESPEC))) {
        enum BSON_HAVE_TIMESPEC = 1;
    }




    static if(!is(typeof(BSON_HAVE_REALLOCF))) {
        enum BSON_HAVE_REALLOCF = 0;
    }




    static if(!is(typeof(BSON_HAVE_GMTIME_R))) {
        enum BSON_HAVE_GMTIME_R = 1;
    }




    static if(!is(typeof(BSON_HAVE_SNPRINTF))) {
        enum BSON_HAVE_SNPRINTF = 1;
    }




    static if(!is(typeof(BSON_HAVE_STRNLEN))) {
        enum BSON_HAVE_STRNLEN = 1;
    }




    static if(!is(typeof(BSON_HAVE_STRINGS_H))) {
        enum BSON_HAVE_STRINGS_H = 1;
    }




    static if(!is(typeof(BSON_HAVE_CLOCK_GETTIME))) {
        enum BSON_HAVE_CLOCK_GETTIME = 1;
    }




    static if(!is(typeof(BSON_HAVE_ATOMIC_64_ADD_AND_FETCH))) {
        enum BSON_HAVE_ATOMIC_64_ADD_AND_FETCH = 1;
    }




    static if(!is(typeof(BSON_HAVE_ATOMIC_32_ADD_AND_FETCH))) {
        enum BSON_HAVE_ATOMIC_32_ADD_AND_FETCH = 1;
    }




    static if(!is(typeof(BSON_OS))) {
        enum BSON_OS = 1;
    }




    static if(!is(typeof(BSON_HAVE_STDBOOL_H))) {
        enum BSON_HAVE_STDBOOL_H = 1;
    }




    static if(!is(typeof(BSON_BYTE_ORDER))) {
        enum BSON_BYTE_ORDER = 1234;
    }






    static if(!is(typeof(F_ULOCK))) {
        enum F_ULOCK = 0;
    }




    static if(!is(typeof(F_LOCK))) {
        enum F_LOCK = 1;
    }




    static if(!is(typeof(F_TLOCK))) {
        enum F_TLOCK = 2;
    }




    static if(!is(typeof(F_TEST))) {
        enum F_TEST = 3;
    }
    static if(!is(typeof(__GNUC_VA_LIST))) {
        enum __GNUC_VA_LIST = 1;
    }
    static if(!is(typeof(true_))) {
        enum true_ = 1;
    }




    static if(!is(typeof(false_))) {
        enum false_ = 0;
    }




    static if(!is(typeof(__bool_true_false_are_defined))) {
        enum __bool_true_false_are_defined = 1;
    }
}


struct __va_list_tag;
