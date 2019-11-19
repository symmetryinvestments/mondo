


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
    alias intptr_t = c_long;
    alias pid_t = int;
    alias useconds_t = uint;
    alias uid_t = uint;
    alias gid_t = uint;
    int timespec_get(timespec*, int) @nogc nothrow;
    int timer_getoverrun(void*) @nogc nothrow;
    int timer_gettime(void*, itimerspec*) @nogc nothrow;
    int timer_settime(void*, int, const(itimerspec)*, itimerspec*) @nogc nothrow;
    int timer_delete(void*) @nogc nothrow;
    int timer_create(int, sigevent*, void**) @nogc nothrow;
    int clock_getcpuclockid(int, int*) @nogc nothrow;
    int clock_nanosleep(int, int, const(timespec)*, timespec*) @nogc nothrow;
    int clock_settime(int, const(timespec)*) @nogc nothrow;
    int clock_gettime(int, timespec*) @nogc nothrow;
    int clock_getres(int, timespec*) @nogc nothrow;
    int nanosleep(const(timespec)*, timespec*) @nogc nothrow;
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
    int dysize(int) @nogc nothrow;
    c_long timelocal(tm*) @nogc nothrow;
    c_long timegm(tm*) @nogc nothrow;
    const(char)* bson_bcon_magic() @nogc nothrow;
    const(char)* bson_bcone_magic() @nogc nothrow;
    int stime(const(c_long)*) @nogc nothrow;
    pragma(mangle, "timezone") extern __gshared c_long timezone_;
    c_long bson_get_monotonic_time() @nogc nothrow;
    int bson_gettimeofday(timeval*) @nogc nothrow;
    extern __gshared int daylight;
    _bson_context_t* bson_context_new(bson_context_flags_t) @nogc nothrow;
    void bson_context_destroy(_bson_context_t*) @nogc nothrow;
    _bson_context_t* bson_context_get_default() @nogc nothrow;
    void tzset() @nogc nothrow;
    extern __gshared char*[2] tzname;
    extern __gshared c_long __timezone;
    void bson_decimal128_to_string(const(bson_decimal128_t)*, char*) @nogc nothrow;
    bool bson_decimal128_from_string(const(char)*, bson_decimal128_t*) @nogc nothrow;
    bool bson_decimal128_from_string_w_len(const(char)*, int, bson_decimal128_t*) @nogc nothrow;
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
    static ushort __bson_uint16_swap_slow(ushort) @nogc nothrow;
    static uint __bson_uint32_swap_slow(uint) @nogc nothrow;
    static c_ulong __bson_uint64_swap_slow(c_ulong) @nogc nothrow;
    alias static_assert_test_210sizeof_uint64_t = char[1];
    static double __bson_double_swap_slow(double) @nogc nothrow;
    c_ulong strftime_l(char*, c_ulong, const(char)*, const(tm)*, __locale_struct*) @nogc nothrow;
    void bson_set_error(_bson_error_t*, uint, uint, const(char)*, ...) @nogc nothrow;
    char* bson_strerror_r(int, char*, c_ulong) @nogc nothrow;
    c_ulong strftime(char*, c_ulong, const(char)*, const(tm)*) @nogc nothrow;
    c_long mktime(tm*) @nogc nothrow;
    double difftime(c_long, c_long) @nogc nothrow;
    c_long time(c_long*) @nogc nothrow;
    c_long clock() @nogc nothrow;
    struct sigevent;
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
    c_ulong bson_uint32_to_string(uint, const(char)**, char*, c_ulong) @nogc nothrow;
    struct sockaddr_un
    {
        ushort sun_family;
        char[108] sun_path;
    }
    c_long pwritev(int, const(iovec)*, int, c_long) @nogc nothrow;
    c_long preadv(int, const(iovec)*, int, c_long) @nogc nothrow;
    c_long writev(int, const(iovec)*, int) @nogc nothrow;
    c_long readv(int, const(iovec)*, int) @nogc nothrow;
    alias fsfilcnt_t = c_ulong;
    alias fsblkcnt_t = c_ulong;
    alias blkcnt_t = c_long;
    alias blksize_t = c_long;
    alias register_t = c_long;
    alias u_int64_t = c_ulong;
    alias u_int32_t = uint;
    struct bson_md5_t
    {
        uint[2] count;
        uint[4] abcd;
        ubyte[64] buf;
    }
    void bson_md5_init(bson_md5_t*) @nogc nothrow;
    void bson_md5_append(bson_md5_t*, const(ubyte)*, uint) @nogc nothrow;
    void bson_md5_finish(bson_md5_t*, ubyte*) @nogc nothrow;
    alias u_int16_t = ushort;
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
    alias u_int8_t = ubyte;
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
    _bson_t* bson_new_from_json(const(ubyte)*, c_long, _bson_error_t*) @nogc nothrow;
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
    int futimes(int, const(timeval)*) @nogc nothrow;
    alias mongoc_apm_callbacks_t = _mongoc_apm_callbacks_t;
    struct _mongoc_apm_callbacks_t;
    alias mongoc_apm_command_started_t = _mongoc_apm_command_started_t;
    struct _mongoc_apm_command_started_t;
    alias mongoc_apm_command_succeeded_t = _mongoc_apm_command_succeeded_t;
    struct _mongoc_apm_command_succeeded_t;
    alias mongoc_apm_command_failed_t = _mongoc_apm_command_failed_t;
    struct _mongoc_apm_command_failed_t;
    alias mongoc_apm_server_changed_t = _mongoc_apm_server_changed_t;
    struct _mongoc_apm_server_changed_t;
    alias mongoc_apm_server_opening_t = _mongoc_apm_server_opening_t;
    struct _mongoc_apm_server_opening_t;
    alias mongoc_apm_server_closed_t = _mongoc_apm_server_closed_t;
    struct _mongoc_apm_server_closed_t;
    alias mongoc_apm_topology_changed_t = _mongoc_apm_topology_changed_t;
    struct _mongoc_apm_topology_changed_t;
    alias mongoc_apm_topology_opening_t = _mongoc_apm_topology_opening_t;
    struct _mongoc_apm_topology_opening_t;
    alias mongoc_apm_topology_closed_t = _mongoc_apm_topology_closed_t;
    struct _mongoc_apm_topology_closed_t;
    alias mongoc_apm_server_heartbeat_started_t = _mongoc_apm_server_heartbeat_started_t;
    struct _mongoc_apm_server_heartbeat_started_t;
    alias mongoc_apm_server_heartbeat_succeeded_t = _mongoc_apm_server_heartbeat_succeeded_t;
    struct _mongoc_apm_server_heartbeat_succeeded_t;
    alias mongoc_apm_server_heartbeat_failed_t = _mongoc_apm_server_heartbeat_failed_t;
    struct _mongoc_apm_server_heartbeat_failed_t;
    const(_bson_t)* mongoc_apm_command_started_get_command(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    const(char)* mongoc_apm_command_started_get_database_name(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    const(char)* mongoc_apm_command_started_get_command_name(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    c_long mongoc_apm_command_started_get_request_id(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    c_long mongoc_apm_command_started_get_operation_id(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_command_started_get_host(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    uint mongoc_apm_command_started_get_server_id(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    void* mongoc_apm_command_started_get_context(const(_mongoc_apm_command_started_t)*) @nogc nothrow;
    c_long mongoc_apm_command_succeeded_get_duration(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_apm_command_succeeded_get_reply(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    const(char)* mongoc_apm_command_succeeded_get_command_name(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    c_long mongoc_apm_command_succeeded_get_request_id(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    c_long mongoc_apm_command_succeeded_get_operation_id(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_command_succeeded_get_host(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    uint mongoc_apm_command_succeeded_get_server_id(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    void* mongoc_apm_command_succeeded_get_context(const(_mongoc_apm_command_succeeded_t)*) @nogc nothrow;
    c_long mongoc_apm_command_failed_get_duration(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    const(char)* mongoc_apm_command_failed_get_command_name(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    void mongoc_apm_command_failed_get_error(const(_mongoc_apm_command_failed_t)*, _bson_error_t*) @nogc nothrow;
    const(_bson_t)* mongoc_apm_command_failed_get_reply(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    c_long mongoc_apm_command_failed_get_request_id(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    c_long mongoc_apm_command_failed_get_operation_id(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_command_failed_get_host(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    uint mongoc_apm_command_failed_get_server_id(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    void* mongoc_apm_command_failed_get_context(const(_mongoc_apm_command_failed_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_server_changed_get_host(const(_mongoc_apm_server_changed_t)*) @nogc nothrow;
    void mongoc_apm_server_changed_get_topology_id(const(_mongoc_apm_server_changed_t)*, bson_oid_t*) @nogc nothrow;
    const(_mongoc_server_description_t)* mongoc_apm_server_changed_get_previous_description(const(_mongoc_apm_server_changed_t)*) @nogc nothrow;
    const(_mongoc_server_description_t)* mongoc_apm_server_changed_get_new_description(const(_mongoc_apm_server_changed_t)*) @nogc nothrow;
    void* mongoc_apm_server_changed_get_context(const(_mongoc_apm_server_changed_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_server_opening_get_host(const(_mongoc_apm_server_opening_t)*) @nogc nothrow;
    void mongoc_apm_server_opening_get_topology_id(const(_mongoc_apm_server_opening_t)*, bson_oid_t*) @nogc nothrow;
    void* mongoc_apm_server_opening_get_context(const(_mongoc_apm_server_opening_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_server_closed_get_host(const(_mongoc_apm_server_closed_t)*) @nogc nothrow;
    void mongoc_apm_server_closed_get_topology_id(const(_mongoc_apm_server_closed_t)*, bson_oid_t*) @nogc nothrow;
    void* mongoc_apm_server_closed_get_context(const(_mongoc_apm_server_closed_t)*) @nogc nothrow;
    void mongoc_apm_topology_changed_get_topology_id(const(_mongoc_apm_topology_changed_t)*, bson_oid_t*) @nogc nothrow;
    const(_mongoc_topology_description_t)* mongoc_apm_topology_changed_get_previous_description(const(_mongoc_apm_topology_changed_t)*) @nogc nothrow;
    const(_mongoc_topology_description_t)* mongoc_apm_topology_changed_get_new_description(const(_mongoc_apm_topology_changed_t)*) @nogc nothrow;
    void* mongoc_apm_topology_changed_get_context(const(_mongoc_apm_topology_changed_t)*) @nogc nothrow;
    void mongoc_apm_topology_opening_get_topology_id(const(_mongoc_apm_topology_opening_t)*, bson_oid_t*) @nogc nothrow;
    void* mongoc_apm_topology_opening_get_context(const(_mongoc_apm_topology_opening_t)*) @nogc nothrow;
    void mongoc_apm_topology_closed_get_topology_id(const(_mongoc_apm_topology_closed_t)*, bson_oid_t*) @nogc nothrow;
    void* mongoc_apm_topology_closed_get_context(const(_mongoc_apm_topology_closed_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_server_heartbeat_started_get_host(const(_mongoc_apm_server_heartbeat_started_t)*) @nogc nothrow;
    void* mongoc_apm_server_heartbeat_started_get_context(const(_mongoc_apm_server_heartbeat_started_t)*) @nogc nothrow;
    c_long mongoc_apm_server_heartbeat_succeeded_get_duration(const(_mongoc_apm_server_heartbeat_succeeded_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_apm_server_heartbeat_succeeded_get_reply(const(_mongoc_apm_server_heartbeat_succeeded_t)*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_server_heartbeat_succeeded_get_host(const(_mongoc_apm_server_heartbeat_succeeded_t)*) @nogc nothrow;
    void* mongoc_apm_server_heartbeat_succeeded_get_context(const(_mongoc_apm_server_heartbeat_succeeded_t)*) @nogc nothrow;
    c_long mongoc_apm_server_heartbeat_failed_get_duration(const(_mongoc_apm_server_heartbeat_failed_t)*) @nogc nothrow;
    void mongoc_apm_server_heartbeat_failed_get_error(const(_mongoc_apm_server_heartbeat_failed_t)*, _bson_error_t*) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_apm_server_heartbeat_failed_get_host(const(_mongoc_apm_server_heartbeat_failed_t)*) @nogc nothrow;
    void* mongoc_apm_server_heartbeat_failed_get_context(const(_mongoc_apm_server_heartbeat_failed_t)*) @nogc nothrow;
    alias mongoc_apm_command_started_cb_t = void function(const(_mongoc_apm_command_started_t)*);
    alias mongoc_apm_command_succeeded_cb_t = void function(const(_mongoc_apm_command_succeeded_t)*);
    alias mongoc_apm_command_failed_cb_t = void function(const(_mongoc_apm_command_failed_t)*);
    alias mongoc_apm_server_changed_cb_t = void function(const(_mongoc_apm_server_changed_t)*);
    alias mongoc_apm_server_opening_cb_t = void function(const(_mongoc_apm_server_opening_t)*);
    alias mongoc_apm_server_closed_cb_t = void function(const(_mongoc_apm_server_closed_t)*);
    alias mongoc_apm_topology_changed_cb_t = void function(const(_mongoc_apm_topology_changed_t)*);
    alias mongoc_apm_topology_opening_cb_t = void function(const(_mongoc_apm_topology_opening_t)*);
    alias mongoc_apm_topology_closed_cb_t = void function(const(_mongoc_apm_topology_closed_t)*);
    alias mongoc_apm_server_heartbeat_started_cb_t = void function(const(_mongoc_apm_server_heartbeat_started_t)*);
    alias mongoc_apm_server_heartbeat_succeeded_cb_t = void function(const(_mongoc_apm_server_heartbeat_succeeded_t)*);
    alias mongoc_apm_server_heartbeat_failed_cb_t = void function(const(_mongoc_apm_server_heartbeat_failed_t)*);
    _mongoc_apm_callbacks_t* mongoc_apm_callbacks_new() @nogc nothrow;
    void mongoc_apm_callbacks_destroy(_mongoc_apm_callbacks_t*) @nogc nothrow;
    void mongoc_apm_set_command_started_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_command_started_t)*)) @nogc nothrow;
    void mongoc_apm_set_command_succeeded_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_command_succeeded_t)*)) @nogc nothrow;
    void mongoc_apm_set_command_failed_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_command_failed_t)*)) @nogc nothrow;
    void mongoc_apm_set_server_changed_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_server_changed_t)*)) @nogc nothrow;
    void mongoc_apm_set_server_opening_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_server_opening_t)*)) @nogc nothrow;
    void mongoc_apm_set_server_closed_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_server_closed_t)*)) @nogc nothrow;
    void mongoc_apm_set_topology_changed_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_topology_changed_t)*)) @nogc nothrow;
    void mongoc_apm_set_topology_opening_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_topology_opening_t)*)) @nogc nothrow;
    void mongoc_apm_set_topology_closed_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_topology_closed_t)*)) @nogc nothrow;
    void mongoc_apm_set_server_heartbeat_started_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_server_heartbeat_started_t)*)) @nogc nothrow;
    void mongoc_apm_set_server_heartbeat_succeeded_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_server_heartbeat_succeeded_t)*)) @nogc nothrow;
    void mongoc_apm_set_server_heartbeat_failed_cb(_mongoc_apm_callbacks_t*, void function(const(_mongoc_apm_server_heartbeat_failed_t)*)) @nogc nothrow;
    struct _mongoc_client_session_t;
    alias mongoc_bulk_operation_t = _mongoc_bulk_operation_t;
    struct _mongoc_bulk_operation_t;
    alias mongoc_bulk_write_flags_t = _mongoc_bulk_write_flags_t;
    struct _mongoc_bulk_write_flags_t;
    void mongoc_bulk_operation_destroy(_mongoc_bulk_operation_t*) @nogc nothrow;
    uint mongoc_bulk_operation_execute(_mongoc_bulk_operation_t*, _bson_t*, _bson_error_t*) @nogc nothrow;
    void mongoc_bulk_operation_delete(_mongoc_bulk_operation_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_bulk_operation_delete_one(_mongoc_bulk_operation_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_bulk_operation_insert(_mongoc_bulk_operation_t*, const(_bson_t)*) @nogc nothrow;
    bool mongoc_bulk_operation_insert_with_opts(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    void mongoc_bulk_operation_remove(_mongoc_bulk_operation_t*, const(_bson_t)*) @nogc nothrow;
    bool mongoc_bulk_operation_remove_many_with_opts(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    void mongoc_bulk_operation_remove_one(_mongoc_bulk_operation_t*, const(_bson_t)*) @nogc nothrow;
    bool mongoc_bulk_operation_remove_one_with_opts(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    void mongoc_bulk_operation_replace_one(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, bool) @nogc nothrow;
    bool mongoc_bulk_operation_replace_one_with_opts(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    void mongoc_bulk_operation_update(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, bool) @nogc nothrow;
    bool mongoc_bulk_operation_update_many_with_opts(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    void mongoc_bulk_operation_update_one(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, bool) @nogc nothrow;
    bool mongoc_bulk_operation_update_one_with_opts(_mongoc_bulk_operation_t*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    void mongoc_bulk_operation_set_bypass_document_validation(_mongoc_bulk_operation_t*, bool) @nogc nothrow;
    _mongoc_bulk_operation_t* mongoc_bulk_operation_new(bool) @nogc nothrow;
    void mongoc_bulk_operation_set_write_concern(_mongoc_bulk_operation_t*, const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_bulk_operation_set_database(_mongoc_bulk_operation_t*, const(char)*) @nogc nothrow;
    void mongoc_bulk_operation_set_collection(_mongoc_bulk_operation_t*, const(char)*) @nogc nothrow;
    void mongoc_bulk_operation_set_client(_mongoc_bulk_operation_t*, void*) @nogc nothrow;
    void mongoc_bulk_operation_set_client_session(_mongoc_bulk_operation_t*, _mongoc_client_session_t*) @nogc nothrow;
    void mongoc_bulk_operation_set_hint(_mongoc_bulk_operation_t*, uint) @nogc nothrow;
    uint mongoc_bulk_operation_get_hint(const(_mongoc_bulk_operation_t)*) @nogc nothrow;
    const(_mongoc_write_concern_t)* mongoc_bulk_operation_get_write_concern(const(_mongoc_bulk_operation_t)*) @nogc nothrow;
    int lutimes(const(char)*, const(timeval)*) @nogc nothrow;
    alias mongoc_change_stream_t = _mongoc_change_stream_t;
    struct _mongoc_change_stream_t;
    void mongoc_change_stream_destroy(_mongoc_change_stream_t*) @nogc nothrow;
    const(_bson_t)* mongoc_change_stream_get_resume_token(_mongoc_change_stream_t*) @nogc nothrow;
    bool mongoc_change_stream_next(_mongoc_change_stream_t*, const(_bson_t)**) @nogc nothrow;
    bool mongoc_change_stream_error_document(const(_mongoc_change_stream_t)*, _bson_error_t*, const(_bson_t)**) @nogc nothrow;
    alias mongoc_client_pool_t = _mongoc_client_pool_t;
    struct _mongoc_client_pool_t;
    _mongoc_client_pool_t* mongoc_client_pool_new(const(_mongoc_uri_t)*) @nogc nothrow;
    void mongoc_client_pool_destroy(_mongoc_client_pool_t*) @nogc nothrow;
    _mongoc_client_t* mongoc_client_pool_pop(_mongoc_client_pool_t*) @nogc nothrow;
    void mongoc_client_pool_push(_mongoc_client_pool_t*, _mongoc_client_t*) @nogc nothrow;
    _mongoc_client_t* mongoc_client_pool_try_pop(_mongoc_client_pool_t*) @nogc nothrow;
    void mongoc_client_pool_max_size(_mongoc_client_pool_t*, uint) @nogc nothrow;
    void mongoc_client_pool_min_size(_mongoc_client_pool_t*, uint) @nogc nothrow;
    void mongoc_client_pool_set_ssl_opts(_mongoc_client_pool_t*, const(_mongoc_ssl_opt_t)*) @nogc nothrow;
    bool mongoc_client_pool_set_apm_callbacks(_mongoc_client_pool_t*, _mongoc_apm_callbacks_t*, void*) @nogc nothrow;
    bool mongoc_client_pool_set_error_api(_mongoc_client_pool_t*, int) @nogc nothrow;
    bool mongoc_client_pool_set_appname(_mongoc_client_pool_t*, const(char)*) @nogc nothrow;
    alias mongoc_client_session_with_transaction_cb_t = bool function(_mongoc_client_session_t*, void*, _bson_t**, _bson_error_t*);
    _mongoc_transaction_opt_t* mongoc_transaction_opts_new() @nogc nothrow;
    _mongoc_transaction_opt_t* mongoc_transaction_opts_clone(const(_mongoc_transaction_opt_t)*) @nogc nothrow;
    void mongoc_transaction_opts_destroy(_mongoc_transaction_opt_t*) @nogc nothrow;
    void mongoc_transaction_opts_set_max_commit_time_ms(_mongoc_transaction_opt_t*, c_long) @nogc nothrow;
    c_long mongoc_transaction_opts_get_max_commit_time_ms(_mongoc_transaction_opt_t*) @nogc nothrow;
    void mongoc_transaction_opts_set_read_concern(_mongoc_transaction_opt_t*, const(_mongoc_read_concern_t)*) @nogc nothrow;
    const(_mongoc_read_concern_t)* mongoc_transaction_opts_get_read_concern(const(_mongoc_transaction_opt_t)*) @nogc nothrow;
    void mongoc_transaction_opts_set_write_concern(_mongoc_transaction_opt_t*, const(_mongoc_write_concern_t)*) @nogc nothrow;
    const(_mongoc_write_concern_t)* mongoc_transaction_opts_get_write_concern(const(_mongoc_transaction_opt_t)*) @nogc nothrow;
    void mongoc_transaction_opts_set_read_prefs(_mongoc_transaction_opt_t*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    const(_mongoc_read_prefs_t)* mongoc_transaction_opts_get_read_prefs(const(_mongoc_transaction_opt_t)*) @nogc nothrow;
    _mongoc_session_opt_t* mongoc_session_opts_new() @nogc nothrow;
    void mongoc_session_opts_set_causal_consistency(_mongoc_session_opt_t*, bool) @nogc nothrow;
    bool mongoc_session_opts_get_causal_consistency(const(_mongoc_session_opt_t)*) @nogc nothrow;
    void mongoc_session_opts_set_default_transaction_opts(_mongoc_session_opt_t*, const(_mongoc_transaction_opt_t)*) @nogc nothrow;
    const(_mongoc_transaction_opt_t)* mongoc_session_opts_get_default_transaction_opts(const(_mongoc_session_opt_t)*) @nogc nothrow;
    _mongoc_transaction_opt_t* mongoc_session_opts_get_transaction_opts(const(_mongoc_client_session_t)*) @nogc nothrow;
    _mongoc_session_opt_t* mongoc_session_opts_clone(const(_mongoc_session_opt_t)*) @nogc nothrow;
    void mongoc_session_opts_destroy(_mongoc_session_opt_t*) @nogc nothrow;
    _mongoc_client_t* mongoc_client_session_get_client(const(_mongoc_client_session_t)*) @nogc nothrow;
    const(_mongoc_session_opt_t)* mongoc_client_session_get_opts(const(_mongoc_client_session_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_client_session_get_lsid(const(_mongoc_client_session_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_client_session_get_cluster_time(const(_mongoc_client_session_t)*) @nogc nothrow;
    void mongoc_client_session_advance_cluster_time(_mongoc_client_session_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_client_session_get_operation_time(const(_mongoc_client_session_t)*, uint*, uint*) @nogc nothrow;
    uint mongoc_client_session_get_server_id(const(_mongoc_client_session_t)*) @nogc nothrow;
    void mongoc_client_session_advance_operation_time(_mongoc_client_session_t*, uint, uint) @nogc nothrow;
    bool mongoc_client_session_with_transaction(_mongoc_client_session_t*, bool function(_mongoc_client_session_t*, void*, _bson_t**, _bson_error_t*), const(_mongoc_transaction_opt_t)*, void*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_session_start_transaction(_mongoc_client_session_t*, const(_mongoc_transaction_opt_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_session_in_transaction(const(_mongoc_client_session_t)*) @nogc nothrow;
    bool mongoc_client_session_commit_transaction(_mongoc_client_session_t*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_session_abort_transaction(_mongoc_client_session_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_session_append(const(_mongoc_client_session_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    void mongoc_client_session_destroy(_mongoc_client_session_t*) @nogc nothrow;
    int utimes(const(char)*, const(timeval)*) @nogc nothrow;
    int setitimer(int, const(itimerval)*, itimerval*) @nogc nothrow;
    alias mongoc_client_t = _mongoc_client_t;
    alias mongoc_client_session_t = _mongoc_client_session_t;
    alias mongoc_session_opt_t = _mongoc_session_opt_t;
    struct _mongoc_session_opt_t;
    alias mongoc_transaction_opt_t = _mongoc_transaction_opt_t;
    struct _mongoc_transaction_opt_t;
    alias mongoc_stream_initiator_t = _mongoc_stream_t* function(const(_mongoc_uri_t)*, const(_mongoc_host_list_t)*, void*, _bson_error_t*);
    _mongoc_client_t* mongoc_client_new(const(char)*) @nogc nothrow;
    _mongoc_client_t* mongoc_client_new_from_uri(const(_mongoc_uri_t)*) @nogc nothrow;
    const(_mongoc_uri_t)* mongoc_client_get_uri(const(_mongoc_client_t)*) @nogc nothrow;
    void mongoc_client_set_stream_initiator(_mongoc_client_t*, _mongoc_stream_t* function(const(_mongoc_uri_t)*, const(_mongoc_host_list_t)*, void*, _bson_error_t*), void*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_client_command(_mongoc_client_t*, const(char)*, mongoc_query_flags_t, uint, uint, uint, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    void mongoc_client_kill_cursor(_mongoc_client_t*, c_long) @nogc nothrow;
    bool mongoc_client_command_simple(_mongoc_client_t*, const(char)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_read_command_with_opts(_mongoc_client_t*, const(char)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_write_command_with_opts(_mongoc_client_t*, const(char)*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_read_write_command_with_opts(_mongoc_client_t*, const(char)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_command_with_opts(_mongoc_client_t*, const(char)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_command_simple_with_server_id(_mongoc_client_t*, const(char)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, uint, _bson_t*, _bson_error_t*) @nogc nothrow;
    void mongoc_client_destroy(_mongoc_client_t*) @nogc nothrow;
    _mongoc_client_session_t* mongoc_client_start_session(_mongoc_client_t*, const(_mongoc_session_opt_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_database_t* mongoc_client_get_database(_mongoc_client_t*, const(char)*) @nogc nothrow;
    _mongoc_database_t* mongoc_client_get_default_database(_mongoc_client_t*) @nogc nothrow;
    _mongoc_gridfs_t* mongoc_client_get_gridfs(_mongoc_client_t*, const(char)*, const(char)*, _bson_error_t*) @nogc nothrow;
    _mongoc_collection_t* mongoc_client_get_collection(_mongoc_client_t*, const(char)*, const(char)*) @nogc nothrow;
    char** mongoc_client_get_database_names(_mongoc_client_t*, _bson_error_t*) @nogc nothrow;
    char** mongoc_client_get_database_names_with_opts(_mongoc_client_t*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_client_find_databases(_mongoc_client_t*, _bson_error_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_client_find_databases_with_opts(_mongoc_client_t*, const(_bson_t)*) @nogc nothrow;
    bool mongoc_client_get_server_status(_mongoc_client_t*, _mongoc_read_prefs_t*, _bson_t*, _bson_error_t*) @nogc nothrow;
    int mongoc_client_get_max_message_size(_mongoc_client_t*) @nogc nothrow;
    int mongoc_client_get_max_bson_size(_mongoc_client_t*) @nogc nothrow;
    const(_mongoc_write_concern_t)* mongoc_client_get_write_concern(const(_mongoc_client_t)*) @nogc nothrow;
    void mongoc_client_set_write_concern(_mongoc_client_t*, const(_mongoc_write_concern_t)*) @nogc nothrow;
    const(_mongoc_read_concern_t)* mongoc_client_get_read_concern(const(_mongoc_client_t)*) @nogc nothrow;
    void mongoc_client_set_read_concern(_mongoc_client_t*, const(_mongoc_read_concern_t)*) @nogc nothrow;
    const(_mongoc_read_prefs_t)* mongoc_client_get_read_prefs(const(_mongoc_client_t)*) @nogc nothrow;
    void mongoc_client_set_read_prefs(_mongoc_client_t*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    void mongoc_client_set_ssl_opts(_mongoc_client_t*, const(_mongoc_ssl_opt_t)*) @nogc nothrow;
    bool mongoc_client_set_apm_callbacks(_mongoc_client_t*, _mongoc_apm_callbacks_t*, void*) @nogc nothrow;
    _mongoc_server_description_t* mongoc_client_get_server_description(_mongoc_client_t*, uint) @nogc nothrow;
    _mongoc_server_description_t** mongoc_client_get_server_descriptions(const(_mongoc_client_t)*, c_ulong*) @nogc nothrow;
    void mongoc_server_descriptions_destroy_all(_mongoc_server_description_t**, c_ulong) @nogc nothrow;
    _mongoc_server_description_t* mongoc_client_select_server(_mongoc_client_t*, bool, const(_mongoc_read_prefs_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_client_set_error_api(_mongoc_client_t*, int) @nogc nothrow;
    bool mongoc_client_set_appname(_mongoc_client_t*, const(char)*) @nogc nothrow;
    _mongoc_change_stream_t* mongoc_client_watch(_mongoc_client_t*, const(_bson_t)*, const(_bson_t)*) @nogc nothrow;
    void mongoc_client_reset(_mongoc_client_t*) @nogc nothrow;
    alias mongoc_collection_t = _mongoc_collection_t;
    struct _mongoc_collection_t;
    _mongoc_cursor_t* mongoc_collection_aggregate(_mongoc_collection_t*, mongoc_query_flags_t, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    void mongoc_collection_destroy(_mongoc_collection_t*) @nogc nothrow;
    _mongoc_collection_t* mongoc_collection_copy(_mongoc_collection_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_collection_command(_mongoc_collection_t*, mongoc_query_flags_t, uint, uint, uint, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    bool mongoc_collection_read_command_with_opts(_mongoc_collection_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_write_command_with_opts(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_read_write_command_with_opts(_mongoc_collection_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_command_with_opts(_mongoc_collection_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_command_simple(_mongoc_collection_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    c_long mongoc_collection_count(_mongoc_collection_t*, mongoc_query_flags_t, const(_bson_t)*, c_long, c_long, const(_mongoc_read_prefs_t)*, _bson_error_t*) @nogc nothrow;
    c_long mongoc_collection_count_with_opts(_mongoc_collection_t*, mongoc_query_flags_t, const(_bson_t)*, c_long, c_long, const(_bson_t)*, const(_mongoc_read_prefs_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_drop(_mongoc_collection_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_drop_with_opts(_mongoc_collection_t*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_drop_index(_mongoc_collection_t*, const(char)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_drop_index_with_opts(_mongoc_collection_t*, const(char)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_create_index(_mongoc_collection_t*, const(_bson_t)*, const(mongoc_index_opt_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_create_index_with_opts(_mongoc_collection_t*, const(_bson_t)*, const(mongoc_index_opt_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_ensure_index(_mongoc_collection_t*, const(_bson_t)*, const(mongoc_index_opt_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_collection_find_indexes(_mongoc_collection_t*, _bson_error_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_collection_find_indexes_with_opts(_mongoc_collection_t*, const(_bson_t)*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_collection_find(_mongoc_collection_t*, mongoc_query_flags_t, uint, uint, uint, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_collection_find_with_opts(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    bool mongoc_collection_insert(_mongoc_collection_t*, mongoc_insert_flags_t, const(_bson_t)*, const(_mongoc_write_concern_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_insert_one(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_insert_many(_mongoc_collection_t*, const(_bson_t)**, c_ulong, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_insert_bulk(_mongoc_collection_t*, mongoc_insert_flags_t, const(_bson_t)**, uint, const(_mongoc_write_concern_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_update(_mongoc_collection_t*, mongoc_update_flags_t, const(_bson_t)*, const(_bson_t)*, const(_mongoc_write_concern_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_update_one(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_update_many(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_replace_one(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_delete(_mongoc_collection_t*, mongoc_delete_flags_t, const(_bson_t)*, const(_mongoc_write_concern_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_save(_mongoc_collection_t*, const(_bson_t)*, const(_mongoc_write_concern_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_remove(_mongoc_collection_t*, mongoc_remove_flags_t, const(_bson_t)*, const(_mongoc_write_concern_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_delete_one(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_delete_many(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_rename(_mongoc_collection_t*, const(char)*, const(char)*, bool, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_rename_with_opts(_mongoc_collection_t*, const(char)*, const(char)*, bool, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_find_and_modify_with_opts(_mongoc_collection_t*, const(_bson_t)*, const(_mongoc_find_and_modify_opts_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_find_and_modify(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, const(_bson_t)*, bool, bool, bool, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_collection_stats(_mongoc_collection_t*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    _mongoc_bulk_operation_t* mongoc_collection_create_bulk_operation(_mongoc_collection_t*, bool, const(_mongoc_write_concern_t)*) @nogc nothrow;
    _mongoc_bulk_operation_t* mongoc_collection_create_bulk_operation_with_opts(_mongoc_collection_t*, const(_bson_t)*) @nogc nothrow;
    const(_mongoc_read_prefs_t)* mongoc_collection_get_read_prefs(const(_mongoc_collection_t)*) @nogc nothrow;
    void mongoc_collection_set_read_prefs(_mongoc_collection_t*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    const(_mongoc_read_concern_t)* mongoc_collection_get_read_concern(const(_mongoc_collection_t)*) @nogc nothrow;
    void mongoc_collection_set_read_concern(_mongoc_collection_t*, const(_mongoc_read_concern_t)*) @nogc nothrow;
    const(_mongoc_write_concern_t)* mongoc_collection_get_write_concern(const(_mongoc_collection_t)*) @nogc nothrow;
    void mongoc_collection_set_write_concern(_mongoc_collection_t*, const(_mongoc_write_concern_t)*) @nogc nothrow;
    const(char)* mongoc_collection_get_name(_mongoc_collection_t*) @nogc nothrow;
    const(_bson_t)* mongoc_collection_get_last_error(const(_mongoc_collection_t)*) @nogc nothrow;
    char* mongoc_collection_keys_to_index_string(const(_bson_t)*) @nogc nothrow;
    bool mongoc_collection_validate(_mongoc_collection_t*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    _mongoc_change_stream_t* mongoc_collection_watch(const(_mongoc_collection_t)*, const(_bson_t)*, const(_bson_t)*) @nogc nothrow;
    c_long mongoc_collection_count_documents(_mongoc_collection_t*, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    c_long mongoc_collection_estimated_document_count(_mongoc_collection_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    int getitimer(int, itimerval*) @nogc nothrow;
    alias mongoc_cursor_t = _mongoc_cursor_t;
    struct _mongoc_cursor_t;
    struct _mongoc_client_t;
    _mongoc_cursor_t* mongoc_cursor_clone(const(_mongoc_cursor_t)*) @nogc nothrow;
    void mongoc_cursor_destroy(_mongoc_cursor_t*) @nogc nothrow;
    bool mongoc_cursor_more(_mongoc_cursor_t*) @nogc nothrow;
    bool mongoc_cursor_next(_mongoc_cursor_t*, const(_bson_t)**) @nogc nothrow;
    bool mongoc_cursor_error(_mongoc_cursor_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_cursor_error_document(_mongoc_cursor_t*, _bson_error_t*, const(_bson_t)**) @nogc nothrow;
    void mongoc_cursor_get_host(_mongoc_cursor_t*, _mongoc_host_list_t*) @nogc nothrow;
    bool mongoc_cursor_is_alive(const(_mongoc_cursor_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_cursor_current(const(_mongoc_cursor_t)*) @nogc nothrow;
    void mongoc_cursor_set_batch_size(_mongoc_cursor_t*, uint) @nogc nothrow;
    uint mongoc_cursor_get_batch_size(const(_mongoc_cursor_t)*) @nogc nothrow;
    bool mongoc_cursor_set_limit(_mongoc_cursor_t*, c_long) @nogc nothrow;
    c_long mongoc_cursor_get_limit(const(_mongoc_cursor_t)*) @nogc nothrow;
    bool mongoc_cursor_set_hint(_mongoc_cursor_t*, uint) @nogc nothrow;
    uint mongoc_cursor_get_hint(const(_mongoc_cursor_t)*) @nogc nothrow;
    c_long mongoc_cursor_get_id(const(_mongoc_cursor_t)*) @nogc nothrow;
    void mongoc_cursor_set_max_await_time_ms(_mongoc_cursor_t*, uint) @nogc nothrow;
    uint mongoc_cursor_get_max_await_time_ms(const(_mongoc_cursor_t)*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_cursor_new_from_command_reply(_mongoc_client_t*, _bson_t*, uint) @nogc nothrow;
    _mongoc_cursor_t* mongoc_cursor_new_from_command_reply_with_opts(_mongoc_client_t*, _bson_t*, const(_bson_t)*) @nogc nothrow;
    alias __itimer_which_t = int;
    alias mongoc_database_t = _mongoc_database_t;
    struct _mongoc_database_t;
    const(char)* mongoc_database_get_name(_mongoc_database_t*) @nogc nothrow;
    bool mongoc_database_remove_user(_mongoc_database_t*, const(char)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_remove_all_users(_mongoc_database_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_add_user(_mongoc_database_t*, const(char)*, const(char)*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    void mongoc_database_destroy(_mongoc_database_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_database_aggregate(_mongoc_database_t*, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    _mongoc_database_t* mongoc_database_copy(_mongoc_database_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_database_command(_mongoc_database_t*, mongoc_query_flags_t, uint, uint, uint, const(_bson_t)*, const(_bson_t)*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    bool mongoc_database_read_command_with_opts(_mongoc_database_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_write_command_with_opts(_mongoc_database_t*, const(_bson_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_read_write_command_with_opts(_mongoc_database_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_command_with_opts(_mongoc_database_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, const(_bson_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_command_simple(_mongoc_database_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, _bson_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_drop(_mongoc_database_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_drop_with_opts(_mongoc_database_t*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_database_has_collection(_mongoc_database_t*, const(char)*, _bson_error_t*) @nogc nothrow;
    _mongoc_collection_t* mongoc_database_create_collection(_mongoc_database_t*, const(char)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    const(_mongoc_read_prefs_t)* mongoc_database_get_read_prefs(const(_mongoc_database_t)*) @nogc nothrow;
    void mongoc_database_set_read_prefs(_mongoc_database_t*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    const(_mongoc_write_concern_t)* mongoc_database_get_write_concern(const(_mongoc_database_t)*) @nogc nothrow;
    void mongoc_database_set_write_concern(_mongoc_database_t*, const(_mongoc_write_concern_t)*) @nogc nothrow;
    const(_mongoc_read_concern_t)* mongoc_database_get_read_concern(const(_mongoc_database_t)*) @nogc nothrow;
    void mongoc_database_set_read_concern(_mongoc_database_t*, const(_mongoc_read_concern_t)*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_database_find_collections(_mongoc_database_t*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_database_find_collections_with_opts(_mongoc_database_t*, const(_bson_t)*) @nogc nothrow;
    char** mongoc_database_get_collection_names(_mongoc_database_t*, _bson_error_t*) @nogc nothrow;
    char** mongoc_database_get_collection_names_with_opts(_mongoc_database_t*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_collection_t* mongoc_database_get_collection(_mongoc_database_t*, const(char)*) @nogc nothrow;
    _mongoc_change_stream_t* mongoc_database_watch(const(_mongoc_database_t)*, const(_bson_t)*, const(_bson_t)*) @nogc nothrow;
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
    alias mongoc_error_domain_t = _Anonymous_16;
    enum _Anonymous_16
    {
        MONGOC_ERROR_CLIENT = 1,
        MONGOC_ERROR_STREAM = 2,
        MONGOC_ERROR_PROTOCOL = 3,
        MONGOC_ERROR_CURSOR = 4,
        MONGOC_ERROR_QUERY = 5,
        MONGOC_ERROR_INSERT = 6,
        MONGOC_ERROR_SASL = 7,
        MONGOC_ERROR_BSON = 8,
        MONGOC_ERROR_MATCHER = 9,
        MONGOC_ERROR_NAMESPACE = 10,
        MONGOC_ERROR_COMMAND = 11,
        MONGOC_ERROR_COLLECTION = 12,
        MONGOC_ERROR_GRIDFS = 13,
        MONGOC_ERROR_SCRAM = 14,
        MONGOC_ERROR_SERVER_SELECTION = 15,
        MONGOC_ERROR_WRITE_CONCERN = 16,
        MONGOC_ERROR_SERVER = 17,
        MONGOC_ERROR_TRANSACTION = 18,
    }
    enum MONGOC_ERROR_CLIENT = _Anonymous_16.MONGOC_ERROR_CLIENT;
    enum MONGOC_ERROR_STREAM = _Anonymous_16.MONGOC_ERROR_STREAM;
    enum MONGOC_ERROR_PROTOCOL = _Anonymous_16.MONGOC_ERROR_PROTOCOL;
    enum MONGOC_ERROR_CURSOR = _Anonymous_16.MONGOC_ERROR_CURSOR;
    enum MONGOC_ERROR_QUERY = _Anonymous_16.MONGOC_ERROR_QUERY;
    enum MONGOC_ERROR_INSERT = _Anonymous_16.MONGOC_ERROR_INSERT;
    enum MONGOC_ERROR_SASL = _Anonymous_16.MONGOC_ERROR_SASL;
    enum MONGOC_ERROR_BSON = _Anonymous_16.MONGOC_ERROR_BSON;
    enum MONGOC_ERROR_MATCHER = _Anonymous_16.MONGOC_ERROR_MATCHER;
    enum MONGOC_ERROR_NAMESPACE = _Anonymous_16.MONGOC_ERROR_NAMESPACE;
    enum MONGOC_ERROR_COMMAND = _Anonymous_16.MONGOC_ERROR_COMMAND;
    enum MONGOC_ERROR_COLLECTION = _Anonymous_16.MONGOC_ERROR_COLLECTION;
    enum MONGOC_ERROR_GRIDFS = _Anonymous_16.MONGOC_ERROR_GRIDFS;
    enum MONGOC_ERROR_SCRAM = _Anonymous_16.MONGOC_ERROR_SCRAM;
    enum MONGOC_ERROR_SERVER_SELECTION = _Anonymous_16.MONGOC_ERROR_SERVER_SELECTION;
    enum MONGOC_ERROR_WRITE_CONCERN = _Anonymous_16.MONGOC_ERROR_WRITE_CONCERN;
    enum MONGOC_ERROR_SERVER = _Anonymous_16.MONGOC_ERROR_SERVER;
    enum MONGOC_ERROR_TRANSACTION = _Anonymous_16.MONGOC_ERROR_TRANSACTION;
    alias mongoc_error_code_t = _Anonymous_17;
    enum _Anonymous_17
    {
        MONGOC_ERROR_STREAM_INVALID_TYPE = 1,
        MONGOC_ERROR_STREAM_INVALID_STATE = 2,
        MONGOC_ERROR_STREAM_NAME_RESOLUTION = 3,
        MONGOC_ERROR_STREAM_SOCKET = 4,
        MONGOC_ERROR_STREAM_CONNECT = 5,
        MONGOC_ERROR_STREAM_NOT_ESTABLISHED = 6,
        MONGOC_ERROR_CLIENT_NOT_READY = 7,
        MONGOC_ERROR_CLIENT_TOO_BIG = 8,
        MONGOC_ERROR_CLIENT_TOO_SMALL = 9,
        MONGOC_ERROR_CLIENT_GETNONCE = 10,
        MONGOC_ERROR_CLIENT_AUTHENTICATE = 11,
        MONGOC_ERROR_CLIENT_NO_ACCEPTABLE_PEER = 12,
        MONGOC_ERROR_CLIENT_IN_EXHAUST = 13,
        MONGOC_ERROR_PROTOCOL_INVALID_REPLY = 14,
        MONGOC_ERROR_PROTOCOL_BAD_WIRE_VERSION = 15,
        MONGOC_ERROR_CURSOR_INVALID_CURSOR = 16,
        MONGOC_ERROR_QUERY_FAILURE = 17,
        MONGOC_ERROR_BSON_INVALID = 18,
        MONGOC_ERROR_MATCHER_INVALID = 19,
        MONGOC_ERROR_NAMESPACE_INVALID = 20,
        MONGOC_ERROR_NAMESPACE_INVALID_FILTER_TYPE = 21,
        MONGOC_ERROR_COMMAND_INVALID_ARG = 22,
        MONGOC_ERROR_COLLECTION_INSERT_FAILED = 23,
        MONGOC_ERROR_COLLECTION_UPDATE_FAILED = 24,
        MONGOC_ERROR_COLLECTION_DELETE_FAILED = 25,
        MONGOC_ERROR_COLLECTION_DOES_NOT_EXIST = 26,
        MONGOC_ERROR_GRIDFS_INVALID_FILENAME = 27,
        MONGOC_ERROR_SCRAM_NOT_DONE = 28,
        MONGOC_ERROR_SCRAM_PROTOCOL_ERROR = 29,
        MONGOC_ERROR_QUERY_COMMAND_NOT_FOUND = 59,
        MONGOC_ERROR_QUERY_NOT_TAILABLE = 13051,
        MONGOC_ERROR_SERVER_SELECTION_BAD_WIRE_VERSION = 13052,
        MONGOC_ERROR_SERVER_SELECTION_FAILURE = 13053,
        MONGOC_ERROR_SERVER_SELECTION_INVALID_ID = 13054,
        MONGOC_ERROR_GRIDFS_CHUNK_MISSING = 13055,
        MONGOC_ERROR_GRIDFS_PROTOCOL_ERROR = 13056,
        MONGOC_ERROR_PROTOCOL_ERROR = 17,
        MONGOC_ERROR_WRITE_CONCERN_ERROR = 64,
        MONGOC_ERROR_DUPLICATE_KEY = 11000,
        MONGOC_ERROR_MAX_TIME_MS_EXPIRED = 50,
        MONGOC_ERROR_CHANGE_STREAM_NO_RESUME_TOKEN = 51,
        MONGOC_ERROR_CLIENT_SESSION_FAILURE = 52,
        MONGOC_ERROR_TRANSACTION_INVALID_STATE = 53,
        MONGOC_ERROR_GRIDFS_CORRUPT = 54,
        MONGOC_ERROR_GRIDFS_BUCKET_FILE_NOT_FOUND = 55,
        MONGOC_ERROR_GRIDFS_BUCKET_STREAM = 56,
    }
    enum MONGOC_ERROR_STREAM_INVALID_TYPE = _Anonymous_17.MONGOC_ERROR_STREAM_INVALID_TYPE;
    enum MONGOC_ERROR_STREAM_INVALID_STATE = _Anonymous_17.MONGOC_ERROR_STREAM_INVALID_STATE;
    enum MONGOC_ERROR_STREAM_NAME_RESOLUTION = _Anonymous_17.MONGOC_ERROR_STREAM_NAME_RESOLUTION;
    enum MONGOC_ERROR_STREAM_SOCKET = _Anonymous_17.MONGOC_ERROR_STREAM_SOCKET;
    enum MONGOC_ERROR_STREAM_CONNECT = _Anonymous_17.MONGOC_ERROR_STREAM_CONNECT;
    enum MONGOC_ERROR_STREAM_NOT_ESTABLISHED = _Anonymous_17.MONGOC_ERROR_STREAM_NOT_ESTABLISHED;
    enum MONGOC_ERROR_CLIENT_NOT_READY = _Anonymous_17.MONGOC_ERROR_CLIENT_NOT_READY;
    enum MONGOC_ERROR_CLIENT_TOO_BIG = _Anonymous_17.MONGOC_ERROR_CLIENT_TOO_BIG;
    enum MONGOC_ERROR_CLIENT_TOO_SMALL = _Anonymous_17.MONGOC_ERROR_CLIENT_TOO_SMALL;
    enum MONGOC_ERROR_CLIENT_GETNONCE = _Anonymous_17.MONGOC_ERROR_CLIENT_GETNONCE;
    enum MONGOC_ERROR_CLIENT_AUTHENTICATE = _Anonymous_17.MONGOC_ERROR_CLIENT_AUTHENTICATE;
    enum MONGOC_ERROR_CLIENT_NO_ACCEPTABLE_PEER = _Anonymous_17.MONGOC_ERROR_CLIENT_NO_ACCEPTABLE_PEER;
    enum MONGOC_ERROR_CLIENT_IN_EXHAUST = _Anonymous_17.MONGOC_ERROR_CLIENT_IN_EXHAUST;
    enum MONGOC_ERROR_PROTOCOL_INVALID_REPLY = _Anonymous_17.MONGOC_ERROR_PROTOCOL_INVALID_REPLY;
    enum MONGOC_ERROR_PROTOCOL_BAD_WIRE_VERSION = _Anonymous_17.MONGOC_ERROR_PROTOCOL_BAD_WIRE_VERSION;
    enum MONGOC_ERROR_CURSOR_INVALID_CURSOR = _Anonymous_17.MONGOC_ERROR_CURSOR_INVALID_CURSOR;
    enum MONGOC_ERROR_QUERY_FAILURE = _Anonymous_17.MONGOC_ERROR_QUERY_FAILURE;
    enum MONGOC_ERROR_BSON_INVALID = _Anonymous_17.MONGOC_ERROR_BSON_INVALID;
    enum MONGOC_ERROR_MATCHER_INVALID = _Anonymous_17.MONGOC_ERROR_MATCHER_INVALID;
    enum MONGOC_ERROR_NAMESPACE_INVALID = _Anonymous_17.MONGOC_ERROR_NAMESPACE_INVALID;
    enum MONGOC_ERROR_NAMESPACE_INVALID_FILTER_TYPE = _Anonymous_17.MONGOC_ERROR_NAMESPACE_INVALID_FILTER_TYPE;
    enum MONGOC_ERROR_COMMAND_INVALID_ARG = _Anonymous_17.MONGOC_ERROR_COMMAND_INVALID_ARG;
    enum MONGOC_ERROR_COLLECTION_INSERT_FAILED = _Anonymous_17.MONGOC_ERROR_COLLECTION_INSERT_FAILED;
    enum MONGOC_ERROR_COLLECTION_UPDATE_FAILED = _Anonymous_17.MONGOC_ERROR_COLLECTION_UPDATE_FAILED;
    enum MONGOC_ERROR_COLLECTION_DELETE_FAILED = _Anonymous_17.MONGOC_ERROR_COLLECTION_DELETE_FAILED;
    enum MONGOC_ERROR_COLLECTION_DOES_NOT_EXIST = _Anonymous_17.MONGOC_ERROR_COLLECTION_DOES_NOT_EXIST;
    enum MONGOC_ERROR_GRIDFS_INVALID_FILENAME = _Anonymous_17.MONGOC_ERROR_GRIDFS_INVALID_FILENAME;
    enum MONGOC_ERROR_SCRAM_NOT_DONE = _Anonymous_17.MONGOC_ERROR_SCRAM_NOT_DONE;
    enum MONGOC_ERROR_SCRAM_PROTOCOL_ERROR = _Anonymous_17.MONGOC_ERROR_SCRAM_PROTOCOL_ERROR;
    enum MONGOC_ERROR_QUERY_COMMAND_NOT_FOUND = _Anonymous_17.MONGOC_ERROR_QUERY_COMMAND_NOT_FOUND;
    enum MONGOC_ERROR_QUERY_NOT_TAILABLE = _Anonymous_17.MONGOC_ERROR_QUERY_NOT_TAILABLE;
    enum MONGOC_ERROR_SERVER_SELECTION_BAD_WIRE_VERSION = _Anonymous_17.MONGOC_ERROR_SERVER_SELECTION_BAD_WIRE_VERSION;
    enum MONGOC_ERROR_SERVER_SELECTION_FAILURE = _Anonymous_17.MONGOC_ERROR_SERVER_SELECTION_FAILURE;
    enum MONGOC_ERROR_SERVER_SELECTION_INVALID_ID = _Anonymous_17.MONGOC_ERROR_SERVER_SELECTION_INVALID_ID;
    enum MONGOC_ERROR_GRIDFS_CHUNK_MISSING = _Anonymous_17.MONGOC_ERROR_GRIDFS_CHUNK_MISSING;
    enum MONGOC_ERROR_GRIDFS_PROTOCOL_ERROR = _Anonymous_17.MONGOC_ERROR_GRIDFS_PROTOCOL_ERROR;
    enum MONGOC_ERROR_PROTOCOL_ERROR = _Anonymous_17.MONGOC_ERROR_PROTOCOL_ERROR;
    enum MONGOC_ERROR_WRITE_CONCERN_ERROR = _Anonymous_17.MONGOC_ERROR_WRITE_CONCERN_ERROR;
    enum MONGOC_ERROR_DUPLICATE_KEY = _Anonymous_17.MONGOC_ERROR_DUPLICATE_KEY;
    enum MONGOC_ERROR_MAX_TIME_MS_EXPIRED = _Anonymous_17.MONGOC_ERROR_MAX_TIME_MS_EXPIRED;
    enum MONGOC_ERROR_CHANGE_STREAM_NO_RESUME_TOKEN = _Anonymous_17.MONGOC_ERROR_CHANGE_STREAM_NO_RESUME_TOKEN;
    enum MONGOC_ERROR_CLIENT_SESSION_FAILURE = _Anonymous_17.MONGOC_ERROR_CLIENT_SESSION_FAILURE;
    enum MONGOC_ERROR_TRANSACTION_INVALID_STATE = _Anonymous_17.MONGOC_ERROR_TRANSACTION_INVALID_STATE;
    enum MONGOC_ERROR_GRIDFS_CORRUPT = _Anonymous_17.MONGOC_ERROR_GRIDFS_CORRUPT;
    enum MONGOC_ERROR_GRIDFS_BUCKET_FILE_NOT_FOUND = _Anonymous_17.MONGOC_ERROR_GRIDFS_BUCKET_FILE_NOT_FOUND;
    enum MONGOC_ERROR_GRIDFS_BUCKET_STREAM = _Anonymous_17.MONGOC_ERROR_GRIDFS_BUCKET_STREAM;
    bool mongoc_error_has_label(const(_bson_t)*, const(char)*) @nogc nothrow;
    int adjtime(const(timeval)*, timeval*) @nogc nothrow;
    alias mongoc_find_and_modify_flags_t = _Anonymous_18;
    enum _Anonymous_18
    {
        MONGOC_FIND_AND_MODIFY_NONE = 0,
        MONGOC_FIND_AND_MODIFY_REMOVE = 1,
        MONGOC_FIND_AND_MODIFY_UPSERT = 2,
        MONGOC_FIND_AND_MODIFY_RETURN_NEW = 4,
    }
    enum MONGOC_FIND_AND_MODIFY_NONE = _Anonymous_18.MONGOC_FIND_AND_MODIFY_NONE;
    enum MONGOC_FIND_AND_MODIFY_REMOVE = _Anonymous_18.MONGOC_FIND_AND_MODIFY_REMOVE;
    enum MONGOC_FIND_AND_MODIFY_UPSERT = _Anonymous_18.MONGOC_FIND_AND_MODIFY_UPSERT;
    enum MONGOC_FIND_AND_MODIFY_RETURN_NEW = _Anonymous_18.MONGOC_FIND_AND_MODIFY_RETURN_NEW;
    alias mongoc_find_and_modify_opts_t = _mongoc_find_and_modify_opts_t;
    struct _mongoc_find_and_modify_opts_t;
    _mongoc_find_and_modify_opts_t* mongoc_find_and_modify_opts_new() @nogc nothrow;
    bool mongoc_find_and_modify_opts_set_sort(_mongoc_find_and_modify_opts_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_find_and_modify_opts_get_sort(const(_mongoc_find_and_modify_opts_t)*, _bson_t*) @nogc nothrow;
    bool mongoc_find_and_modify_opts_set_update(_mongoc_find_and_modify_opts_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_find_and_modify_opts_get_update(const(_mongoc_find_and_modify_opts_t)*, _bson_t*) @nogc nothrow;
    bool mongoc_find_and_modify_opts_set_fields(_mongoc_find_and_modify_opts_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_find_and_modify_opts_get_fields(const(_mongoc_find_and_modify_opts_t)*, _bson_t*) @nogc nothrow;
    bool mongoc_find_and_modify_opts_set_flags(_mongoc_find_and_modify_opts_t*, const(mongoc_find_and_modify_flags_t)) @nogc nothrow;
    mongoc_find_and_modify_flags_t mongoc_find_and_modify_opts_get_flags(const(_mongoc_find_and_modify_opts_t)*) @nogc nothrow;
    bool mongoc_find_and_modify_opts_set_bypass_document_validation(_mongoc_find_and_modify_opts_t*, bool) @nogc nothrow;
    bool mongoc_find_and_modify_opts_get_bypass_document_validation(const(_mongoc_find_and_modify_opts_t)*) @nogc nothrow;
    bool mongoc_find_and_modify_opts_set_max_time_ms(_mongoc_find_and_modify_opts_t*, uint) @nogc nothrow;
    uint mongoc_find_and_modify_opts_get_max_time_ms(const(_mongoc_find_and_modify_opts_t)*) @nogc nothrow;
    bool mongoc_find_and_modify_opts_append(_mongoc_find_and_modify_opts_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_find_and_modify_opts_get_extra(const(_mongoc_find_and_modify_opts_t)*, _bson_t*) @nogc nothrow;
    void mongoc_find_and_modify_opts_destroy(_mongoc_find_and_modify_opts_t*) @nogc nothrow;
    alias mongoc_delete_flags_t = _Anonymous_19;
    enum _Anonymous_19
    {
        MONGOC_DELETE_NONE = 0,
        MONGOC_DELETE_SINGLE_REMOVE = 1,
    }
    enum MONGOC_DELETE_NONE = _Anonymous_19.MONGOC_DELETE_NONE;
    enum MONGOC_DELETE_SINGLE_REMOVE = _Anonymous_19.MONGOC_DELETE_SINGLE_REMOVE;
    alias mongoc_remove_flags_t = _Anonymous_20;
    enum _Anonymous_20
    {
        MONGOC_REMOVE_NONE = 0,
        MONGOC_REMOVE_SINGLE_REMOVE = 1,
    }
    enum MONGOC_REMOVE_NONE = _Anonymous_20.MONGOC_REMOVE_NONE;
    enum MONGOC_REMOVE_SINGLE_REMOVE = _Anonymous_20.MONGOC_REMOVE_SINGLE_REMOVE;
    alias mongoc_insert_flags_t = _Anonymous_21;
    enum _Anonymous_21
    {
        MONGOC_INSERT_NONE = 0,
        MONGOC_INSERT_CONTINUE_ON_ERROR = 1,
    }
    enum MONGOC_INSERT_NONE = _Anonymous_21.MONGOC_INSERT_NONE;
    enum MONGOC_INSERT_CONTINUE_ON_ERROR = _Anonymous_21.MONGOC_INSERT_CONTINUE_ON_ERROR;
    int settimeofday(const(timeval)*, const(timezone)*) @nogc nothrow;
    alias mongoc_query_flags_t = _Anonymous_22;
    enum _Anonymous_22
    {
        MONGOC_QUERY_NONE = 0,
        MONGOC_QUERY_TAILABLE_CURSOR = 2,
        MONGOC_QUERY_SLAVE_OK = 4,
        MONGOC_QUERY_OPLOG_REPLAY = 8,
        MONGOC_QUERY_NO_CURSOR_TIMEOUT = 16,
        MONGOC_QUERY_AWAIT_DATA = 32,
        MONGOC_QUERY_EXHAUST = 64,
        MONGOC_QUERY_PARTIAL = 128,
    }
    enum MONGOC_QUERY_NONE = _Anonymous_22.MONGOC_QUERY_NONE;
    enum MONGOC_QUERY_TAILABLE_CURSOR = _Anonymous_22.MONGOC_QUERY_TAILABLE_CURSOR;
    enum MONGOC_QUERY_SLAVE_OK = _Anonymous_22.MONGOC_QUERY_SLAVE_OK;
    enum MONGOC_QUERY_OPLOG_REPLAY = _Anonymous_22.MONGOC_QUERY_OPLOG_REPLAY;
    enum MONGOC_QUERY_NO_CURSOR_TIMEOUT = _Anonymous_22.MONGOC_QUERY_NO_CURSOR_TIMEOUT;
    enum MONGOC_QUERY_AWAIT_DATA = _Anonymous_22.MONGOC_QUERY_AWAIT_DATA;
    enum MONGOC_QUERY_EXHAUST = _Anonymous_22.MONGOC_QUERY_EXHAUST;
    enum MONGOC_QUERY_PARTIAL = _Anonymous_22.MONGOC_QUERY_PARTIAL;
    alias mongoc_reply_flags_t = _Anonymous_23;
    enum _Anonymous_23
    {
        MONGOC_REPLY_NONE = 0,
        MONGOC_REPLY_CURSOR_NOT_FOUND = 1,
        MONGOC_REPLY_QUERY_FAILURE = 2,
        MONGOC_REPLY_SHARD_CONFIG_STALE = 4,
        MONGOC_REPLY_AWAIT_CAPABLE = 8,
    }
    enum MONGOC_REPLY_NONE = _Anonymous_23.MONGOC_REPLY_NONE;
    enum MONGOC_REPLY_CURSOR_NOT_FOUND = _Anonymous_23.MONGOC_REPLY_CURSOR_NOT_FOUND;
    enum MONGOC_REPLY_QUERY_FAILURE = _Anonymous_23.MONGOC_REPLY_QUERY_FAILURE;
    enum MONGOC_REPLY_SHARD_CONFIG_STALE = _Anonymous_23.MONGOC_REPLY_SHARD_CONFIG_STALE;
    enum MONGOC_REPLY_AWAIT_CAPABLE = _Anonymous_23.MONGOC_REPLY_AWAIT_CAPABLE;
    alias mongoc_update_flags_t = _Anonymous_24;
    enum _Anonymous_24
    {
        MONGOC_UPDATE_NONE = 0,
        MONGOC_UPDATE_UPSERT = 1,
        MONGOC_UPDATE_MULTI_UPDATE = 2,
    }
    enum MONGOC_UPDATE_NONE = _Anonymous_24.MONGOC_UPDATE_NONE;
    enum MONGOC_UPDATE_UPSERT = _Anonymous_24.MONGOC_UPDATE_UPSERT;
    enum MONGOC_UPDATE_MULTI_UPDATE = _Anonymous_24.MONGOC_UPDATE_MULTI_UPDATE;
    alias mongoc_gridfs_bucket_t = _mongoc_gridfs_bucket_t;
    struct _mongoc_gridfs_bucket_t;
    _mongoc_gridfs_bucket_t* mongoc_gridfs_bucket_new(_mongoc_database_t*, const(_bson_t)*, const(_mongoc_read_prefs_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_stream_t* mongoc_gridfs_bucket_open_upload_stream(_mongoc_gridfs_bucket_t*, const(char)*, const(_bson_t)*, _bson_value_t*, _bson_error_t*) @nogc nothrow;
    _mongoc_stream_t* mongoc_gridfs_bucket_open_upload_stream_with_id(_mongoc_gridfs_bucket_t*, const(_bson_value_t)*, const(char)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_gridfs_bucket_upload_from_stream(_mongoc_gridfs_bucket_t*, const(char)*, _mongoc_stream_t*, const(_bson_t)*, _bson_value_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_gridfs_bucket_upload_from_stream_with_id(_mongoc_gridfs_bucket_t*, const(_bson_value_t)*, const(char)*, _mongoc_stream_t*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_stream_t* mongoc_gridfs_bucket_open_download_stream(_mongoc_gridfs_bucket_t*, const(_bson_value_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_gridfs_bucket_download_to_stream(_mongoc_gridfs_bucket_t*, const(_bson_value_t)*, _mongoc_stream_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_gridfs_bucket_delete_by_id(_mongoc_gridfs_bucket_t*, const(_bson_value_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_cursor_t* mongoc_gridfs_bucket_find(_mongoc_gridfs_bucket_t*, const(_bson_t)*, const(_bson_t)*) @nogc nothrow;
    bool mongoc_gridfs_bucket_stream_error(_mongoc_stream_t*, _bson_error_t*) @nogc nothrow;
    void mongoc_gridfs_bucket_destroy(_mongoc_gridfs_bucket_t*) @nogc nothrow;
    bool mongoc_gridfs_bucket_abort_upload(_mongoc_stream_t*) @nogc nothrow;
    alias mongoc_gridfs_file_list_t = _mongoc_gridfs_file_list_t;
    struct _mongoc_gridfs_file_list_t;
    _mongoc_gridfs_file_t* mongoc_gridfs_file_list_next(_mongoc_gridfs_file_list_t*) @nogc nothrow;
    void mongoc_gridfs_file_list_destroy(_mongoc_gridfs_file_list_t*) @nogc nothrow;
    bool mongoc_gridfs_file_list_error(_mongoc_gridfs_file_list_t*, _bson_error_t*) @nogc nothrow;
    int gettimeofday(timeval*, timezone*) @nogc nothrow;
    alias mongoc_gridfs_file_page_t = _mongoc_gridfs_file_page_t;
    struct _mongoc_gridfs_file_page_t;
    alias __timezone_ptr_t = timezone*;
    struct timezone
    {
        int tz_minuteswest;
        int tz_dsttime;
    }
    alias mongoc_gridfs_file_t = _mongoc_gridfs_file_t;
    struct _mongoc_gridfs_file_t;
    alias mongoc_gridfs_file_opt_t = _mongoc_gridfs_file_opt_t;
    struct _mongoc_gridfs_file_opt_t
    {
        const(char)* md5;
        const(char)* filename;
        const(char)* content_type;
        const(_bson_t)* aliases;
        const(_bson_t)* metadata;
        uint chunk_size;
    }
    const(char)* mongoc_gridfs_file_get_md5(_mongoc_gridfs_file_t*) @nogc nothrow;
    void mongoc_gridfs_file_set_md5(_mongoc_gridfs_file_t*, const(char)*) @nogc nothrow;
    const(char)* mongoc_gridfs_file_get_filename(_mongoc_gridfs_file_t*) @nogc nothrow;
    void mongoc_gridfs_file_set_filename(_mongoc_gridfs_file_t*, const(char)*) @nogc nothrow;
    void mongoc_gridfs_file_set_content_type(_mongoc_gridfs_file_t*, const(char)*) @nogc nothrow;
    const(char)* mongoc_gridfs_file_get_content_type(_mongoc_gridfs_file_t*) @nogc nothrow;
    void mongoc_gridfs_file_set_aliases(_mongoc_gridfs_file_t*, const(_bson_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_gridfs_file_get_aliases(_mongoc_gridfs_file_t*) @nogc nothrow;
    void mongoc_gridfs_file_set_metadata(_mongoc_gridfs_file_t*, const(_bson_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_gridfs_file_get_metadata(_mongoc_gridfs_file_t*) @nogc nothrow;
    const(_bson_value_t)* mongoc_gridfs_file_get_id(_mongoc_gridfs_file_t*) @nogc nothrow;
    c_long mongoc_gridfs_file_get_length(_mongoc_gridfs_file_t*) @nogc nothrow;
    int mongoc_gridfs_file_get_chunk_size(_mongoc_gridfs_file_t*) @nogc nothrow;
    c_long mongoc_gridfs_file_get_upload_date(_mongoc_gridfs_file_t*) @nogc nothrow;
    c_long mongoc_gridfs_file_writev(_mongoc_gridfs_file_t*, const(iovec)*, c_ulong, uint) @nogc nothrow;
    c_long mongoc_gridfs_file_readv(_mongoc_gridfs_file_t*, iovec*, c_ulong, c_ulong, uint) @nogc nothrow;
    int mongoc_gridfs_file_seek(_mongoc_gridfs_file_t*, c_long, int) @nogc nothrow;
    c_ulong mongoc_gridfs_file_tell(_mongoc_gridfs_file_t*) @nogc nothrow;
    bool mongoc_gridfs_file_set_id(_mongoc_gridfs_file_t*, const(_bson_value_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_gridfs_file_save(_mongoc_gridfs_file_t*) @nogc nothrow;
    void mongoc_gridfs_file_destroy(_mongoc_gridfs_file_t*) @nogc nothrow;
    bool mongoc_gridfs_file_error(_mongoc_gridfs_file_t*, _bson_error_t*) @nogc nothrow;
    bool mongoc_gridfs_file_remove(_mongoc_gridfs_file_t*, _bson_error_t*) @nogc nothrow;
    alias mongoc_gridfs_t = _mongoc_gridfs_t;
    struct _mongoc_gridfs_t;
    _mongoc_gridfs_file_t* mongoc_gridfs_create_file_from_stream(_mongoc_gridfs_t*, _mongoc_stream_t*, _mongoc_gridfs_file_opt_t*) @nogc nothrow;
    _mongoc_gridfs_file_t* mongoc_gridfs_create_file(_mongoc_gridfs_t*, _mongoc_gridfs_file_opt_t*) @nogc nothrow;
    _mongoc_gridfs_file_list_t* mongoc_gridfs_find(_mongoc_gridfs_t*, const(_bson_t)*) @nogc nothrow;
    _mongoc_gridfs_file_t* mongoc_gridfs_find_one(_mongoc_gridfs_t*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_gridfs_file_list_t* mongoc_gridfs_find_with_opts(_mongoc_gridfs_t*, const(_bson_t)*, const(_bson_t)*) @nogc nothrow;
    _mongoc_gridfs_file_t* mongoc_gridfs_find_one_with_opts(_mongoc_gridfs_t*, const(_bson_t)*, const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    _mongoc_gridfs_file_t* mongoc_gridfs_find_one_by_filename(_mongoc_gridfs_t*, const(char)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_gridfs_drop(_mongoc_gridfs_t*, _bson_error_t*) @nogc nothrow;
    void mongoc_gridfs_destroy(_mongoc_gridfs_t*) @nogc nothrow;
    _mongoc_collection_t* mongoc_gridfs_get_files(_mongoc_gridfs_t*) @nogc nothrow;
    _mongoc_collection_t* mongoc_gridfs_get_chunks(_mongoc_gridfs_t*) @nogc nothrow;
    bool mongoc_gridfs_remove_by_filename(_mongoc_gridfs_t*, const(char)*, _bson_error_t*) @nogc nothrow;
    alias suseconds_t = c_long;
    bool mongoc_handshake_data_append(const(char)*, const(char)*, const(char)*) @nogc nothrow;
    alias mongoc_host_list_t = _mongoc_host_list_t;
    struct _mongoc_host_list_t
    {
        _mongoc_host_list_t* next;
        char[256] host;
        char[262] host_and_port;
        ushort port;
        int family;
        void*[4] padding;
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
    alias mongoc_index_storage_opt_type_t = _Anonymous_25;
    enum _Anonymous_25
    {
        MONGOC_INDEX_STORAGE_OPT_MMAPV1 = 0,
        MONGOC_INDEX_STORAGE_OPT_WIREDTIGER = 1,
    }
    enum MONGOC_INDEX_STORAGE_OPT_MMAPV1 = _Anonymous_25.MONGOC_INDEX_STORAGE_OPT_MMAPV1;
    enum MONGOC_INDEX_STORAGE_OPT_WIREDTIGER = _Anonymous_25.MONGOC_INDEX_STORAGE_OPT_WIREDTIGER;
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
        const(_bson_t)* weights;
        const(char)* default_language;
        const(char)* language_override;
        mongoc_index_opt_geo_t* geo_options;
        mongoc_index_opt_storage_t* storage_options;
        const(_bson_t)* partial_filter_expression;
        const(_bson_t)* collation;
        void*[4] padding;
    }
    const(mongoc_index_opt_t)* mongoc_index_opt_get_default() @nogc nothrow;
    const(mongoc_index_opt_geo_t)* mongoc_index_opt_geo_get_default() @nogc nothrow;
    const(mongoc_index_opt_wt_t)* mongoc_index_opt_wt_get_default() @nogc nothrow;
    void mongoc_index_opt_init(mongoc_index_opt_t*) @nogc nothrow;
    void mongoc_index_opt_geo_init(mongoc_index_opt_geo_t*) @nogc nothrow;
    void mongoc_index_opt_wt_init(mongoc_index_opt_wt_t*) @nogc nothrow;
    void mongoc_init() @nogc nothrow;
    void mongoc_cleanup() @nogc nothrow;
    alias mongoc_iovec_t = iovec;
    int __xmknodat(int, int, const(char)*, uint, c_ulong*) @nogc nothrow;
    int __xmknod(int, const(char)*, uint, c_ulong*) @nogc nothrow;
    alias mongoc_log_level_t = _Anonymous_26;
    enum _Anonymous_26
    {
        MONGOC_LOG_LEVEL_ERROR = 0,
        MONGOC_LOG_LEVEL_CRITICAL = 1,
        MONGOC_LOG_LEVEL_WARNING = 2,
        MONGOC_LOG_LEVEL_MESSAGE = 3,
        MONGOC_LOG_LEVEL_INFO = 4,
        MONGOC_LOG_LEVEL_DEBUG = 5,
        MONGOC_LOG_LEVEL_TRACE = 6,
    }
    enum MONGOC_LOG_LEVEL_ERROR = _Anonymous_26.MONGOC_LOG_LEVEL_ERROR;
    enum MONGOC_LOG_LEVEL_CRITICAL = _Anonymous_26.MONGOC_LOG_LEVEL_CRITICAL;
    enum MONGOC_LOG_LEVEL_WARNING = _Anonymous_26.MONGOC_LOG_LEVEL_WARNING;
    enum MONGOC_LOG_LEVEL_MESSAGE = _Anonymous_26.MONGOC_LOG_LEVEL_MESSAGE;
    enum MONGOC_LOG_LEVEL_INFO = _Anonymous_26.MONGOC_LOG_LEVEL_INFO;
    enum MONGOC_LOG_LEVEL_DEBUG = _Anonymous_26.MONGOC_LOG_LEVEL_DEBUG;
    enum MONGOC_LOG_LEVEL_TRACE = _Anonymous_26.MONGOC_LOG_LEVEL_TRACE;
    alias mongoc_log_func_t = void function(mongoc_log_level_t, const(char)*, const(char)*, void*);
    void mongoc_log_set_handler(void function(mongoc_log_level_t, const(char)*, const(char)*, void*), void*) @nogc nothrow;
    void mongoc_log(mongoc_log_level_t, const(char)*, const(char)*, ...) @nogc nothrow;
    void mongoc_log_default_handler(mongoc_log_level_t, const(char)*, const(char)*, void*) @nogc nothrow;
    const(char)* mongoc_log_level_str(mongoc_log_level_t) @nogc nothrow;
    void mongoc_log_trace_enable() @nogc nothrow;
    void mongoc_log_trace_disable() @nogc nothrow;
    int __fxstatat(int, int, const(char)*, stat*, int) @nogc nothrow;
    int __lxstat(int, const(char)*, stat*) @nogc nothrow;
    alias mongoc_matcher_t = _mongoc_matcher_t;
    struct _mongoc_matcher_t;
    _mongoc_matcher_t* mongoc_matcher_new(const(_bson_t)*, _bson_error_t*) @nogc nothrow;
    bool mongoc_matcher_match(const(_mongoc_matcher_t)*, const(_bson_t)*) @nogc nothrow;
    void mongoc_matcher_destroy(_mongoc_matcher_t*) @nogc nothrow;
    alias mongoc_opcode_t = _Anonymous_27;
    enum _Anonymous_27
    {
        MONGOC_OPCODE_REPLY = 1,
        MONGOC_OPCODE_UPDATE = 2001,
        MONGOC_OPCODE_INSERT = 2002,
        MONGOC_OPCODE_QUERY = 2004,
        MONGOC_OPCODE_GET_MORE = 2005,
        MONGOC_OPCODE_DELETE = 2006,
        MONGOC_OPCODE_KILL_CURSORS = 2007,
        MONGOC_OPCODE_COMPRESSED = 2012,
        MONGOC_OPCODE_MSG = 2013,
    }
    enum MONGOC_OPCODE_REPLY = _Anonymous_27.MONGOC_OPCODE_REPLY;
    enum MONGOC_OPCODE_UPDATE = _Anonymous_27.MONGOC_OPCODE_UPDATE;
    enum MONGOC_OPCODE_INSERT = _Anonymous_27.MONGOC_OPCODE_INSERT;
    enum MONGOC_OPCODE_QUERY = _Anonymous_27.MONGOC_OPCODE_QUERY;
    enum MONGOC_OPCODE_GET_MORE = _Anonymous_27.MONGOC_OPCODE_GET_MORE;
    enum MONGOC_OPCODE_DELETE = _Anonymous_27.MONGOC_OPCODE_DELETE;
    enum MONGOC_OPCODE_KILL_CURSORS = _Anonymous_27.MONGOC_OPCODE_KILL_CURSORS;
    enum MONGOC_OPCODE_COMPRESSED = _Anonymous_27.MONGOC_OPCODE_COMPRESSED;
    enum MONGOC_OPCODE_MSG = _Anonymous_27.MONGOC_OPCODE_MSG;
    int __xstat(int, const(char)*, stat*) @nogc nothrow;
    void mongoc_rand_seed(const(void)*, int) @nogc nothrow;
    void mongoc_rand_add(const(void)*, int, double) @nogc nothrow;
    int mongoc_rand_status() @nogc nothrow;
    int __fxstat(int, int, stat*) @nogc nothrow;
    int futimens(int, const(timespec)*) @nogc nothrow;
    alias mongoc_read_concern_t = _mongoc_read_concern_t;
    struct _mongoc_read_concern_t;
    _mongoc_read_concern_t* mongoc_read_concern_new() @nogc nothrow;
    _mongoc_read_concern_t* mongoc_read_concern_copy(const(_mongoc_read_concern_t)*) @nogc nothrow;
    void mongoc_read_concern_destroy(_mongoc_read_concern_t*) @nogc nothrow;
    const(char)* mongoc_read_concern_get_level(const(_mongoc_read_concern_t)*) @nogc nothrow;
    bool mongoc_read_concern_set_level(_mongoc_read_concern_t*, const(char)*) @nogc nothrow;
    bool mongoc_read_concern_append(_mongoc_read_concern_t*, _bson_t*) @nogc nothrow;
    bool mongoc_read_concern_is_default(const(_mongoc_read_concern_t)*) @nogc nothrow;
    alias mongoc_read_prefs_t = _mongoc_read_prefs_t;
    struct _mongoc_read_prefs_t;
    alias mongoc_read_mode_t = _Anonymous_28;
    enum _Anonymous_28
    {
        MONGOC_READ_PRIMARY = 1,
        MONGOC_READ_SECONDARY = 2,
        MONGOC_READ_PRIMARY_PREFERRED = 5,
        MONGOC_READ_SECONDARY_PREFERRED = 6,
        MONGOC_READ_NEAREST = 10,
    }
    enum MONGOC_READ_PRIMARY = _Anonymous_28.MONGOC_READ_PRIMARY;
    enum MONGOC_READ_SECONDARY = _Anonymous_28.MONGOC_READ_SECONDARY;
    enum MONGOC_READ_PRIMARY_PREFERRED = _Anonymous_28.MONGOC_READ_PRIMARY_PREFERRED;
    enum MONGOC_READ_SECONDARY_PREFERRED = _Anonymous_28.MONGOC_READ_SECONDARY_PREFERRED;
    enum MONGOC_READ_NEAREST = _Anonymous_28.MONGOC_READ_NEAREST;
    _mongoc_read_prefs_t* mongoc_read_prefs_new(mongoc_read_mode_t) @nogc nothrow;
    _mongoc_read_prefs_t* mongoc_read_prefs_copy(const(_mongoc_read_prefs_t)*) @nogc nothrow;
    void mongoc_read_prefs_destroy(_mongoc_read_prefs_t*) @nogc nothrow;
    mongoc_read_mode_t mongoc_read_prefs_get_mode(const(_mongoc_read_prefs_t)*) @nogc nothrow;
    void mongoc_read_prefs_set_mode(_mongoc_read_prefs_t*, mongoc_read_mode_t) @nogc nothrow;
    const(_bson_t)* mongoc_read_prefs_get_tags(const(_mongoc_read_prefs_t)*) @nogc nothrow;
    void mongoc_read_prefs_set_tags(_mongoc_read_prefs_t*, const(_bson_t)*) @nogc nothrow;
    void mongoc_read_prefs_add_tag(_mongoc_read_prefs_t*, const(_bson_t)*) @nogc nothrow;
    c_long mongoc_read_prefs_get_max_staleness_seconds(const(_mongoc_read_prefs_t)*) @nogc nothrow;
    void mongoc_read_prefs_set_max_staleness_seconds(_mongoc_read_prefs_t*, c_long) @nogc nothrow;
    bool mongoc_read_prefs_is_valid(const(_mongoc_read_prefs_t)*) @nogc nothrow;
    int utimensat(int, const(char)*, const(timespec)*, int) @nogc nothrow;
    alias mongoc_server_description_t = _mongoc_server_description_t;
    struct _mongoc_server_description_t;
    void mongoc_server_description_destroy(_mongoc_server_description_t*) @nogc nothrow;
    _mongoc_server_description_t* mongoc_server_description_new_copy(const(_mongoc_server_description_t)*) @nogc nothrow;
    uint mongoc_server_description_id(const(_mongoc_server_description_t)*) @nogc nothrow;
    _mongoc_host_list_t* mongoc_server_description_host(const(_mongoc_server_description_t)*) @nogc nothrow;
    c_long mongoc_server_description_last_update_time(const(_mongoc_server_description_t)*) @nogc nothrow;
    c_long mongoc_server_description_round_trip_time(const(_mongoc_server_description_t)*) @nogc nothrow;
    const(char)* mongoc_server_description_type(const(_mongoc_server_description_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_server_description_ismaster(const(_mongoc_server_description_t)*) @nogc nothrow;
    int mongoc_server_description_compressor_id(const(_mongoc_server_description_t)*) @nogc nothrow;
    alias mongoc_socklen_t = uint;
    alias mongoc_socket_t = _mongoc_socket_t;
    struct _mongoc_socket_t;
    struct mongoc_socket_poll_t
    {
        _mongoc_socket_t* socket;
        int events;
        int revents;
    }
    _mongoc_socket_t* mongoc_socket_accept(_mongoc_socket_t*, c_long) @nogc nothrow;
    int mongoc_socket_bind(_mongoc_socket_t*, const(sockaddr)*, uint) @nogc nothrow;
    int mongoc_socket_close(_mongoc_socket_t*) @nogc nothrow;
    int mongoc_socket_connect(_mongoc_socket_t*, const(sockaddr)*, uint, c_long) @nogc nothrow;
    char* mongoc_socket_getnameinfo(_mongoc_socket_t*) @nogc nothrow;
    void mongoc_socket_destroy(_mongoc_socket_t*) @nogc nothrow;
    int mongoc_socket_errno(_mongoc_socket_t*) @nogc nothrow;
    int mongoc_socket_getsockname(_mongoc_socket_t*, sockaddr*, uint*) @nogc nothrow;
    int mongoc_socket_listen(_mongoc_socket_t*, uint) @nogc nothrow;
    _mongoc_socket_t* mongoc_socket_new(int, int, int) @nogc nothrow;
    c_long mongoc_socket_recv(_mongoc_socket_t*, void*, c_ulong, int, c_long) @nogc nothrow;
    int mongoc_socket_setsockopt(_mongoc_socket_t*, int, int, const(void)*, uint) @nogc nothrow;
    c_long mongoc_socket_send(_mongoc_socket_t*, const(void)*, c_ulong, c_long) @nogc nothrow;
    c_long mongoc_socket_sendv(_mongoc_socket_t*, iovec*, c_ulong, c_long) @nogc nothrow;
    bool mongoc_socket_check_closed(_mongoc_socket_t*) @nogc nothrow;
    void mongoc_socket_inet_ntop(addrinfo*, char*, c_ulong) @nogc nothrow;
    c_long mongoc_socket_poll(mongoc_socket_poll_t*, c_ulong, int) @nogc nothrow;
    alias mongoc_ssl_opt_t = _mongoc_ssl_opt_t;
    struct _mongoc_ssl_opt_t
    {
        const(char)* pem_file;
        const(char)* pem_pwd;
        const(char)* ca_file;
        const(char)* ca_dir;
        const(char)* crl_file;
        bool weak_cert_validation;
        bool allow_invalid_hostname;
        void*[7] padding;
    }
    const(_mongoc_ssl_opt_t)* mongoc_ssl_opt_get_default() @nogc nothrow;
    _mongoc_stream_t* mongoc_stream_buffered_new(_mongoc_stream_t*, c_ulong) @nogc nothrow;
    int mkfifoat(int, const(char)*, uint) @nogc nothrow;
    alias mongoc_stream_file_t = _mongoc_stream_file_t;
    struct _mongoc_stream_file_t;
    _mongoc_stream_t* mongoc_stream_file_new(int) @nogc nothrow;
    _mongoc_stream_t* mongoc_stream_file_new_for_path(const(char)*, int, int) @nogc nothrow;
    int mongoc_stream_file_get_fd(_mongoc_stream_file_t*) @nogc nothrow;
    _mongoc_stream_t* mongoc_stream_gridfs_new(_mongoc_gridfs_file_t*) @nogc nothrow;
    alias mongoc_stream_socket_t = _mongoc_stream_socket_t;
    struct _mongoc_stream_socket_t;
    _mongoc_stream_t* mongoc_stream_socket_new(_mongoc_socket_t*) @nogc nothrow;
    _mongoc_socket_t* mongoc_stream_socket_get_socket(_mongoc_stream_socket_t*) @nogc nothrow;
    alias mongoc_stream_tls_t = _mongoc_stream_tls_t;
    struct _mongoc_stream_tls_t;
    bool mongoc_stream_tls_handshake(_mongoc_stream_t*, const(char)*, int, int*, _bson_error_t*) @nogc nothrow;
    bool mongoc_stream_tls_handshake_block(_mongoc_stream_t*, const(char)*, int, _bson_error_t*) @nogc nothrow;
    bool mongoc_stream_tls_do_handshake(_mongoc_stream_t*, int) @nogc nothrow;
    bool mongoc_stream_tls_check_cert(_mongoc_stream_t*, const(char)*) @nogc nothrow;
    _mongoc_stream_t* mongoc_stream_tls_new_with_hostname(_mongoc_stream_t*, const(char)*, _mongoc_ssl_opt_t*, int) @nogc nothrow;
    _mongoc_stream_t* mongoc_stream_tls_new(_mongoc_stream_t*, _mongoc_ssl_opt_t*, int) @nogc nothrow;
    int mkfifo(const(char)*, uint) @nogc nothrow;
    alias mongoc_stream_t = _mongoc_stream_t;
    struct _mongoc_stream_t
    {
        int type;
        void function(_mongoc_stream_t*) destroy;
        int function(_mongoc_stream_t*) close;
        int function(_mongoc_stream_t*) flush;
        c_long function(_mongoc_stream_t*, iovec*, c_ulong, int) writev;
        c_long function(_mongoc_stream_t*, iovec*, c_ulong, c_ulong, int) readv;
        int function(_mongoc_stream_t*, int, int, void*, uint) setsockopt;
        _mongoc_stream_t* function(_mongoc_stream_t*) get_base_stream;
        bool function(_mongoc_stream_t*) check_closed;
        c_long function(_mongoc_stream_poll_t*, c_ulong, int) poll;
        void function(_mongoc_stream_t*) failed;
        bool function(_mongoc_stream_t*) timed_out;
        bool function(_mongoc_stream_t*) should_retry;
        void*[3] padding;
    }
    alias mongoc_stream_poll_t = _mongoc_stream_poll_t;
    struct _mongoc_stream_poll_t
    {
        _mongoc_stream_t* stream;
        int events;
        int revents;
    }
    _mongoc_stream_t* mongoc_stream_get_base_stream(_mongoc_stream_t*) @nogc nothrow;
    _mongoc_stream_t* mongoc_stream_get_tls_stream(_mongoc_stream_t*) @nogc nothrow;
    int mongoc_stream_close(_mongoc_stream_t*) @nogc nothrow;
    void mongoc_stream_destroy(_mongoc_stream_t*) @nogc nothrow;
    void mongoc_stream_failed(_mongoc_stream_t*) @nogc nothrow;
    int mongoc_stream_flush(_mongoc_stream_t*) @nogc nothrow;
    c_long mongoc_stream_writev(_mongoc_stream_t*, iovec*, c_ulong, int) @nogc nothrow;
    c_long mongoc_stream_write(_mongoc_stream_t*, void*, c_ulong, int) @nogc nothrow;
    c_long mongoc_stream_readv(_mongoc_stream_t*, iovec*, c_ulong, c_ulong, int) @nogc nothrow;
    c_long mongoc_stream_read(_mongoc_stream_t*, void*, c_ulong, c_ulong, int) @nogc nothrow;
    int mongoc_stream_setsockopt(_mongoc_stream_t*, int, int, void*, uint) @nogc nothrow;
    bool mongoc_stream_check_closed(_mongoc_stream_t*) @nogc nothrow;
    bool mongoc_stream_timed_out(_mongoc_stream_t*) @nogc nothrow;
    bool mongoc_stream_should_retry(_mongoc_stream_t*) @nogc nothrow;
    c_long mongoc_stream_poll(_mongoc_stream_poll_t*, c_ulong, int) @nogc nothrow;
    alias mongoc_topology_description_t = _mongoc_topology_description_t;
    struct _mongoc_topology_description_t;
    bool mongoc_topology_description_has_readable_server(_mongoc_topology_description_t*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    bool mongoc_topology_description_has_writable_server(_mongoc_topology_description_t*) @nogc nothrow;
    const(char)* mongoc_topology_description_type(const(_mongoc_topology_description_t)*) @nogc nothrow;
    _mongoc_server_description_t** mongoc_topology_description_get_servers(const(_mongoc_topology_description_t)*, c_ulong*) @nogc nothrow;
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
    alias mongoc_uri_t = _mongoc_uri_t;
    struct _mongoc_uri_t;
    _mongoc_uri_t* mongoc_uri_copy(const(_mongoc_uri_t)*) @nogc nothrow;
    void mongoc_uri_destroy(_mongoc_uri_t*) @nogc nothrow;
    _mongoc_uri_t* mongoc_uri_new(const(char)*) @nogc nothrow;
    _mongoc_uri_t* mongoc_uri_new_with_error(const(char)*, _bson_error_t*) @nogc nothrow;
    _mongoc_uri_t* mongoc_uri_new_for_host_port(const(char)*, ushort) @nogc nothrow;
    const(_mongoc_host_list_t)* mongoc_uri_get_hosts(const(_mongoc_uri_t)*) @nogc nothrow;
    const(char)* mongoc_uri_get_service(const(_mongoc_uri_t)*) @nogc nothrow;
    const(char)* mongoc_uri_get_database(const(_mongoc_uri_t)*) @nogc nothrow;
    bool mongoc_uri_set_database(_mongoc_uri_t*, const(char)*) @nogc nothrow;
    const(_bson_t)* mongoc_uri_get_compressors(const(_mongoc_uri_t)*) @nogc nothrow;
    const(_bson_t)* mongoc_uri_get_options(const(_mongoc_uri_t)*) @nogc nothrow;
    const(char)* mongoc_uri_get_password(const(_mongoc_uri_t)*) @nogc nothrow;
    bool mongoc_uri_set_password(_mongoc_uri_t*, const(char)*) @nogc nothrow;
    bool mongoc_uri_option_is_int32(const(char)*) @nogc nothrow;
    bool mongoc_uri_option_is_bool(const(char)*) @nogc nothrow;
    bool mongoc_uri_option_is_utf8(const(char)*) @nogc nothrow;
    int mongoc_uri_get_option_as_int32(const(_mongoc_uri_t)*, const(char)*, int) @nogc nothrow;
    bool mongoc_uri_get_option_as_bool(const(_mongoc_uri_t)*, const(char)*, bool) @nogc nothrow;
    const(char)* mongoc_uri_get_option_as_utf8(const(_mongoc_uri_t)*, const(char)*, const(char)*) @nogc nothrow;
    bool mongoc_uri_set_option_as_int32(_mongoc_uri_t*, const(char)*, int) @nogc nothrow;
    bool mongoc_uri_set_option_as_bool(_mongoc_uri_t*, const(char)*, bool) @nogc nothrow;
    bool mongoc_uri_set_option_as_utf8(_mongoc_uri_t*, const(char)*, const(char)*) @nogc nothrow;
    const(_bson_t)* mongoc_uri_get_read_prefs(const(_mongoc_uri_t)*) @nogc nothrow;
    const(char)* mongoc_uri_get_replica_set(const(_mongoc_uri_t)*) @nogc nothrow;
    const(char)* mongoc_uri_get_string(const(_mongoc_uri_t)*) @nogc nothrow;
    const(char)* mongoc_uri_get_username(const(_mongoc_uri_t)*) @nogc nothrow;
    bool mongoc_uri_set_username(_mongoc_uri_t*, const(char)*) @nogc nothrow;
    const(_bson_t)* mongoc_uri_get_credentials(const(_mongoc_uri_t)*) @nogc nothrow;
    const(char)* mongoc_uri_get_auth_source(const(_mongoc_uri_t)*) @nogc nothrow;
    bool mongoc_uri_set_auth_source(_mongoc_uri_t*, const(char)*) @nogc nothrow;
    const(char)* mongoc_uri_get_appname(const(_mongoc_uri_t)*) @nogc nothrow;
    bool mongoc_uri_set_appname(_mongoc_uri_t*, const(char)*) @nogc nothrow;
    bool mongoc_uri_set_compressors(_mongoc_uri_t*, const(char)*) @nogc nothrow;
    const(char)* mongoc_uri_get_auth_mechanism(const(_mongoc_uri_t)*) @nogc nothrow;
    bool mongoc_uri_set_auth_mechanism(_mongoc_uri_t*, const(char)*) @nogc nothrow;
    bool mongoc_uri_get_mechanism_properties(const(_mongoc_uri_t)*, _bson_t*) @nogc nothrow;
    bool mongoc_uri_set_mechanism_properties(_mongoc_uri_t*, const(_bson_t)*) @nogc nothrow;
    bool mongoc_uri_get_ssl(const(_mongoc_uri_t)*) @nogc nothrow;
    bool mongoc_uri_get_tls(const(_mongoc_uri_t)*) @nogc nothrow;
    char* mongoc_uri_unescape(const(char)*) @nogc nothrow;
    const(_mongoc_read_prefs_t)* mongoc_uri_get_read_prefs_t(const(_mongoc_uri_t)*) @nogc nothrow;
    void mongoc_uri_set_read_prefs_t(_mongoc_uri_t*, const(_mongoc_read_prefs_t)*) @nogc nothrow;
    const(_mongoc_write_concern_t)* mongoc_uri_get_write_concern(const(_mongoc_uri_t)*) @nogc nothrow;
    void mongoc_uri_set_write_concern(_mongoc_uri_t*, const(_mongoc_write_concern_t)*) @nogc nothrow;
    const(_mongoc_read_concern_t)* mongoc_uri_get_read_concern(const(_mongoc_uri_t)*) @nogc nothrow;
    void mongoc_uri_set_read_concern(_mongoc_uri_t*, const(_mongoc_read_concern_t)*) @nogc nothrow;
    int mongoc_get_major_version() @nogc nothrow;
    int mongoc_get_minor_version() @nogc nothrow;
    int mongoc_get_micro_version() @nogc nothrow;
    const(char)* mongoc_get_version() @nogc nothrow;
    bool mongoc_check_version(int, int, int) @nogc nothrow;
    alias mongoc_write_concern_t = _mongoc_write_concern_t;
    struct _mongoc_write_concern_t;
    _mongoc_write_concern_t* mongoc_write_concern_new() @nogc nothrow;
    _mongoc_write_concern_t* mongoc_write_concern_copy(const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_write_concern_destroy(_mongoc_write_concern_t*) @nogc nothrow;
    bool mongoc_write_concern_get_fsync(const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_write_concern_set_fsync(_mongoc_write_concern_t*, bool) @nogc nothrow;
    bool mongoc_write_concern_get_journal(const(_mongoc_write_concern_t)*) @nogc nothrow;
    bool mongoc_write_concern_journal_is_set(const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_write_concern_set_journal(_mongoc_write_concern_t*, bool) @nogc nothrow;
    int mongoc_write_concern_get_w(const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_write_concern_set_w(_mongoc_write_concern_t*, int) @nogc nothrow;
    const(char)* mongoc_write_concern_get_wtag(const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_write_concern_set_wtag(_mongoc_write_concern_t*, const(char)*) @nogc nothrow;
    int mongoc_write_concern_get_wtimeout(const(_mongoc_write_concern_t)*) @nogc nothrow;
    c_long mongoc_write_concern_get_wtimeout_int64(const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_write_concern_set_wtimeout(_mongoc_write_concern_t*, int) @nogc nothrow;
    void mongoc_write_concern_set_wtimeout_int64(_mongoc_write_concern_t*, c_long) @nogc nothrow;
    bool mongoc_write_concern_get_wmajority(const(_mongoc_write_concern_t)*) @nogc nothrow;
    void mongoc_write_concern_set_wmajority(_mongoc_write_concern_t*, int) @nogc nothrow;
    bool mongoc_write_concern_is_acknowledged(const(_mongoc_write_concern_t)*) @nogc nothrow;
    bool mongoc_write_concern_is_valid(const(_mongoc_write_concern_t)*) @nogc nothrow;
    bool mongoc_write_concern_append(_mongoc_write_concern_t*, _bson_t*) @nogc nothrow;
    bool mongoc_write_concern_is_default(const(_mongoc_write_concern_t)*) @nogc nothrow;
    pragma(mangle, "alloca") void* alloca_(c_ulong) @nogc nothrow;
    uint inet_addr(const(char)*) @nogc nothrow;
    uint inet_lnaof(in_addr) @nogc nothrow;
    in_addr inet_makeaddr(uint, uint) @nogc nothrow;
    uint inet_netof(in_addr) @nogc nothrow;
    uint inet_network(const(char)*) @nogc nothrow;
    char* inet_ntoa(in_addr) @nogc nothrow;
    int inet_pton(int, const(char)*, void*) @nogc nothrow;
    const(char)* inet_ntop(int, const(void)*, char*, uint) @nogc nothrow;
    int inet_aton(const(char)*, in_addr*) @nogc nothrow;
    char* inet_neta(uint, char*, c_ulong) @nogc nothrow;
    char* inet_net_ntop(int, const(void)*, int, char*, c_ulong) @nogc nothrow;
    int inet_net_pton(int, const(char)*, void*, c_ulong) @nogc nothrow;
    uint inet_nsap_addr(const(char)*, ubyte*, int) @nogc nothrow;
    char* inet_nsap_ntoa(int, const(ubyte)*, char*) @nogc nothrow;
    alias nlink_t = c_ulong;
    alias ino_t = c_ulong;
    alias dev_t = c_ulong;
    int isfdtype(int, int) @nogc nothrow;
    int sockatmark(int) @nogc nothrow;
    int shutdown(int, int) @nogc nothrow;
    int accept(int, sockaddr*, uint*) @nogc nothrow;
    int listen(int, int) @nogc nothrow;
    int setsockopt(int, int, int, const(void)*, uint) @nogc nothrow;
    int getsockopt(int, int, int, void*, uint*) @nogc nothrow;
    c_long recvmsg(int, msghdr*, int) @nogc nothrow;
    c_long sendmsg(int, const(msghdr)*, int) @nogc nothrow;
    c_long recvfrom(int, void*, c_ulong, int, sockaddr*, uint*) @nogc nothrow;
    c_long sendto(int, const(void)*, c_ulong, int, const(sockaddr)*, uint) @nogc nothrow;
    c_long recv(int, void*, c_ulong, int) @nogc nothrow;
    c_long send(int, const(void)*, c_ulong, int) @nogc nothrow;
    int getpeername(int, sockaddr*, uint*) @nogc nothrow;
    int connect(int, const(sockaddr)*, uint) @nogc nothrow;
    int getsockname(int, sockaddr*, uint*) @nogc nothrow;
    int bind(int, const(sockaddr)*, uint) @nogc nothrow;
    int socketpair(int, int, int, int*) @nogc nothrow;
    int socket(int, int, int) @nogc nothrow;
    enum _Anonymous_29
    {
        SHUT_RD = 0,
        SHUT_WR = 1,
        SHUT_RDWR = 2,
    }
    enum SHUT_RD = _Anonymous_29.SHUT_RD;
    enum SHUT_WR = _Anonymous_29.SHUT_WR;
    enum SHUT_RDWR = _Anonymous_29.SHUT_RDWR;
    int pselect(int, fd_set*, fd_set*, fd_set*, const(timespec)*, const(__sigset_t)*) @nogc nothrow;
    int select(int, fd_set*, fd_set*, fd_set*, timeval*) @nogc nothrow;
    alias fd_mask = c_long;
    struct fd_set
    {
        c_long[16] __fds_bits;
    }
    alias __fd_mask = c_long;
    int poll(pollfd*, c_ulong, int) @nogc nothrow;
    struct pollfd
    {
        int fd;
        short events;
        short revents;
    }
    alias nfds_t = c_ulong;
    alias __kernel_long_t = c_long;
    alias __kernel_ulong_t = c_ulong;
    alias __kernel_ino_t = c_ulong;
    alias __kernel_mode_t = uint;
    alias __kernel_pid_t = int;
    alias __kernel_ipc_pid_t = int;
    alias __kernel_uid_t = uint;
    alias __kernel_gid_t = uint;
    alias __kernel_suseconds_t = c_long;
    alias __kernel_daddr_t = int;
    alias __kernel_uid32_t = uint;
    alias __kernel_gid32_t = uint;
    alias __kernel_size_t = c_ulong;
    alias __kernel_ssize_t = c_long;
    alias __kernel_ptrdiff_t = c_long;
    struct __kernel_fsid_t
    {
        int[2] val;
    }
    alias __kernel_off_t = c_long;
    alias __kernel_loff_t = long;
    alias __kernel_time_t = c_long;
    alias __kernel_time64_t = long;
    alias __kernel_clock_t = c_long;
    alias __kernel_timer_t = int;
    alias __kernel_clockid_t = int;
    alias __kernel_caddr_t = char*;
    alias __kernel_uid16_t = ushort;
    alias __kernel_gid16_t = ushort;
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
    alias __kernel_old_uid_t = ushort;
    alias __kernel_old_gid_t = ushort;
    alias __kernel_old_dev_t = c_ulong;
    char* __stpcpy(char*, const(char)*) @nogc nothrow;
    static ushort __bswap_16(ushort) @nogc nothrow;
    char* strsignal(int) @nogc nothrow;
    static uint __bswap_32(uint) @nogc nothrow;
    static c_ulong __bswap_64(c_ulong) @nogc nothrow;
    enum _Anonymous_30
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
    enum _PC_LINK_MAX = _Anonymous_30._PC_LINK_MAX;
    enum _PC_MAX_CANON = _Anonymous_30._PC_MAX_CANON;
    enum _PC_MAX_INPUT = _Anonymous_30._PC_MAX_INPUT;
    enum _PC_NAME_MAX = _Anonymous_30._PC_NAME_MAX;
    enum _PC_PATH_MAX = _Anonymous_30._PC_PATH_MAX;
    enum _PC_PIPE_BUF = _Anonymous_30._PC_PIPE_BUF;
    enum _PC_CHOWN_RESTRICTED = _Anonymous_30._PC_CHOWN_RESTRICTED;
    enum _PC_NO_TRUNC = _Anonymous_30._PC_NO_TRUNC;
    enum _PC_VDISABLE = _Anonymous_30._PC_VDISABLE;
    enum _PC_SYNC_IO = _Anonymous_30._PC_SYNC_IO;
    enum _PC_ASYNC_IO = _Anonymous_30._PC_ASYNC_IO;
    enum _PC_PRIO_IO = _Anonymous_30._PC_PRIO_IO;
    enum _PC_SOCK_MAXBUF = _Anonymous_30._PC_SOCK_MAXBUF;
    enum _PC_FILESIZEBITS = _Anonymous_30._PC_FILESIZEBITS;
    enum _PC_REC_INCR_XFER_SIZE = _Anonymous_30._PC_REC_INCR_XFER_SIZE;
    enum _PC_REC_MAX_XFER_SIZE = _Anonymous_30._PC_REC_MAX_XFER_SIZE;
    enum _PC_REC_MIN_XFER_SIZE = _Anonymous_30._PC_REC_MIN_XFER_SIZE;
    enum _PC_REC_XFER_ALIGN = _Anonymous_30._PC_REC_XFER_ALIGN;
    enum _PC_ALLOC_SIZE_MIN = _Anonymous_30._PC_ALLOC_SIZE_MIN;
    enum _PC_SYMLINK_MAX = _Anonymous_30._PC_SYMLINK_MAX;
    enum _PC_2_SYMLINKS = _Anonymous_30._PC_2_SYMLINKS;
    char* strsep(char**, const(char)*) @nogc nothrow;
    void explicit_bzero(void*, c_ulong) @nogc nothrow;
    char* strerror_l(int, __locale_struct*) @nogc nothrow;
    int strerror_r(int, char*, c_ulong) @nogc nothrow;
    char* strerror(int) @nogc nothrow;
    enum _Anonymous_31
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
    enum _SC_ARG_MAX = _Anonymous_31._SC_ARG_MAX;
    enum _SC_CHILD_MAX = _Anonymous_31._SC_CHILD_MAX;
    enum _SC_CLK_TCK = _Anonymous_31._SC_CLK_TCK;
    enum _SC_NGROUPS_MAX = _Anonymous_31._SC_NGROUPS_MAX;
    enum _SC_OPEN_MAX = _Anonymous_31._SC_OPEN_MAX;
    enum _SC_STREAM_MAX = _Anonymous_31._SC_STREAM_MAX;
    enum _SC_TZNAME_MAX = _Anonymous_31._SC_TZNAME_MAX;
    enum _SC_JOB_CONTROL = _Anonymous_31._SC_JOB_CONTROL;
    enum _SC_SAVED_IDS = _Anonymous_31._SC_SAVED_IDS;
    enum _SC_REALTIME_SIGNALS = _Anonymous_31._SC_REALTIME_SIGNALS;
    enum _SC_PRIORITY_SCHEDULING = _Anonymous_31._SC_PRIORITY_SCHEDULING;
    enum _SC_TIMERS = _Anonymous_31._SC_TIMERS;
    enum _SC_ASYNCHRONOUS_IO = _Anonymous_31._SC_ASYNCHRONOUS_IO;
    enum _SC_PRIORITIZED_IO = _Anonymous_31._SC_PRIORITIZED_IO;
    enum _SC_SYNCHRONIZED_IO = _Anonymous_31._SC_SYNCHRONIZED_IO;
    enum _SC_FSYNC = _Anonymous_31._SC_FSYNC;
    enum _SC_MAPPED_FILES = _Anonymous_31._SC_MAPPED_FILES;
    enum _SC_MEMLOCK = _Anonymous_31._SC_MEMLOCK;
    enum _SC_MEMLOCK_RANGE = _Anonymous_31._SC_MEMLOCK_RANGE;
    enum _SC_MEMORY_PROTECTION = _Anonymous_31._SC_MEMORY_PROTECTION;
    enum _SC_MESSAGE_PASSING = _Anonymous_31._SC_MESSAGE_PASSING;
    enum _SC_SEMAPHORES = _Anonymous_31._SC_SEMAPHORES;
    enum _SC_SHARED_MEMORY_OBJECTS = _Anonymous_31._SC_SHARED_MEMORY_OBJECTS;
    enum _SC_AIO_LISTIO_MAX = _Anonymous_31._SC_AIO_LISTIO_MAX;
    enum _SC_AIO_MAX = _Anonymous_31._SC_AIO_MAX;
    enum _SC_AIO_PRIO_DELTA_MAX = _Anonymous_31._SC_AIO_PRIO_DELTA_MAX;
    enum _SC_DELAYTIMER_MAX = _Anonymous_31._SC_DELAYTIMER_MAX;
    enum _SC_MQ_OPEN_MAX = _Anonymous_31._SC_MQ_OPEN_MAX;
    enum _SC_MQ_PRIO_MAX = _Anonymous_31._SC_MQ_PRIO_MAX;
    enum _SC_VERSION = _Anonymous_31._SC_VERSION;
    enum _SC_PAGESIZE = _Anonymous_31._SC_PAGESIZE;
    enum _SC_RTSIG_MAX = _Anonymous_31._SC_RTSIG_MAX;
    enum _SC_SEM_NSEMS_MAX = _Anonymous_31._SC_SEM_NSEMS_MAX;
    enum _SC_SEM_VALUE_MAX = _Anonymous_31._SC_SEM_VALUE_MAX;
    enum _SC_SIGQUEUE_MAX = _Anonymous_31._SC_SIGQUEUE_MAX;
    enum _SC_TIMER_MAX = _Anonymous_31._SC_TIMER_MAX;
    enum _SC_BC_BASE_MAX = _Anonymous_31._SC_BC_BASE_MAX;
    enum _SC_BC_DIM_MAX = _Anonymous_31._SC_BC_DIM_MAX;
    enum _SC_BC_SCALE_MAX = _Anonymous_31._SC_BC_SCALE_MAX;
    enum _SC_BC_STRING_MAX = _Anonymous_31._SC_BC_STRING_MAX;
    enum _SC_COLL_WEIGHTS_MAX = _Anonymous_31._SC_COLL_WEIGHTS_MAX;
    enum _SC_EQUIV_CLASS_MAX = _Anonymous_31._SC_EQUIV_CLASS_MAX;
    enum _SC_EXPR_NEST_MAX = _Anonymous_31._SC_EXPR_NEST_MAX;
    enum _SC_LINE_MAX = _Anonymous_31._SC_LINE_MAX;
    enum _SC_RE_DUP_MAX = _Anonymous_31._SC_RE_DUP_MAX;
    enum _SC_CHARCLASS_NAME_MAX = _Anonymous_31._SC_CHARCLASS_NAME_MAX;
    enum _SC_2_VERSION = _Anonymous_31._SC_2_VERSION;
    enum _SC_2_C_BIND = _Anonymous_31._SC_2_C_BIND;
    enum _SC_2_C_DEV = _Anonymous_31._SC_2_C_DEV;
    enum _SC_2_FORT_DEV = _Anonymous_31._SC_2_FORT_DEV;
    enum _SC_2_FORT_RUN = _Anonymous_31._SC_2_FORT_RUN;
    enum _SC_2_SW_DEV = _Anonymous_31._SC_2_SW_DEV;
    enum _SC_2_LOCALEDEF = _Anonymous_31._SC_2_LOCALEDEF;
    enum _SC_PII = _Anonymous_31._SC_PII;
    enum _SC_PII_XTI = _Anonymous_31._SC_PII_XTI;
    enum _SC_PII_SOCKET = _Anonymous_31._SC_PII_SOCKET;
    enum _SC_PII_INTERNET = _Anonymous_31._SC_PII_INTERNET;
    enum _SC_PII_OSI = _Anonymous_31._SC_PII_OSI;
    enum _SC_POLL = _Anonymous_31._SC_POLL;
    enum _SC_SELECT = _Anonymous_31._SC_SELECT;
    enum _SC_UIO_MAXIOV = _Anonymous_31._SC_UIO_MAXIOV;
    enum _SC_IOV_MAX = _Anonymous_31._SC_IOV_MAX;
    enum _SC_PII_INTERNET_STREAM = _Anonymous_31._SC_PII_INTERNET_STREAM;
    enum _SC_PII_INTERNET_DGRAM = _Anonymous_31._SC_PII_INTERNET_DGRAM;
    enum _SC_PII_OSI_COTS = _Anonymous_31._SC_PII_OSI_COTS;
    enum _SC_PII_OSI_CLTS = _Anonymous_31._SC_PII_OSI_CLTS;
    enum _SC_PII_OSI_M = _Anonymous_31._SC_PII_OSI_M;
    enum _SC_T_IOV_MAX = _Anonymous_31._SC_T_IOV_MAX;
    enum _SC_THREADS = _Anonymous_31._SC_THREADS;
    enum _SC_THREAD_SAFE_FUNCTIONS = _Anonymous_31._SC_THREAD_SAFE_FUNCTIONS;
    enum _SC_GETGR_R_SIZE_MAX = _Anonymous_31._SC_GETGR_R_SIZE_MAX;
    enum _SC_GETPW_R_SIZE_MAX = _Anonymous_31._SC_GETPW_R_SIZE_MAX;
    enum _SC_LOGIN_NAME_MAX = _Anonymous_31._SC_LOGIN_NAME_MAX;
    enum _SC_TTY_NAME_MAX = _Anonymous_31._SC_TTY_NAME_MAX;
    enum _SC_THREAD_DESTRUCTOR_ITERATIONS = _Anonymous_31._SC_THREAD_DESTRUCTOR_ITERATIONS;
    enum _SC_THREAD_KEYS_MAX = _Anonymous_31._SC_THREAD_KEYS_MAX;
    enum _SC_THREAD_STACK_MIN = _Anonymous_31._SC_THREAD_STACK_MIN;
    enum _SC_THREAD_THREADS_MAX = _Anonymous_31._SC_THREAD_THREADS_MAX;
    enum _SC_THREAD_ATTR_STACKADDR = _Anonymous_31._SC_THREAD_ATTR_STACKADDR;
    enum _SC_THREAD_ATTR_STACKSIZE = _Anonymous_31._SC_THREAD_ATTR_STACKSIZE;
    enum _SC_THREAD_PRIORITY_SCHEDULING = _Anonymous_31._SC_THREAD_PRIORITY_SCHEDULING;
    enum _SC_THREAD_PRIO_INHERIT = _Anonymous_31._SC_THREAD_PRIO_INHERIT;
    enum _SC_THREAD_PRIO_PROTECT = _Anonymous_31._SC_THREAD_PRIO_PROTECT;
    enum _SC_THREAD_PROCESS_SHARED = _Anonymous_31._SC_THREAD_PROCESS_SHARED;
    enum _SC_NPROCESSORS_CONF = _Anonymous_31._SC_NPROCESSORS_CONF;
    enum _SC_NPROCESSORS_ONLN = _Anonymous_31._SC_NPROCESSORS_ONLN;
    enum _SC_PHYS_PAGES = _Anonymous_31._SC_PHYS_PAGES;
    enum _SC_AVPHYS_PAGES = _Anonymous_31._SC_AVPHYS_PAGES;
    enum _SC_ATEXIT_MAX = _Anonymous_31._SC_ATEXIT_MAX;
    enum _SC_PASS_MAX = _Anonymous_31._SC_PASS_MAX;
    enum _SC_XOPEN_VERSION = _Anonymous_31._SC_XOPEN_VERSION;
    enum _SC_XOPEN_XCU_VERSION = _Anonymous_31._SC_XOPEN_XCU_VERSION;
    enum _SC_XOPEN_UNIX = _Anonymous_31._SC_XOPEN_UNIX;
    enum _SC_XOPEN_CRYPT = _Anonymous_31._SC_XOPEN_CRYPT;
    enum _SC_XOPEN_ENH_I18N = _Anonymous_31._SC_XOPEN_ENH_I18N;
    enum _SC_XOPEN_SHM = _Anonymous_31._SC_XOPEN_SHM;
    enum _SC_2_CHAR_TERM = _Anonymous_31._SC_2_CHAR_TERM;
    enum _SC_2_C_VERSION = _Anonymous_31._SC_2_C_VERSION;
    enum _SC_2_UPE = _Anonymous_31._SC_2_UPE;
    enum _SC_XOPEN_XPG2 = _Anonymous_31._SC_XOPEN_XPG2;
    enum _SC_XOPEN_XPG3 = _Anonymous_31._SC_XOPEN_XPG3;
    enum _SC_XOPEN_XPG4 = _Anonymous_31._SC_XOPEN_XPG4;
    enum _SC_CHAR_BIT = _Anonymous_31._SC_CHAR_BIT;
    enum _SC_CHAR_MAX = _Anonymous_31._SC_CHAR_MAX;
    enum _SC_CHAR_MIN = _Anonymous_31._SC_CHAR_MIN;
    enum _SC_INT_MAX = _Anonymous_31._SC_INT_MAX;
    enum _SC_INT_MIN = _Anonymous_31._SC_INT_MIN;
    enum _SC_LONG_BIT = _Anonymous_31._SC_LONG_BIT;
    enum _SC_WORD_BIT = _Anonymous_31._SC_WORD_BIT;
    enum _SC_MB_LEN_MAX = _Anonymous_31._SC_MB_LEN_MAX;
    enum _SC_NZERO = _Anonymous_31._SC_NZERO;
    enum _SC_SSIZE_MAX = _Anonymous_31._SC_SSIZE_MAX;
    enum _SC_SCHAR_MAX = _Anonymous_31._SC_SCHAR_MAX;
    enum _SC_SCHAR_MIN = _Anonymous_31._SC_SCHAR_MIN;
    enum _SC_SHRT_MAX = _Anonymous_31._SC_SHRT_MAX;
    enum _SC_SHRT_MIN = _Anonymous_31._SC_SHRT_MIN;
    enum _SC_UCHAR_MAX = _Anonymous_31._SC_UCHAR_MAX;
    enum _SC_UINT_MAX = _Anonymous_31._SC_UINT_MAX;
    enum _SC_ULONG_MAX = _Anonymous_31._SC_ULONG_MAX;
    enum _SC_USHRT_MAX = _Anonymous_31._SC_USHRT_MAX;
    enum _SC_NL_ARGMAX = _Anonymous_31._SC_NL_ARGMAX;
    enum _SC_NL_LANGMAX = _Anonymous_31._SC_NL_LANGMAX;
    enum _SC_NL_MSGMAX = _Anonymous_31._SC_NL_MSGMAX;
    enum _SC_NL_NMAX = _Anonymous_31._SC_NL_NMAX;
    enum _SC_NL_SETMAX = _Anonymous_31._SC_NL_SETMAX;
    enum _SC_NL_TEXTMAX = _Anonymous_31._SC_NL_TEXTMAX;
    enum _SC_XBS5_ILP32_OFF32 = _Anonymous_31._SC_XBS5_ILP32_OFF32;
    enum _SC_XBS5_ILP32_OFFBIG = _Anonymous_31._SC_XBS5_ILP32_OFFBIG;
    enum _SC_XBS5_LP64_OFF64 = _Anonymous_31._SC_XBS5_LP64_OFF64;
    enum _SC_XBS5_LPBIG_OFFBIG = _Anonymous_31._SC_XBS5_LPBIG_OFFBIG;
    enum _SC_XOPEN_LEGACY = _Anonymous_31._SC_XOPEN_LEGACY;
    enum _SC_XOPEN_REALTIME = _Anonymous_31._SC_XOPEN_REALTIME;
    enum _SC_XOPEN_REALTIME_THREADS = _Anonymous_31._SC_XOPEN_REALTIME_THREADS;
    enum _SC_ADVISORY_INFO = _Anonymous_31._SC_ADVISORY_INFO;
    enum _SC_BARRIERS = _Anonymous_31._SC_BARRIERS;
    enum _SC_BASE = _Anonymous_31._SC_BASE;
    enum _SC_C_LANG_SUPPORT = _Anonymous_31._SC_C_LANG_SUPPORT;
    enum _SC_C_LANG_SUPPORT_R = _Anonymous_31._SC_C_LANG_SUPPORT_R;
    enum _SC_CLOCK_SELECTION = _Anonymous_31._SC_CLOCK_SELECTION;
    enum _SC_CPUTIME = _Anonymous_31._SC_CPUTIME;
    enum _SC_THREAD_CPUTIME = _Anonymous_31._SC_THREAD_CPUTIME;
    enum _SC_DEVICE_IO = _Anonymous_31._SC_DEVICE_IO;
    enum _SC_DEVICE_SPECIFIC = _Anonymous_31._SC_DEVICE_SPECIFIC;
    enum _SC_DEVICE_SPECIFIC_R = _Anonymous_31._SC_DEVICE_SPECIFIC_R;
    enum _SC_FD_MGMT = _Anonymous_31._SC_FD_MGMT;
    enum _SC_FIFO = _Anonymous_31._SC_FIFO;
    enum _SC_PIPE = _Anonymous_31._SC_PIPE;
    enum _SC_FILE_ATTRIBUTES = _Anonymous_31._SC_FILE_ATTRIBUTES;
    enum _SC_FILE_LOCKING = _Anonymous_31._SC_FILE_LOCKING;
    enum _SC_FILE_SYSTEM = _Anonymous_31._SC_FILE_SYSTEM;
    enum _SC_MONOTONIC_CLOCK = _Anonymous_31._SC_MONOTONIC_CLOCK;
    enum _SC_MULTI_PROCESS = _Anonymous_31._SC_MULTI_PROCESS;
    enum _SC_SINGLE_PROCESS = _Anonymous_31._SC_SINGLE_PROCESS;
    enum _SC_NETWORKING = _Anonymous_31._SC_NETWORKING;
    enum _SC_READER_WRITER_LOCKS = _Anonymous_31._SC_READER_WRITER_LOCKS;
    enum _SC_SPIN_LOCKS = _Anonymous_31._SC_SPIN_LOCKS;
    enum _SC_REGEXP = _Anonymous_31._SC_REGEXP;
    enum _SC_REGEX_VERSION = _Anonymous_31._SC_REGEX_VERSION;
    enum _SC_SHELL = _Anonymous_31._SC_SHELL;
    enum _SC_SIGNALS = _Anonymous_31._SC_SIGNALS;
    enum _SC_SPAWN = _Anonymous_31._SC_SPAWN;
    enum _SC_SPORADIC_SERVER = _Anonymous_31._SC_SPORADIC_SERVER;
    enum _SC_THREAD_SPORADIC_SERVER = _Anonymous_31._SC_THREAD_SPORADIC_SERVER;
    enum _SC_SYSTEM_DATABASE = _Anonymous_31._SC_SYSTEM_DATABASE;
    enum _SC_SYSTEM_DATABASE_R = _Anonymous_31._SC_SYSTEM_DATABASE_R;
    enum _SC_TIMEOUTS = _Anonymous_31._SC_TIMEOUTS;
    enum _SC_TYPED_MEMORY_OBJECTS = _Anonymous_31._SC_TYPED_MEMORY_OBJECTS;
    enum _SC_USER_GROUPS = _Anonymous_31._SC_USER_GROUPS;
    enum _SC_USER_GROUPS_R = _Anonymous_31._SC_USER_GROUPS_R;
    enum _SC_2_PBS = _Anonymous_31._SC_2_PBS;
    enum _SC_2_PBS_ACCOUNTING = _Anonymous_31._SC_2_PBS_ACCOUNTING;
    enum _SC_2_PBS_LOCATE = _Anonymous_31._SC_2_PBS_LOCATE;
    enum _SC_2_PBS_MESSAGE = _Anonymous_31._SC_2_PBS_MESSAGE;
    enum _SC_2_PBS_TRACK = _Anonymous_31._SC_2_PBS_TRACK;
    enum _SC_SYMLOOP_MAX = _Anonymous_31._SC_SYMLOOP_MAX;
    enum _SC_STREAMS = _Anonymous_31._SC_STREAMS;
    enum _SC_2_PBS_CHECKPOINT = _Anonymous_31._SC_2_PBS_CHECKPOINT;
    enum _SC_V6_ILP32_OFF32 = _Anonymous_31._SC_V6_ILP32_OFF32;
    enum _SC_V6_ILP32_OFFBIG = _Anonymous_31._SC_V6_ILP32_OFFBIG;
    enum _SC_V6_LP64_OFF64 = _Anonymous_31._SC_V6_LP64_OFF64;
    enum _SC_V6_LPBIG_OFFBIG = _Anonymous_31._SC_V6_LPBIG_OFFBIG;
    enum _SC_HOST_NAME_MAX = _Anonymous_31._SC_HOST_NAME_MAX;
    enum _SC_TRACE = _Anonymous_31._SC_TRACE;
    enum _SC_TRACE_EVENT_FILTER = _Anonymous_31._SC_TRACE_EVENT_FILTER;
    enum _SC_TRACE_INHERIT = _Anonymous_31._SC_TRACE_INHERIT;
    enum _SC_TRACE_LOG = _Anonymous_31._SC_TRACE_LOG;
    enum _SC_LEVEL1_ICACHE_SIZE = _Anonymous_31._SC_LEVEL1_ICACHE_SIZE;
    enum _SC_LEVEL1_ICACHE_ASSOC = _Anonymous_31._SC_LEVEL1_ICACHE_ASSOC;
    enum _SC_LEVEL1_ICACHE_LINESIZE = _Anonymous_31._SC_LEVEL1_ICACHE_LINESIZE;
    enum _SC_LEVEL1_DCACHE_SIZE = _Anonymous_31._SC_LEVEL1_DCACHE_SIZE;
    enum _SC_LEVEL1_DCACHE_ASSOC = _Anonymous_31._SC_LEVEL1_DCACHE_ASSOC;
    enum _SC_LEVEL1_DCACHE_LINESIZE = _Anonymous_31._SC_LEVEL1_DCACHE_LINESIZE;
    enum _SC_LEVEL2_CACHE_SIZE = _Anonymous_31._SC_LEVEL2_CACHE_SIZE;
    enum _SC_LEVEL2_CACHE_ASSOC = _Anonymous_31._SC_LEVEL2_CACHE_ASSOC;
    enum _SC_LEVEL2_CACHE_LINESIZE = _Anonymous_31._SC_LEVEL2_CACHE_LINESIZE;
    enum _SC_LEVEL3_CACHE_SIZE = _Anonymous_31._SC_LEVEL3_CACHE_SIZE;
    enum _SC_LEVEL3_CACHE_ASSOC = _Anonymous_31._SC_LEVEL3_CACHE_ASSOC;
    enum _SC_LEVEL3_CACHE_LINESIZE = _Anonymous_31._SC_LEVEL3_CACHE_LINESIZE;
    enum _SC_LEVEL4_CACHE_SIZE = _Anonymous_31._SC_LEVEL4_CACHE_SIZE;
    enum _SC_LEVEL4_CACHE_ASSOC = _Anonymous_31._SC_LEVEL4_CACHE_ASSOC;
    enum _SC_LEVEL4_CACHE_LINESIZE = _Anonymous_31._SC_LEVEL4_CACHE_LINESIZE;
    enum _SC_IPV6 = _Anonymous_31._SC_IPV6;
    enum _SC_RAW_SOCKETS = _Anonymous_31._SC_RAW_SOCKETS;
    enum _SC_V7_ILP32_OFF32 = _Anonymous_31._SC_V7_ILP32_OFF32;
    enum _SC_V7_ILP32_OFFBIG = _Anonymous_31._SC_V7_ILP32_OFFBIG;
    enum _SC_V7_LP64_OFF64 = _Anonymous_31._SC_V7_LP64_OFF64;
    enum _SC_V7_LPBIG_OFFBIG = _Anonymous_31._SC_V7_LPBIG_OFFBIG;
    enum _SC_SS_REPL_MAX = _Anonymous_31._SC_SS_REPL_MAX;
    enum _SC_TRACE_EVENT_NAME_MAX = _Anonymous_31._SC_TRACE_EVENT_NAME_MAX;
    enum _SC_TRACE_NAME_MAX = _Anonymous_31._SC_TRACE_NAME_MAX;
    enum _SC_TRACE_SYS_MAX = _Anonymous_31._SC_TRACE_SYS_MAX;
    enum _SC_TRACE_USER_EVENT_MAX = _Anonymous_31._SC_TRACE_USER_EVENT_MAX;
    enum _SC_XOPEN_STREAMS = _Anonymous_31._SC_XOPEN_STREAMS;
    enum _SC_THREAD_ROBUST_PRIO_INHERIT = _Anonymous_31._SC_THREAD_ROBUST_PRIO_INHERIT;
    enum _SC_THREAD_ROBUST_PRIO_PROTECT = _Anonymous_31._SC_THREAD_ROBUST_PRIO_PROTECT;
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
    void* bsearch(const(void)*, const(void)*, c_ulong, c_ulong, int function(const(void)*, const(void)*)) @nogc nothrow;
    alias __compar_fn_t = int function(const(void)*, const(void)*);
    char* realpath(const(char)*, char*) @nogc nothrow;
    int system(const(char)*) @nogc nothrow;
    enum _Anonymous_32
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
    enum _CS_PATH = _Anonymous_32._CS_PATH;
    enum _CS_V6_WIDTH_RESTRICTED_ENVS = _Anonymous_32._CS_V6_WIDTH_RESTRICTED_ENVS;
    enum _CS_GNU_LIBC_VERSION = _Anonymous_32._CS_GNU_LIBC_VERSION;
    enum _CS_GNU_LIBPTHREAD_VERSION = _Anonymous_32._CS_GNU_LIBPTHREAD_VERSION;
    enum _CS_V5_WIDTH_RESTRICTED_ENVS = _Anonymous_32._CS_V5_WIDTH_RESTRICTED_ENVS;
    enum _CS_V7_WIDTH_RESTRICTED_ENVS = _Anonymous_32._CS_V7_WIDTH_RESTRICTED_ENVS;
    enum _CS_LFS_CFLAGS = _Anonymous_32._CS_LFS_CFLAGS;
    enum _CS_LFS_LDFLAGS = _Anonymous_32._CS_LFS_LDFLAGS;
    enum _CS_LFS_LIBS = _Anonymous_32._CS_LFS_LIBS;
    enum _CS_LFS_LINTFLAGS = _Anonymous_32._CS_LFS_LINTFLAGS;
    enum _CS_LFS64_CFLAGS = _Anonymous_32._CS_LFS64_CFLAGS;
    enum _CS_LFS64_LDFLAGS = _Anonymous_32._CS_LFS64_LDFLAGS;
    enum _CS_LFS64_LIBS = _Anonymous_32._CS_LFS64_LIBS;
    enum _CS_LFS64_LINTFLAGS = _Anonymous_32._CS_LFS64_LINTFLAGS;
    enum _CS_XBS5_ILP32_OFF32_CFLAGS = _Anonymous_32._CS_XBS5_ILP32_OFF32_CFLAGS;
    enum _CS_XBS5_ILP32_OFF32_LDFLAGS = _Anonymous_32._CS_XBS5_ILP32_OFF32_LDFLAGS;
    enum _CS_XBS5_ILP32_OFF32_LIBS = _Anonymous_32._CS_XBS5_ILP32_OFF32_LIBS;
    enum _CS_XBS5_ILP32_OFF32_LINTFLAGS = _Anonymous_32._CS_XBS5_ILP32_OFF32_LINTFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_CFLAGS = _Anonymous_32._CS_XBS5_ILP32_OFFBIG_CFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_LDFLAGS = _Anonymous_32._CS_XBS5_ILP32_OFFBIG_LDFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_LIBS = _Anonymous_32._CS_XBS5_ILP32_OFFBIG_LIBS;
    enum _CS_XBS5_ILP32_OFFBIG_LINTFLAGS = _Anonymous_32._CS_XBS5_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_XBS5_LP64_OFF64_CFLAGS = _Anonymous_32._CS_XBS5_LP64_OFF64_CFLAGS;
    enum _CS_XBS5_LP64_OFF64_LDFLAGS = _Anonymous_32._CS_XBS5_LP64_OFF64_LDFLAGS;
    enum _CS_XBS5_LP64_OFF64_LIBS = _Anonymous_32._CS_XBS5_LP64_OFF64_LIBS;
    enum _CS_XBS5_LP64_OFF64_LINTFLAGS = _Anonymous_32._CS_XBS5_LP64_OFF64_LINTFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_CFLAGS = _Anonymous_32._CS_XBS5_LPBIG_OFFBIG_CFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_LDFLAGS = _Anonymous_32._CS_XBS5_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_LIBS = _Anonymous_32._CS_XBS5_LPBIG_OFFBIG_LIBS;
    enum _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_32._CS_XBS5_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_CFLAGS = _Anonymous_32._CS_POSIX_V6_ILP32_OFF32_CFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_LDFLAGS = _Anonymous_32._CS_POSIX_V6_ILP32_OFF32_LDFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_LIBS = _Anonymous_32._CS_POSIX_V6_ILP32_OFF32_LIBS;
    enum _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = _Anonymous_32._CS_POSIX_V6_ILP32_OFF32_LINTFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = _Anonymous_32._CS_POSIX_V6_ILP32_OFFBIG_CFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = _Anonymous_32._CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LIBS = _Anonymous_32._CS_POSIX_V6_ILP32_OFFBIG_LIBS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = _Anonymous_32._CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_CFLAGS = _Anonymous_32._CS_POSIX_V6_LP64_OFF64_CFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_LDFLAGS = _Anonymous_32._CS_POSIX_V6_LP64_OFF64_LDFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_LIBS = _Anonymous_32._CS_POSIX_V6_LP64_OFF64_LIBS;
    enum _CS_POSIX_V6_LP64_OFF64_LINTFLAGS = _Anonymous_32._CS_POSIX_V6_LP64_OFF64_LINTFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = _Anonymous_32._CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = _Anonymous_32._CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LIBS = _Anonymous_32._CS_POSIX_V6_LPBIG_OFFBIG_LIBS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_32._CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_CFLAGS = _Anonymous_32._CS_POSIX_V7_ILP32_OFF32_CFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_LDFLAGS = _Anonymous_32._CS_POSIX_V7_ILP32_OFF32_LDFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_LIBS = _Anonymous_32._CS_POSIX_V7_ILP32_OFF32_LIBS;
    enum _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = _Anonymous_32._CS_POSIX_V7_ILP32_OFF32_LINTFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = _Anonymous_32._CS_POSIX_V7_ILP32_OFFBIG_CFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = _Anonymous_32._CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LIBS = _Anonymous_32._CS_POSIX_V7_ILP32_OFFBIG_LIBS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = _Anonymous_32._CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_CFLAGS = _Anonymous_32._CS_POSIX_V7_LP64_OFF64_CFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_LDFLAGS = _Anonymous_32._CS_POSIX_V7_LP64_OFF64_LDFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_LIBS = _Anonymous_32._CS_POSIX_V7_LP64_OFF64_LIBS;
    enum _CS_POSIX_V7_LP64_OFF64_LINTFLAGS = _Anonymous_32._CS_POSIX_V7_LP64_OFF64_LINTFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = _Anonymous_32._CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = _Anonymous_32._CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LIBS = _Anonymous_32._CS_POSIX_V7_LPBIG_OFFBIG_LIBS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_32._CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_V6_ENV = _Anonymous_32._CS_V6_ENV;
    enum _CS_V7_ENV = _Anonymous_32._CS_V7_ENV;
    char* mkdtemp(char*) @nogc nothrow;
    int mkstemps(char*, int) @nogc nothrow;
    int mkstemp(char*) @nogc nothrow;
    char* mktemp(char*) @nogc nothrow;
    int clearenv() @nogc nothrow;
    int unsetenv(const(char)*) @nogc nothrow;
    int setenv(const(char)*, const(char)*, int) @nogc nothrow;
    int putenv(char*) @nogc nothrow;
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
    struct flock
    {
        short l_type;
        short l_whence;
        c_long l_start;
        c_long l_len;
        int l_pid;
    }
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
    alias _Float32 = float;
    c_long random() @nogc nothrow;
    alias _Float64 = double;
    c_long a64l(const(char)*) @nogc nothrow;
    alias _Float32x = double;
    char* l64a(c_long) @nogc nothrow;
    alias _Float64x = real;
    extern __gshared char* optarg;
    extern __gshared int optind;
    extern __gshared int opterr;
    extern __gshared int optopt;
    int getopt(int, char**, const(char)*) @nogc nothrow;
    ulong strtoull(const(char)*, char**, int) @nogc nothrow;
    long strtoll(const(char)*, char**, int) @nogc nothrow;
    ulong strtouq(const(char)*, char**, int) @nogc nothrow;
    long strtoq(const(char)*, char**, int) @nogc nothrow;
    c_ulong strtoul(const(char)*, char**, int) @nogc nothrow;
    c_long strtol(const(char)*, char**, int) @nogc nothrow;
    real strtold(const(char)*, char**) @nogc nothrow;
    float strtof(const(char)*, char**) @nogc nothrow;
    double strtod(const(char)*, char**) @nogc nothrow;
    long atoll(const(char)*) @nogc nothrow;
    c_long atol(const(char)*) @nogc nothrow;
    int atoi(const(char)*) @nogc nothrow;
    double atof(const(char)*) @nogc nothrow;
    c_ulong __ctype_get_mb_cur_max() @nogc nothrow;
    struct ip_opts
    {
        in_addr ip_dst;
        char[40] ip_opts_;
    }
    struct ip_mreqn
    {
        in_addr imr_multiaddr;
        in_addr imr_address;
        int imr_ifindex;
    }
    struct in_pktinfo
    {
        int ipi_ifindex;
        in_addr ipi_spec_dst;
        in_addr ipi_addr;
    }
    struct lldiv_t
    {
        long quot;
        long rem;
    }
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
    int __overflow(_IO_FILE*, int) @nogc nothrow;
    int __uflow(_IO_FILE*) @nogc nothrow;
    void funlockfile(_IO_FILE*) @nogc nothrow;
    int ftrylockfile(_IO_FILE*) @nogc nothrow;
    void flockfile(_IO_FILE*) @nogc nothrow;
    char* ctermid(char*) @nogc nothrow;
    int pclose(_IO_FILE*) @nogc nothrow;
    _IO_FILE* popen(const(char)*, const(char)*) @nogc nothrow;
    int fileno_unlocked(_IO_FILE*) @nogc nothrow;
    int fileno(_IO_FILE*) @nogc nothrow;
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
    struct netent
    {
        char* n_name;
        char** n_aliases;
        int n_addrtype;
        uint n_net;
    }
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
    int sscanf(const(char)*, const(char)*, ...) @nogc nothrow;
    int scanf(const(char)*, ...) @nogc nothrow;
    int fscanf(_IO_FILE*, const(char)*, ...) @nogc nothrow;
    int dprintf(int, const(char)*, ...) @nogc nothrow;
    int vdprintf(int, const(char)*, va_list*) @nogc nothrow;
    int vsnprintf(char*, c_ulong, const(char)*, va_list*) @nogc nothrow;
    int snprintf(char*, c_ulong, const(char)*, ...) @nogc nothrow;
    int vsprintf(char*, const(char)*, va_list*) @nogc nothrow;
    int vprintf(const(char)*, va_list*) @nogc nothrow;
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
    int rename(const(char)*, const(char)*) @nogc nothrow;
    int remove(const(char)*) @nogc nothrow;
    extern __gshared _IO_FILE* stderr;
    extern __gshared _IO_FILE* stdout;
    extern __gshared _IO_FILE* stdin;
    alias fpos_t = _G_fpos_t;
    alias ssize_t = c_long;
    alias off_t = c_long;
    alias uintmax_t = c_ulong;
    alias intmax_t = c_long;
    alias uintptr_t = c_ulong;
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
    alias uint_fast64_t = c_ulong;
    alias uint_fast32_t = c_ulong;
    alias uint_fast16_t = c_ulong;
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
    alias uint_fast8_t = ubyte;
    alias int_fast64_t = c_long;
    alias int_fast32_t = c_long;
    alias int_fast16_t = c_long;
    alias int_fast8_t = byte;
    alias sa_family_t = ushort;
    alias uint_least64_t = c_ulong;
    alias uint_least32_t = uint;
    alias uint_least16_t = ushort;
    alias uint_least8_t = ubyte;
    alias int_least64_t = c_long;
    alias int_least32_t = int;
    alias int_least16_t = short;
    alias int_least8_t = byte;
    int getrpcent_r(rpcent*, char*, c_ulong, rpcent**) @nogc nothrow;
    int getrpcbynumber_r(int, rpcent*, char*, c_ulong, rpcent**) @nogc nothrow;
    int getrpcbyname_r(const(char)*, rpcent*, char*, c_ulong, rpcent**) @nogc nothrow;
    rpcent* getrpcent() @nogc nothrow;
    rpcent* getrpcbynumber(int) @nogc nothrow;
    rpcent* getrpcbyname(const(char)*) @nogc nothrow;
    void endrpcent() @nogc nothrow;
    void setrpcent(int) @nogc nothrow;
    struct rpcent
    {
        char* r_name;
        char** r_aliases;
        int r_number;
    }
    struct tcp_zerocopy_receive
    {
        c_ulong address;
        uint length;
        uint recv_skip_hint;
    }
    struct tcp_repair_window
    {
        uint snd_wl1;
        uint snd_wnd;
        uint max_window;
        uint rcv_wnd;
        uint rcv_wup;
    }
    struct tcp_cookie_transactions
    {
        ushort tcpct_flags;
        ubyte __tcpct_pad1;
        ubyte tcpct_cookie_desired;
        ushort tcpct_s_data_desired;
        ushort tcpct_used;
        ubyte[536] tcpct_value;
    }
    enum _Anonymous_33
    {
        TCP_NO_QUEUE = 0,
        TCP_RECV_QUEUE = 1,
        TCP_SEND_QUEUE = 2,
        TCP_QUEUES_NR = 3,
    }
    enum TCP_NO_QUEUE = _Anonymous_33.TCP_NO_QUEUE;
    enum TCP_RECV_QUEUE = _Anonymous_33.TCP_RECV_QUEUE;
    enum TCP_SEND_QUEUE = _Anonymous_33.TCP_SEND_QUEUE;
    enum TCP_QUEUES_NR = _Anonymous_33.TCP_QUEUES_NR;
    struct tcp_repair_opt
    {
        uint opt_code;
        uint opt_val;
    }
    struct tcp_md5sig
    {
        sockaddr_storage tcpm_addr;
        ubyte tcpm_flags;
        ubyte tcpm_prefixlen;
        ushort tcpm_keylen;
        uint __tcpm_pad;
        ubyte[80] tcpm_key;
    }
    struct tcp_info
    {
        import std.bitmanip: bitfields;

        align(4):
        ubyte tcpi_state;
        ubyte tcpi_ca_state;
        ubyte tcpi_retransmits;
        ubyte tcpi_probes;
        ubyte tcpi_backoff;
        ubyte tcpi_options;
        mixin(bitfields!(
            ubyte, "tcpi_snd_wscale", 4,
            ubyte, "tcpi_rcv_wscale", 4,
        ));
        uint tcpi_rto;
        uint tcpi_ato;
        uint tcpi_snd_mss;
        uint tcpi_rcv_mss;
        uint tcpi_unacked;
        uint tcpi_sacked;
        uint tcpi_lost;
        uint tcpi_retrans;
        uint tcpi_fackets;
        uint tcpi_last_data_sent;
        uint tcpi_last_ack_sent;
        uint tcpi_last_data_recv;
        uint tcpi_last_ack_recv;
        uint tcpi_pmtu;
        uint tcpi_rcv_ssthresh;
        uint tcpi_rtt;
        uint tcpi_rttvar;
        uint tcpi_snd_ssthresh;
        uint tcpi_snd_cwnd;
        uint tcpi_advmss;
        uint tcpi_reordering;
        uint tcpi_rcv_rtt;
        uint tcpi_rcv_space;
        uint tcpi_total_retrans;
    }
    enum tcp_ca_state
    {
        TCP_CA_Open = 0,
        TCP_CA_Disorder = 1,
        TCP_CA_CWR = 2,
        TCP_CA_Recovery = 3,
        TCP_CA_Loss = 4,
    }
    enum TCP_CA_Open = tcp_ca_state.TCP_CA_Open;
    enum TCP_CA_Disorder = tcp_ca_state.TCP_CA_Disorder;
    enum TCP_CA_CWR = tcp_ca_state.TCP_CA_CWR;
    enum TCP_CA_Recovery = tcp_ca_state.TCP_CA_Recovery;
    enum TCP_CA_Loss = tcp_ca_state.TCP_CA_Loss;
    enum _Anonymous_34
    {
        TCP_ESTABLISHED = 1,
        TCP_SYN_SENT = 2,
        TCP_SYN_RECV = 3,
        TCP_FIN_WAIT1 = 4,
        TCP_FIN_WAIT2 = 5,
        TCP_TIME_WAIT = 6,
        TCP_CLOSE = 7,
        TCP_CLOSE_WAIT = 8,
        TCP_LAST_ACK = 9,
        TCP_LISTEN = 10,
        TCP_CLOSING = 11,
    }
    enum TCP_ESTABLISHED = _Anonymous_34.TCP_ESTABLISHED;
    enum TCP_SYN_SENT = _Anonymous_34.TCP_SYN_SENT;
    enum TCP_SYN_RECV = _Anonymous_34.TCP_SYN_RECV;
    enum TCP_FIN_WAIT1 = _Anonymous_34.TCP_FIN_WAIT1;
    enum TCP_FIN_WAIT2 = _Anonymous_34.TCP_FIN_WAIT2;
    enum TCP_TIME_WAIT = _Anonymous_34.TCP_TIME_WAIT;
    enum TCP_CLOSE = _Anonymous_34.TCP_CLOSE;
    enum TCP_CLOSE_WAIT = _Anonymous_34.TCP_CLOSE_WAIT;
    enum TCP_LAST_ACK = _Anonymous_34.TCP_LAST_ACK;
    enum TCP_LISTEN = _Anonymous_34.TCP_LISTEN;
    enum TCP_CLOSING = _Anonymous_34.TCP_CLOSING;
    struct tcphdr
    {
        static union _Anonymous_35
        {
            static struct _Anonymous_36
            {
                import std.bitmanip: bitfields;

                align(4):
                ushort th_sport;
                ushort th_dport;
                uint th_seq;
                uint th_ack;
                mixin(bitfields!(
                    ubyte, "th_x2", 4,
                    ubyte, "th_off", 4,
                ));
                ubyte th_flags;
                ushort th_win;
                ushort th_sum;
                ushort th_urp;
            }
            _Anonymous_36 _anonymous_37;
            auto th_sport() @property @nogc pure nothrow { return _anonymous_37.th_sport; }
            void th_sport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_sport = val; }
            auto th_dport() @property @nogc pure nothrow { return _anonymous_37.th_dport; }
            void th_dport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_dport = val; }
            auto th_seq() @property @nogc pure nothrow { return _anonymous_37.th_seq; }
            void th_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_seq = val; }
            auto th_ack() @property @nogc pure nothrow { return _anonymous_37.th_ack; }
            void th_ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_ack = val; }
            auto th_x2() @property @nogc pure nothrow { return _anonymous_37.th_x2; }
            void th_x2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_x2 = val; }
            auto th_off() @property @nogc pure nothrow { return _anonymous_37.th_off; }
            void th_off(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_off = val; }
            auto th_flags() @property @nogc pure nothrow { return _anonymous_37.th_flags; }
            void th_flags(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_flags = val; }
            auto th_win() @property @nogc pure nothrow { return _anonymous_37.th_win; }
            void th_win(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_win = val; }
            auto th_sum() @property @nogc pure nothrow { return _anonymous_37.th_sum; }
            void th_sum(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_sum = val; }
            auto th_urp() @property @nogc pure nothrow { return _anonymous_37.th_urp; }
            void th_urp(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_37.th_urp = val; }
            static struct _Anonymous_38
            {
                import std.bitmanip: bitfields;

                align(4):
                ushort source;
                ushort dest;
                uint seq;
                uint ack_seq;
                mixin(bitfields!(
                    ushort, "res1", 4,
                    ushort, "doff", 4,
                    ushort, "fin", 1,
                    ushort, "syn", 1,
                    ushort, "rst", 1,
                    ushort, "psh", 1,
                    ushort, "ack", 1,
                    ushort, "urg", 1,
                    ushort, "res2", 2,
                ));
                ushort window;
                ushort check;
                ushort urg_ptr;
            }
            _Anonymous_38 _anonymous_39;
            auto source() @property @nogc pure nothrow { return _anonymous_39.source; }
            void source(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.source = val; }
            auto dest() @property @nogc pure nothrow { return _anonymous_39.dest; }
            void dest(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.dest = val; }
            auto seq() @property @nogc pure nothrow { return _anonymous_39.seq; }
            void seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.seq = val; }
            auto ack_seq() @property @nogc pure nothrow { return _anonymous_39.ack_seq; }
            void ack_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.ack_seq = val; }
            auto res1() @property @nogc pure nothrow { return _anonymous_39.res1; }
            void res1(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.res1 = val; }
            auto doff() @property @nogc pure nothrow { return _anonymous_39.doff; }
            void doff(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.doff = val; }
            auto fin() @property @nogc pure nothrow { return _anonymous_39.fin; }
            void fin(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.fin = val; }
            auto syn() @property @nogc pure nothrow { return _anonymous_39.syn; }
            void syn(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.syn = val; }
            auto rst() @property @nogc pure nothrow { return _anonymous_39.rst; }
            void rst(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.rst = val; }
            auto psh() @property @nogc pure nothrow { return _anonymous_39.psh; }
            void psh(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.psh = val; }
            auto ack() @property @nogc pure nothrow { return _anonymous_39.ack; }
            void ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.ack = val; }
            auto urg() @property @nogc pure nothrow { return _anonymous_39.urg; }
            void urg(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.urg = val; }
            auto res2() @property @nogc pure nothrow { return _anonymous_39.res2; }
            void res2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.res2 = val; }
            auto window() @property @nogc pure nothrow { return _anonymous_39.window; }
            void window(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.window = val; }
            auto check() @property @nogc pure nothrow { return _anonymous_39.check; }
            void check(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.check = val; }
            auto urg_ptr() @property @nogc pure nothrow { return _anonymous_39.urg_ptr; }
            void urg_ptr(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_39.urg_ptr = val; }
        }
        _Anonymous_35 _anonymous_40;

        auto th_sport() @property @nogc pure nothrow { return _anonymous_40.th_sport; }
        void th_sport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_sport = val; }

        auto th_dport() @property @nogc pure nothrow { return _anonymous_40.th_dport; }
        void th_dport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_dport = val; }

        auto th_seq() @property @nogc pure nothrow { return _anonymous_40.th_seq; }
        void th_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_seq = val; }

        auto th_ack() @property @nogc pure nothrow { return _anonymous_40.th_ack; }
        void th_ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_ack = val; }

        auto th_x2() @property @nogc pure nothrow { return _anonymous_40.th_x2; }
        void th_x2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_x2 = val; }

        auto th_off() @property @nogc pure nothrow { return _anonymous_40.th_off; }
        void th_off(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_off = val; }

        auto th_flags() @property @nogc pure nothrow { return _anonymous_40.th_flags; }
        void th_flags(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_flags = val; }

        auto th_win() @property @nogc pure nothrow { return _anonymous_40.th_win; }
        void th_win(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_win = val; }

        auto th_sum() @property @nogc pure nothrow { return _anonymous_40.th_sum; }
        void th_sum(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_sum = val; }

        auto th_urp() @property @nogc pure nothrow { return _anonymous_40.th_urp; }
        void th_urp(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.th_urp = val; }

        auto source() @property @nogc pure nothrow { return _anonymous_40.source; }
        void source(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.source = val; }

        auto dest() @property @nogc pure nothrow { return _anonymous_40.dest; }
        void dest(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.dest = val; }

        auto seq() @property @nogc pure nothrow { return _anonymous_40.seq; }
        void seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.seq = val; }

        auto ack_seq() @property @nogc pure nothrow { return _anonymous_40.ack_seq; }
        void ack_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.ack_seq = val; }

        auto res1() @property @nogc pure nothrow { return _anonymous_40.res1; }
        void res1(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.res1 = val; }

        auto doff() @property @nogc pure nothrow { return _anonymous_40.doff; }
        void doff(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.doff = val; }

        auto fin() @property @nogc pure nothrow { return _anonymous_40.fin; }
        void fin(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.fin = val; }

        auto syn() @property @nogc pure nothrow { return _anonymous_40.syn; }
        void syn(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.syn = val; }

        auto rst() @property @nogc pure nothrow { return _anonymous_40.rst; }
        void rst(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.rst = val; }

        auto psh() @property @nogc pure nothrow { return _anonymous_40.psh; }
        void psh(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.psh = val; }

        auto ack() @property @nogc pure nothrow { return _anonymous_40.ack; }
        void ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.ack = val; }

        auto urg() @property @nogc pure nothrow { return _anonymous_40.urg; }
        void urg(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.urg = val; }

        auto res2() @property @nogc pure nothrow { return _anonymous_40.res2; }
        void res2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.res2 = val; }

        auto window() @property @nogc pure nothrow { return _anonymous_40.window; }
        void window(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.window = val; }

        auto check() @property @nogc pure nothrow { return _anonymous_40.check; }
        void check(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.check = val; }

        auto urg_ptr() @property @nogc pure nothrow { return _anonymous_40.urg_ptr; }
        void urg_ptr(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_40.urg_ptr = val; }
    }
    alias tcp_seq = uint;
    int bindresvport6(int, sockaddr_in6*) @nogc nothrow;
    int bindresvport(int, sockaddr_in*) @nogc nothrow;
    ushort htons(ushort) @nogc nothrow;
    uint htonl(uint) @nogc nothrow;
    ushort ntohs(ushort) @nogc nothrow;
    uint ntohl(uint) @nogc nothrow;
    struct group_filter
    {
        uint gf_interface;
        sockaddr_storage gf_group;
        uint gf_fmode;
        uint gf_numsrc;
        sockaddr_storage[1] gf_slist;
    }
    struct ip_msfilter
    {
        in_addr imsf_multiaddr;
        in_addr imsf_interface;
        uint imsf_fmode;
        uint imsf_numsrc;
        in_addr[1] imsf_slist;
    }
    struct group_source_req
    {
        uint gsr_interface;
        sockaddr_storage gsr_group;
        sockaddr_storage gsr_source;
    }
    struct group_req
    {
        uint gr_interface;
        sockaddr_storage gr_group;
    }
    struct ipv6_mreq
    {
        in6_addr ipv6mr_multiaddr;
        uint ipv6mr_interface;
    }
    struct ip_mreq_source
    {
        in_addr imr_multiaddr;
        in_addr imr_interface;
        in_addr imr_sourceaddr;
    }
    struct ip_mreq
    {
        in_addr imr_multiaddr;
        in_addr imr_interface;
    }
    struct sockaddr_in6
    {
        ushort sin6_family;
        ushort sin6_port;
        uint sin6_flowinfo;
        in6_addr sin6_addr;
        uint sin6_scope_id;
    }
    struct sockaddr_in
    {
        ushort sin_family;
        ushort sin_port;
        in_addr sin_addr;
        ubyte[8] sin_zero;
    }
    extern __gshared const(in6_addr) in6addr_loopback;
    extern __gshared const(in6_addr) in6addr_any;
    struct in6_addr
    {
        static union _Anonymous_41
        {
            ubyte[16] __u6_addr8;
            ushort[8] __u6_addr16;
            uint[4] __u6_addr32;
        }
        _Anonymous_41 __in6_u;
    }
    enum _Anonymous_42
    {
        IPPORT_ECHO = 7,
        IPPORT_DISCARD = 9,
        IPPORT_SYSTAT = 11,
        IPPORT_DAYTIME = 13,
        IPPORT_NETSTAT = 15,
        IPPORT_FTP = 21,
        IPPORT_TELNET = 23,
        IPPORT_SMTP = 25,
        IPPORT_TIMESERVER = 37,
        IPPORT_NAMESERVER = 42,
        IPPORT_WHOIS = 43,
        IPPORT_MTP = 57,
        IPPORT_TFTP = 69,
        IPPORT_RJE = 77,
        IPPORT_FINGER = 79,
        IPPORT_TTYLINK = 87,
        IPPORT_SUPDUP = 95,
        IPPORT_EXECSERVER = 512,
        IPPORT_LOGINSERVER = 513,
        IPPORT_CMDSERVER = 514,
        IPPORT_EFSSERVER = 520,
        IPPORT_BIFFUDP = 512,
        IPPORT_WHOSERVER = 513,
        IPPORT_ROUTESERVER = 520,
        IPPORT_RESERVED = 1024,
        IPPORT_USERRESERVED = 5000,
    }
    enum IPPORT_ECHO = _Anonymous_42.IPPORT_ECHO;
    enum IPPORT_DISCARD = _Anonymous_42.IPPORT_DISCARD;
    enum IPPORT_SYSTAT = _Anonymous_42.IPPORT_SYSTAT;
    enum IPPORT_DAYTIME = _Anonymous_42.IPPORT_DAYTIME;
    enum IPPORT_NETSTAT = _Anonymous_42.IPPORT_NETSTAT;
    enum IPPORT_FTP = _Anonymous_42.IPPORT_FTP;
    enum IPPORT_TELNET = _Anonymous_42.IPPORT_TELNET;
    enum IPPORT_SMTP = _Anonymous_42.IPPORT_SMTP;
    enum IPPORT_TIMESERVER = _Anonymous_42.IPPORT_TIMESERVER;
    enum IPPORT_NAMESERVER = _Anonymous_42.IPPORT_NAMESERVER;
    enum IPPORT_WHOIS = _Anonymous_42.IPPORT_WHOIS;
    enum IPPORT_MTP = _Anonymous_42.IPPORT_MTP;
    enum IPPORT_TFTP = _Anonymous_42.IPPORT_TFTP;
    enum IPPORT_RJE = _Anonymous_42.IPPORT_RJE;
    enum IPPORT_FINGER = _Anonymous_42.IPPORT_FINGER;
    enum IPPORT_TTYLINK = _Anonymous_42.IPPORT_TTYLINK;
    enum IPPORT_SUPDUP = _Anonymous_42.IPPORT_SUPDUP;
    enum IPPORT_EXECSERVER = _Anonymous_42.IPPORT_EXECSERVER;
    enum IPPORT_LOGINSERVER = _Anonymous_42.IPPORT_LOGINSERVER;
    enum IPPORT_CMDSERVER = _Anonymous_42.IPPORT_CMDSERVER;
    enum IPPORT_EFSSERVER = _Anonymous_42.IPPORT_EFSSERVER;
    enum IPPORT_BIFFUDP = _Anonymous_42.IPPORT_BIFFUDP;
    enum IPPORT_WHOSERVER = _Anonymous_42.IPPORT_WHOSERVER;
    enum IPPORT_ROUTESERVER = _Anonymous_42.IPPORT_ROUTESERVER;
    enum IPPORT_RESERVED = _Anonymous_42.IPPORT_RESERVED;
    enum IPPORT_USERRESERVED = _Anonymous_42.IPPORT_USERRESERVED;
    alias in_port_t = ushort;
    enum _Anonymous_43
    {
        IPPROTO_HOPOPTS = 0,
        IPPROTO_ROUTING = 43,
        IPPROTO_FRAGMENT = 44,
        IPPROTO_ICMPV6 = 58,
        IPPROTO_NONE = 59,
        IPPROTO_DSTOPTS = 60,
        IPPROTO_MH = 135,
    }
    enum IPPROTO_HOPOPTS = _Anonymous_43.IPPROTO_HOPOPTS;
    enum IPPROTO_ROUTING = _Anonymous_43.IPPROTO_ROUTING;
    enum IPPROTO_FRAGMENT = _Anonymous_43.IPPROTO_FRAGMENT;
    enum IPPROTO_ICMPV6 = _Anonymous_43.IPPROTO_ICMPV6;
    enum IPPROTO_NONE = _Anonymous_43.IPPROTO_NONE;
    enum IPPROTO_DSTOPTS = _Anonymous_43.IPPROTO_DSTOPTS;
    enum IPPROTO_MH = _Anonymous_43.IPPROTO_MH;
    enum _Anonymous_44
    {
        IPPROTO_IP = 0,
        IPPROTO_ICMP = 1,
        IPPROTO_IGMP = 2,
        IPPROTO_IPIP = 4,
        IPPROTO_TCP = 6,
        IPPROTO_EGP = 8,
        IPPROTO_PUP = 12,
        IPPROTO_UDP = 17,
        IPPROTO_IDP = 22,
        IPPROTO_TP = 29,
        IPPROTO_DCCP = 33,
        IPPROTO_IPV6 = 41,
        IPPROTO_RSVP = 46,
        IPPROTO_GRE = 47,
        IPPROTO_ESP = 50,
        IPPROTO_AH = 51,
        IPPROTO_MTP = 92,
        IPPROTO_BEETPH = 94,
        IPPROTO_ENCAP = 98,
        IPPROTO_PIM = 103,
        IPPROTO_COMP = 108,
        IPPROTO_SCTP = 132,
        IPPROTO_UDPLITE = 136,
        IPPROTO_MPLS = 137,
        IPPROTO_RAW = 255,
        IPPROTO_MAX = 256,
    }
    enum IPPROTO_IP = _Anonymous_44.IPPROTO_IP;
    enum IPPROTO_ICMP = _Anonymous_44.IPPROTO_ICMP;
    enum IPPROTO_IGMP = _Anonymous_44.IPPROTO_IGMP;
    enum IPPROTO_IPIP = _Anonymous_44.IPPROTO_IPIP;
    enum IPPROTO_TCP = _Anonymous_44.IPPROTO_TCP;
    enum IPPROTO_EGP = _Anonymous_44.IPPROTO_EGP;
    enum IPPROTO_PUP = _Anonymous_44.IPPROTO_PUP;
    enum IPPROTO_UDP = _Anonymous_44.IPPROTO_UDP;
    enum IPPROTO_IDP = _Anonymous_44.IPPROTO_IDP;
    enum IPPROTO_TP = _Anonymous_44.IPPROTO_TP;
    enum IPPROTO_DCCP = _Anonymous_44.IPPROTO_DCCP;
    enum IPPROTO_IPV6 = _Anonymous_44.IPPROTO_IPV6;
    enum IPPROTO_RSVP = _Anonymous_44.IPPROTO_RSVP;
    enum IPPROTO_GRE = _Anonymous_44.IPPROTO_GRE;
    enum IPPROTO_ESP = _Anonymous_44.IPPROTO_ESP;
    enum IPPROTO_AH = _Anonymous_44.IPPROTO_AH;
    enum IPPROTO_MTP = _Anonymous_44.IPPROTO_MTP;
    enum IPPROTO_BEETPH = _Anonymous_44.IPPROTO_BEETPH;
    enum IPPROTO_ENCAP = _Anonymous_44.IPPROTO_ENCAP;
    enum IPPROTO_PIM = _Anonymous_44.IPPROTO_PIM;
    enum IPPROTO_COMP = _Anonymous_44.IPPROTO_COMP;
    enum IPPROTO_SCTP = _Anonymous_44.IPPROTO_SCTP;
    enum IPPROTO_UDPLITE = _Anonymous_44.IPPROTO_UDPLITE;
    enum IPPROTO_MPLS = _Anonymous_44.IPPROTO_MPLS;
    enum IPPROTO_RAW = _Anonymous_44.IPPROTO_RAW;
    enum IPPROTO_MAX = _Anonymous_44.IPPROTO_MAX;
    struct in_addr
    {
        uint s_addr;
    }
    alias in_addr_t = uint;
    int getnameinfo(const(sockaddr)*, uint, char*, uint, char*, uint, int) @nogc nothrow;
    const(char)* gai_strerror(int) @nogc nothrow;
    void freeaddrinfo(addrinfo*) @nogc nothrow;
    int getaddrinfo(const(char)*, const(char)*, const(addrinfo)*, addrinfo**) @nogc nothrow;
    struct addrinfo
    {
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        uint ai_addrlen;
        sockaddr* ai_addr;
        char* ai_canonname;
        addrinfo* ai_next;
    }
    int rresvport_af(int*, ushort) @nogc nothrow;
    int rresvport(int*) @nogc nothrow;
    int iruserok_af(const(void)*, int, const(char)*, const(char)*, ushort) @nogc nothrow;
    int iruserok(uint, int, const(char)*, const(char)*) @nogc nothrow;
    int ruserok_af(const(char)*, int, const(char)*, const(char)*, ushort) @nogc nothrow;
    struct sockaddr
    {
        ushort sa_family;
        char[14] sa_data;
    }
    int ruserok(const(char)*, int, const(char)*, const(char)*) @nogc nothrow;
    int rexec_af(char**, int, const(char)*, const(char)*, const(char)*, int*, ushort) @nogc nothrow;
    struct sockaddr_storage
    {
        ushort ss_family;
        char[118] __ss_padding;
        c_ulong __ss_align;
    }
    enum _Anonymous_45
    {
        MSG_OOB = 1,
        MSG_PEEK = 2,
        MSG_DONTROUTE = 4,
        MSG_CTRUNC = 8,
        MSG_PROXY = 16,
        MSG_TRUNC = 32,
        MSG_DONTWAIT = 64,
        MSG_EOR = 128,
        MSG_WAITALL = 256,
        MSG_FIN = 512,
        MSG_SYN = 1024,
        MSG_CONFIRM = 2048,
        MSG_RST = 4096,
        MSG_ERRQUEUE = 8192,
        MSG_NOSIGNAL = 16384,
        MSG_MORE = 32768,
        MSG_WAITFORONE = 65536,
        MSG_BATCH = 262144,
        MSG_ZEROCOPY = 67108864,
        MSG_FASTOPEN = 536870912,
        MSG_CMSG_CLOEXEC = 1073741824,
    }
    enum MSG_OOB = _Anonymous_45.MSG_OOB;
    enum MSG_PEEK = _Anonymous_45.MSG_PEEK;
    enum MSG_DONTROUTE = _Anonymous_45.MSG_DONTROUTE;
    enum MSG_CTRUNC = _Anonymous_45.MSG_CTRUNC;
    enum MSG_PROXY = _Anonymous_45.MSG_PROXY;
    enum MSG_TRUNC = _Anonymous_45.MSG_TRUNC;
    enum MSG_DONTWAIT = _Anonymous_45.MSG_DONTWAIT;
    enum MSG_EOR = _Anonymous_45.MSG_EOR;
    enum MSG_WAITALL = _Anonymous_45.MSG_WAITALL;
    enum MSG_FIN = _Anonymous_45.MSG_FIN;
    enum MSG_SYN = _Anonymous_45.MSG_SYN;
    enum MSG_CONFIRM = _Anonymous_45.MSG_CONFIRM;
    enum MSG_RST = _Anonymous_45.MSG_RST;
    enum MSG_ERRQUEUE = _Anonymous_45.MSG_ERRQUEUE;
    enum MSG_NOSIGNAL = _Anonymous_45.MSG_NOSIGNAL;
    enum MSG_MORE = _Anonymous_45.MSG_MORE;
    enum MSG_WAITFORONE = _Anonymous_45.MSG_WAITFORONE;
    enum MSG_BATCH = _Anonymous_45.MSG_BATCH;
    enum MSG_ZEROCOPY = _Anonymous_45.MSG_ZEROCOPY;
    enum MSG_FASTOPEN = _Anonymous_45.MSG_FASTOPEN;
    enum MSG_CMSG_CLOEXEC = _Anonymous_45.MSG_CMSG_CLOEXEC;
    int rexec(char**, int, const(char)*, const(char)*, const(char)*, int*) @nogc nothrow;
    int rcmd_af(char**, ushort, const(char)*, const(char)*, const(char)*, int*, ushort) @nogc nothrow;
    int rcmd(char**, ushort, const(char)*, const(char)*, const(char)*, int*) @nogc nothrow;
    int getnetgrent_r(char**, char**, char**, char*, c_ulong) @nogc nothrow;
    int innetgr(const(char)*, const(char)*, const(char)*, const(char)*) @nogc nothrow;
    int getnetgrent(char**, char**, char**) @nogc nothrow;
    void endnetgrent() @nogc nothrow;
    int setnetgrent(const(char)*) @nogc nothrow;
    int getprotobynumber_r(int, protoent*, char*, c_ulong, protoent**) @nogc nothrow;
    int getprotobyname_r(const(char)*, protoent*, char*, c_ulong, protoent**) @nogc nothrow;
    int getprotoent_r(protoent*, char*, c_ulong, protoent**) @nogc nothrow;
    protoent* getprotobynumber(int) @nogc nothrow;
    protoent* getprotobyname(const(char)*) @nogc nothrow;
    protoent* getprotoent() @nogc nothrow;
    void endprotoent() @nogc nothrow;
    void setprotoent(int) @nogc nothrow;
    struct protoent
    {
        char* p_name;
        char** p_aliases;
        int p_proto;
    }
    int getservbyport_r(int, const(char)*, servent*, char*, c_ulong, servent**) @nogc nothrow;
    int getservbyname_r(const(char)*, const(char)*, servent*, char*, c_ulong, servent**) @nogc nothrow;
    struct msghdr
    {
        void* msg_name;
        uint msg_namelen;
        iovec* msg_iov;
        c_ulong msg_iovlen;
        void* msg_control;
        c_ulong msg_controllen;
        int msg_flags;
    }
    struct cmsghdr
    {
        c_ulong cmsg_len;
        int cmsg_level;
        int cmsg_type;
        ubyte[0] __cmsg_data;
    }
    int getservent_r(servent*, char*, c_ulong, servent**) @nogc nothrow;
    servent* getservbyport(int, const(char)*) @nogc nothrow;
    servent* getservbyname(const(char)*, const(char)*) @nogc nothrow;
    servent* getservent() @nogc nothrow;
    void endservent() @nogc nothrow;
    cmsghdr* __cmsg_nxthdr(msghdr*, cmsghdr*) @nogc nothrow;
    enum _Anonymous_46
    {
        SCM_RIGHTS = 1,
    }
    enum SCM_RIGHTS = _Anonymous_46.SCM_RIGHTS;
    void setservent(int) @nogc nothrow;
    struct servent
    {
        char* s_name;
        char** s_aliases;
        int s_port;
        char* s_proto;
    }
    int getnetbyname_r(const(char)*, netent*, char*, c_ulong, netent**, int*) @nogc nothrow;
    int getnetbyaddr_r(uint, int, netent*, char*, c_ulong, netent**, int*) @nogc nothrow;
    int getnetent_r(netent*, char*, c_ulong, netent**, int*) @nogc nothrow;
    struct linger
    {
        int l_onoff;
        int l_linger;
    }
    enum __socket_type
    {
        SOCK_STREAM = 1,
        SOCK_DGRAM = 2,
        SOCK_RAW = 3,
        SOCK_RDM = 4,
        SOCK_SEQPACKET = 5,
        SOCK_DCCP = 6,
        SOCK_PACKET = 10,
        SOCK_CLOEXEC = 524288,
        SOCK_NONBLOCK = 2048,
    }
    enum SOCK_STREAM = __socket_type.SOCK_STREAM;
    enum SOCK_DGRAM = __socket_type.SOCK_DGRAM;
    enum SOCK_RAW = __socket_type.SOCK_RAW;
    enum SOCK_RDM = __socket_type.SOCK_RDM;
    enum SOCK_SEQPACKET = __socket_type.SOCK_SEQPACKET;
    enum SOCK_DCCP = __socket_type.SOCK_DCCP;
    enum SOCK_PACKET = __socket_type.SOCK_PACKET;
    enum SOCK_CLOEXEC = __socket_type.SOCK_CLOEXEC;
    enum SOCK_NONBLOCK = __socket_type.SOCK_NONBLOCK;
    netent* getnetbyname(const(char)*) @nogc nothrow;
    netent* getnetbyaddr(uint, int) @nogc nothrow;
    netent* getnetent() @nogc nothrow;
    void endnetent() @nogc nothrow;
    void setnetent(int) @nogc nothrow;
    int gethostbyname2_r(const(char)*, int, hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    int gethostbyname_r(const(char)*, hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    int gethostbyaddr_r(const(void)*, uint, int, hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    int gethostent_r(hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    hostent* gethostbyname2(const(char)*, int) @nogc nothrow;
    hostent* gethostbyname(const(char)*) @nogc nothrow;
    hostent* gethostbyaddr(const(void)*, uint, int) @nogc nothrow;
    hostent* gethostent() @nogc nothrow;
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
    void endhostent() @nogc nothrow;
    void sethostent(int) @nogc nothrow;
    struct hostent
    {
        char* h_name;
        char** h_aliases;
        int h_addrtype;
        int h_length;
        char** h_addr_list;
    }
    const(char)* hstrerror(int) @nogc nothrow;
    void herror(const(char)*) @nogc nothrow;
    int* __h_errno_location() @nogc nothrow;
    alias __kernel_mqd_t = int;
    alias __kernel_key_t = int;
    alias int8_t = byte;
    alias int16_t = short;
    alias int32_t = int;
    alias int64_t = c_long;
    alias __kernel_sighandler_t = void function(int);
    alias uint8_t = ubyte;
    alias uint16_t = ushort;
    alias uint32_t = uint;
    alias uint64_t = ulong;
    struct __kernel_fd_set
    {
        c_ulong[16] fds_bits;
    }
    extern __gshared int sys_nerr;
    extern __gshared const(const(char)*)[0] sys_errlist;
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
        static union _Anonymous_47
        {
            ulong __wseq;
            static struct _Anonymous_48
            {
                uint __low;
                uint __high;
            }
            _Anonymous_48 __wseq32;
        }
        _Anonymous_47 _anonymous_49;
        auto __wseq() @property @nogc pure nothrow { return _anonymous_49.__wseq; }
        void __wseq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_49.__wseq = val; }
        auto __wseq32() @property @nogc pure nothrow { return _anonymous_49.__wseq32; }
        void __wseq32(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_49.__wseq32 = val; }
        static union _Anonymous_50
        {
            ulong __g1_start;
            static struct _Anonymous_51
            {
                uint __low;
                uint __high;
            }
            _Anonymous_51 __g1_start32;
        }
        _Anonymous_50 _anonymous_52;
        auto __g1_start() @property @nogc pure nothrow { return _anonymous_52.__g1_start; }
        void __g1_start(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_52.__g1_start = val; }
        auto __g1_start32() @property @nogc pure nothrow { return _anonymous_52.__g1_start32; }
        void __g1_start32(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_52.__g1_start32 = val; }
        uint[2] __g_refs;
        uint[2] __g_size;
        uint __g1_orig_size;
        uint __wrefs;
        uint[2] __g_signals;
    }
    c_ulong wcstoumax(const(int)*, int**, int) @nogc nothrow;
    c_long wcstoimax(const(int)*, int**, int) @nogc nothrow;
    c_ulong strtoumax(const(char)*, char**, int) @nogc nothrow;
    c_long strtoimax(const(char)*, char**, int) @nogc nothrow;
    imaxdiv_t imaxdiv(c_long, c_long) @nogc nothrow;
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
    c_long imaxabs(c_long) @nogc nothrow;
    struct imaxdiv_t
    {
        c_long quot;
        c_long rem;
    }
    alias __gwchar_t = int;
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
    alias FILE = _IO_FILE;
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
        static union _Anonymous_53
        {
            uint __wch;
            char[4] __wchb;
        }
        _Anonymous_53 __value;
    }
    struct __sigset_t
    {
        c_ulong[16] __val;
    }
    alias clock_t = c_long;
    alias clockid_t = int;
    alias locale_t = __locale_struct*;
    alias sigset_t = __sigset_t;
    struct _IO_marker;
    struct _IO_codecvt;
    struct _IO_wide_data;
    alias _IO_lock_t = void;
    struct iovec
    {
        void* iov_base;
        c_ulong iov_len;
    }
    struct itimerspec
    {
        timespec it_interval;
        timespec it_value;
    }
    struct osockaddr
    {
        ushort sa_family;
        ubyte[14] sa_data;
    }
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
    alias timer_t = void*;
    int posix_fallocate(int, c_long, c_long) @nogc nothrow;
    int posix_fadvise(int, c_long, c_long, int) @nogc nothrow;
    int creat(const(char)*, uint) @nogc nothrow;
    int openat(int, const(char)*, int, ...) @nogc nothrow;
    int open(const(char)*, int, ...) @nogc nothrow;
    int fcntl(int, int, ...) @nogc nothrow;
    static ushort __uint16_identity(ushort) @nogc nothrow;
    static uint __uint32_identity(uint) @nogc nothrow;
    static c_ulong __uint64_identity(c_ulong) @nogc nothrow;
    alias mode_t = uint;
    int* __errno_location() @nogc nothrow;
    int toupper_l(int, __locale_struct*) @nogc nothrow;
    int __toupper_l(int, __locale_struct*) @nogc nothrow;
    int tolower_l(int, __locale_struct*) @nogc nothrow;
    int __tolower_l(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isblank_l") int isblank_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isxdigit_l") int isxdigit_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isupper_l") int isupper_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isspace_l") int isspace_l_(int, __locale_struct*) @nogc nothrow;
    enum _Anonymous_54
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
    enum _ISupper = _Anonymous_54._ISupper;
    enum _ISlower = _Anonymous_54._ISlower;
    enum _ISalpha = _Anonymous_54._ISalpha;
    enum _ISdigit = _Anonymous_54._ISdigit;
    enum _ISxdigit = _Anonymous_54._ISxdigit;
    enum _ISspace = _Anonymous_54._ISspace;
    enum _ISprint = _Anonymous_54._ISprint;
    enum _ISgraph = _Anonymous_54._ISgraph;
    enum _ISblank = _Anonymous_54._ISblank;
    enum _IScntrl = _Anonymous_54._IScntrl;
    enum _ISpunct = _Anonymous_54._ISpunct;
    enum _ISalnum = _Anonymous_54._ISalnum;
    const(ushort)** __ctype_b_loc() @nogc nothrow;
    const(int)** __ctype_tolower_loc() @nogc nothrow;
    const(int)** __ctype_toupper_loc() @nogc nothrow;
    pragma(mangle, "ispunct_l") int ispunct_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isprint_l") int isprint_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isgraph_l") int isgraph_l_(int, __locale_struct*) @nogc nothrow;
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
    pragma(mangle, "islower_l") int islower_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isdigit_l") int isdigit_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "iscntrl_l") int iscntrl_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isalpha_l") int isalpha_l_(int, __locale_struct*) @nogc nothrow;
    pragma(mangle, "isalnum_l") int isalnum_l_(int, __locale_struct*) @nogc nothrow;
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
    static if(!is(typeof(_ENDIAN_H))) {
        enum _ENDIAN_H = 1;
    }




    static if(!is(typeof(__LITTLE_ENDIAN))) {
        enum __LITTLE_ENDIAN = 1234;
    }




    static if(!is(typeof(__BIG_ENDIAN))) {
        enum __BIG_ENDIAN = 4321;
    }




    static if(!is(typeof(__PDP_ENDIAN))) {
        enum __PDP_ENDIAN = 3412;
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
    static if(!is(typeof(_ERRNO_H))) {
        enum _ERRNO_H = 1;
    }
    static if(!is(typeof(_FCNTL_H))) {
        enum _FCNTL_H = 1;
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




    static if(!is(typeof(__IOV_MAX))) {
        enum __IOV_MAX = 1024;
    }




    static if(!is(typeof(_BITS_UIO_LIM_H))) {
        enum _BITS_UIO_LIM_H = 1;
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
    static if(!is(typeof(SEEK_SET))) {
        enum SEEK_SET = 0;
    }




    static if(!is(typeof(SEEK_CUR))) {
        enum SEEK_CUR = 1;
    }




    static if(!is(typeof(SEEK_END))) {
        enum SEEK_END = 2;
    }
    static if(!is(typeof(AT_SYMLINK_NOFOLLOW))) {
        enum AT_SYMLINK_NOFOLLOW = 0x100;
    }




    static if(!is(typeof(AT_REMOVEDIR))) {
        enum AT_REMOVEDIR = 0x200;
    }




    static if(!is(typeof(AT_SYMLINK_FOLLOW))) {
        enum AT_SYMLINK_FOLLOW = 0x400;
    }




    static if(!is(typeof(AT_EACCESS))) {
        enum AT_EACCESS = 0x200;
    }
    static if(!is(typeof(_FEATURES_H))) {
        enum _FEATURES_H = 1;
    }
    static if(!is(typeof(_DEFAULT_SOURCE))) {
        enum _DEFAULT_SOURCE = 1;
    }
    static if(!is(typeof(__USE_ISOC11))) {
        enum __USE_ISOC11 = 1;
    }
    static if(!is(typeof(__USE_ISOC99))) {
        enum __USE_ISOC99 = 1;
    }
    static if(!is(typeof(__USE_ISOC95))) {
        enum __USE_ISOC95 = 1;
    }






    static if(!is(typeof(__USE_POSIX_IMPLICITLY))) {
        enum __USE_POSIX_IMPLICITLY = 1;
    }




    static if(!is(typeof(_POSIX_SOURCE))) {
        enum _POSIX_SOURCE = 1;
    }




    static if(!is(typeof(_POSIX_C_SOURCE))) {
        enum _POSIX_C_SOURCE = 200809L;
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




    static if(!is(typeof(__osockaddr_defined))) {
        enum __osockaddr_defined = 1;
    }




    static if(!is(typeof(__USE_POSIX))) {
        enum __USE_POSIX = 1;
    }




    static if(!is(typeof(__itimerspec_defined))) {
        enum __itimerspec_defined = 1;
    }






    static if(!is(typeof(__USE_POSIX2))) {
        enum __USE_POSIX2 = 1;
    }




    static if(!is(typeof(__iovec_defined))) {
        enum __iovec_defined = 1;
    }




    static if(!is(typeof(_IO_USER_LOCK))) {
        enum _IO_USER_LOCK = 0x8000;
    }




    static if(!is(typeof(__USE_POSIX199309))) {
        enum __USE_POSIX199309 = 1;
    }






    static if(!is(typeof(_IO_ERR_SEEN))) {
        enum _IO_ERR_SEEN = 0x0020;
    }




    static if(!is(typeof(__USE_POSIX199506))) {
        enum __USE_POSIX199506 = 1;
    }






    static if(!is(typeof(_IO_EOF_SEEN))) {
        enum _IO_EOF_SEEN = 0x0010;
    }




    static if(!is(typeof(__USE_XOPEN2K))) {
        enum __USE_XOPEN2K = 1;
    }
    static if(!is(typeof(__USE_XOPEN2K8))) {
        enum __USE_XOPEN2K8 = 1;
    }




    static if(!is(typeof(_ATFILE_SOURCE))) {
        enum _ATFILE_SOURCE = 1;
    }




    static if(!is(typeof(__struct_FILE_defined))) {
        enum __struct_FILE_defined = 1;
    }




    static if(!is(typeof(__USE_MISC))) {
        enum __USE_MISC = 1;
    }




    static if(!is(typeof(__sigset_t_defined))) {
        enum __sigset_t_defined = 1;
    }




    static if(!is(typeof(__USE_ATFILE))) {
        enum __USE_ATFILE = 1;
    }




    static if(!is(typeof(__USE_FORTIFY_LEVEL))) {
        enum __USE_FORTIFY_LEVEL = 0;
    }




    static if(!is(typeof(_BITS_TYPES_LOCALE_T_H))) {
        enum _BITS_TYPES_LOCALE_T_H = 1;
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_GETS))) {
        enum __GLIBC_USE_DEPRECATED_GETS = 0;
    }




    static if(!is(typeof(__clockid_t_defined))) {
        enum __clockid_t_defined = 1;
    }




    static if(!is(typeof(__clock_t_defined))) {
        enum __clock_t_defined = 1;
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_SCANF))) {
        enum __GLIBC_USE_DEPRECATED_SCANF = 0;
    }






    static if(!is(typeof(__GNU_LIBRARY__))) {
        enum __GNU_LIBRARY__ = 6;
    }




    static if(!is(typeof(__GLIBC__))) {
        enum __GLIBC__ = 2;
    }




    static if(!is(typeof(__GLIBC_MINOR__))) {
        enum __GLIBC_MINOR__ = 29;
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
    static if(!is(typeof(_INTTYPES_H))) {
        enum _INTTYPES_H = 1;
    }
    static if(!is(typeof(____gwchar_t_defined))) {
        enum ____gwchar_t_defined = 1;
    }






    static if(!is(typeof(__PRI64_PREFIX))) {
        enum __PRI64_PREFIX = "l";
    }




    static if(!is(typeof(__PRIPTR_PREFIX))) {
        enum __PRIPTR_PREFIX = "l";
    }




    static if(!is(typeof(PRId8))) {
        enum PRId8 = "d";
    }




    static if(!is(typeof(PRId16))) {
        enum PRId16 = "d";
    }




    static if(!is(typeof(PRId32))) {
        enum PRId32 = "d";
    }






    static if(!is(typeof(PRIdLEAST8))) {
        enum PRIdLEAST8 = "d";
    }




    static if(!is(typeof(PRIdLEAST16))) {
        enum PRIdLEAST16 = "d";
    }




    static if(!is(typeof(PRIdLEAST32))) {
        enum PRIdLEAST32 = "d";
    }






    static if(!is(typeof(PRIdFAST8))) {
        enum PRIdFAST8 = "d";
    }
    static if(!is(typeof(PRIi8))) {
        enum PRIi8 = "i";
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
    static if(!is(typeof(_BITS_TYPES_H))) {
        enum _BITS_TYPES_H = 1;
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




    static if(!is(typeof(_LIBC_LIMITS_H_))) {
        enum _LIBC_LIMITS_H_ = 1;
    }






    static if(!is(typeof(CLOCK_MONOTONIC_RAW))) {
        enum CLOCK_MONOTONIC_RAW = 4;
    }




    static if(!is(typeof(MB_LEN_MAX))) {
        enum MB_LEN_MAX = 16;
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




    static if(!is(typeof(_NETDB_H))) {
        enum _NETDB_H = 1;
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






    static if(!is(typeof(_PATH_HEQUIV))) {
        enum _PATH_HEQUIV = "/etc/hosts.equiv";
    }




    static if(!is(typeof(_PATH_HOSTS))) {
        enum _PATH_HOSTS = "/etc/hosts";
    }




    static if(!is(typeof(_PATH_NETWORKS))) {
        enum _PATH_NETWORKS = "/etc/networks";
    }




    static if(!is(typeof(_PATH_NSSWITCH_CONF))) {
        enum _PATH_NSSWITCH_CONF = "/etc/nsswitch.conf";
    }




    static if(!is(typeof(_PATH_PROTOCOLS))) {
        enum _PATH_PROTOCOLS = "/etc/protocols";
    }




    static if(!is(typeof(_PATH_SERVICES))) {
        enum _PATH_SERVICES = "/etc/services";
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




    static if(!is(typeof(HOST_NOT_FOUND))) {
        enum HOST_NOT_FOUND = 1;
    }




    static if(!is(typeof(TRY_AGAIN))) {
        enum TRY_AGAIN = 2;
    }




    static if(!is(typeof(NO_RECOVERY))) {
        enum NO_RECOVERY = 3;
    }




    static if(!is(typeof(NO_DATA))) {
        enum NO_DATA = 4;
    }




    static if(!is(typeof(__S_IFREG))) {
        enum __S_IFREG = std.conv.octal!100000;
    }






    static if(!is(typeof(NETDB_SUCCESS))) {
        enum NETDB_SUCCESS = 0;
    }






    static if(!is(typeof(__S_IFBLK))) {
        enum __S_IFBLK = std.conv.octal!60000;
    }




    static if(!is(typeof(IPPORT_RESERVED))) {
        enum IPPORT_RESERVED = 1024;
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
    static if(!is(typeof(SOMAXCONN))) {
        enum SOMAXCONN = 128;
    }




    static if(!is(typeof(SOL_XDP))) {
        enum SOL_XDP = 283;
    }




    static if(!is(typeof(SOL_TLS))) {
        enum SOL_TLS = 282;
    }




    static if(!is(typeof(SOL_KCM))) {
        enum SOL_KCM = 281;
    }




    static if(!is(typeof(SOL_NFC))) {
        enum SOL_NFC = 280;
    }




    static if(!is(typeof(SOL_ALG))) {
        enum SOL_ALG = 279;
    }




    static if(!is(typeof(SOL_CAIF))) {
        enum SOL_CAIF = 278;
    }




    static if(!is(typeof(AI_PASSIVE))) {
        enum AI_PASSIVE = 0x0001;
    }




    static if(!is(typeof(AI_CANONNAME))) {
        enum AI_CANONNAME = 0x0002;
    }




    static if(!is(typeof(AI_NUMERICHOST))) {
        enum AI_NUMERICHOST = 0x0004;
    }




    static if(!is(typeof(AI_V4MAPPED))) {
        enum AI_V4MAPPED = 0x0008;
    }




    static if(!is(typeof(AI_ALL))) {
        enum AI_ALL = 0x0010;
    }




    static if(!is(typeof(AI_ADDRCONFIG))) {
        enum AI_ADDRCONFIG = 0x0020;
    }




    static if(!is(typeof(AI_NUMERICSERV))) {
        enum AI_NUMERICSERV = 0x0400;
    }
    static if(!is(typeof(SOL_IUCV))) {
        enum SOL_IUCV = 277;
    }




    static if(!is(typeof(NI_MAXHOST))) {
        enum NI_MAXHOST = 1025;
    }




    static if(!is(typeof(NI_MAXSERV))) {
        enum NI_MAXSERV = 32;
    }




    static if(!is(typeof(NI_NUMERICHOST))) {
        enum NI_NUMERICHOST = 1;
    }




    static if(!is(typeof(NI_NUMERICSERV))) {
        enum NI_NUMERICSERV = 2;
    }




    static if(!is(typeof(NI_NOFQDN))) {
        enum NI_NOFQDN = 4;
    }




    static if(!is(typeof(NI_NAMEREQD))) {
        enum NI_NAMEREQD = 8;
    }




    static if(!is(typeof(NI_DGRAM))) {
        enum NI_DGRAM = 16;
    }




    static if(!is(typeof(SOL_RDS))) {
        enum SOL_RDS = 276;
    }




    static if(!is(typeof(SOL_PNPIPE))) {
        enum SOL_PNPIPE = 275;
    }




    static if(!is(typeof(SOL_BLUETOOTH))) {
        enum SOL_BLUETOOTH = 274;
    }




    static if(!is(typeof(SOL_PPPOL2TP))) {
        enum SOL_PPPOL2TP = 273;
    }




    static if(!is(typeof(SOL_RXRPC))) {
        enum SOL_RXRPC = 272;
    }




    static if(!is(typeof(SOL_TIPC))) {
        enum SOL_TIPC = 271;
    }




    static if(!is(typeof(SOL_NETLINK))) {
        enum SOL_NETLINK = 270;
    }




    static if(!is(typeof(_NETINET_IN_H))) {
        enum _NETINET_IN_H = 1;
    }




    static if(!is(typeof(SOL_DCCP))) {
        enum SOL_DCCP = 269;
    }




    static if(!is(typeof(SOL_LLC))) {
        enum SOL_LLC = 268;
    }




    static if(!is(typeof(SOL_NETBEUI))) {
        enum SOL_NETBEUI = 267;
    }




    static if(!is(typeof(SOL_IRDA))) {
        enum SOL_IRDA = 266;
    }




    static if(!is(typeof(SOL_AAL))) {
        enum SOL_AAL = 265;
    }




    static if(!is(typeof(SOL_ATM))) {
        enum SOL_ATM = 264;
    }




    static if(!is(typeof(SOL_PACKET))) {
        enum SOL_PACKET = 263;
    }




    static if(!is(typeof(SOL_X25))) {
        enum SOL_X25 = 262;
    }




    static if(!is(typeof(SOL_DECNET))) {
        enum SOL_DECNET = 261;
    }
    static if(!is(typeof(SOL_RAW))) {
        enum SOL_RAW = 255;
    }
    static if(!is(typeof(IN_CLASSA_NET))) {
        enum IN_CLASSA_NET = 0xff000000;
    }




    static if(!is(typeof(IN_CLASSA_NSHIFT))) {
        enum IN_CLASSA_NSHIFT = 24;
    }






    static if(!is(typeof(IN_CLASSA_MAX))) {
        enum IN_CLASSA_MAX = 128;
    }






    static if(!is(typeof(IN_CLASSB_NET))) {
        enum IN_CLASSB_NET = 0xffff0000;
    }




    static if(!is(typeof(IN_CLASSB_NSHIFT))) {
        enum IN_CLASSB_NSHIFT = 16;
    }






    static if(!is(typeof(IN_CLASSB_MAX))) {
        enum IN_CLASSB_MAX = 65536;
    }






    static if(!is(typeof(IN_CLASSC_NET))) {
        enum IN_CLASSC_NET = 0xffffff00;
    }




    static if(!is(typeof(IN_CLASSC_NSHIFT))) {
        enum IN_CLASSC_NSHIFT = 8;
    }
    static if(!is(typeof(IN_LOOPBACKNET))) {
        enum IN_LOOPBACKNET = 127;
    }
    static if(!is(typeof(INET_ADDRSTRLEN))) {
        enum INET_ADDRSTRLEN = 16;
    }




    static if(!is(typeof(INET6_ADDRSTRLEN))) {
        enum INET6_ADDRSTRLEN = 46;
    }
    static if(!is(typeof(_NETINET_TCP_H))) {
        enum _NETINET_TCP_H = 1;
    }






    static if(!is(typeof(TCP_NODELAY))) {
        enum TCP_NODELAY = 1;
    }




    static if(!is(typeof(TCP_MAXSEG))) {
        enum TCP_MAXSEG = 2;
    }




    static if(!is(typeof(TCP_CORK))) {
        enum TCP_CORK = 3;
    }




    static if(!is(typeof(TCP_KEEPIDLE))) {
        enum TCP_KEEPIDLE = 4;
    }




    static if(!is(typeof(TCP_KEEPINTVL))) {
        enum TCP_KEEPINTVL = 5;
    }




    static if(!is(typeof(TCP_KEEPCNT))) {
        enum TCP_KEEPCNT = 6;
    }




    static if(!is(typeof(TCP_SYNCNT))) {
        enum TCP_SYNCNT = 7;
    }




    static if(!is(typeof(TCP_LINGER2))) {
        enum TCP_LINGER2 = 8;
    }




    static if(!is(typeof(TCP_DEFER_ACCEPT))) {
        enum TCP_DEFER_ACCEPT = 9;
    }




    static if(!is(typeof(TCP_WINDOW_CLAMP))) {
        enum TCP_WINDOW_CLAMP = 10;
    }




    static if(!is(typeof(TCP_INFO))) {
        enum TCP_INFO = 11;
    }




    static if(!is(typeof(TCP_QUICKACK))) {
        enum TCP_QUICKACK = 12;
    }




    static if(!is(typeof(TCP_CONGESTION))) {
        enum TCP_CONGESTION = 13;
    }




    static if(!is(typeof(TCP_MD5SIG))) {
        enum TCP_MD5SIG = 14;
    }




    static if(!is(typeof(TCP_COOKIE_TRANSACTIONS))) {
        enum TCP_COOKIE_TRANSACTIONS = 15;
    }




    static if(!is(typeof(TCP_THIN_LINEAR_TIMEOUTS))) {
        enum TCP_THIN_LINEAR_TIMEOUTS = 16;
    }




    static if(!is(typeof(TCP_THIN_DUPACK))) {
        enum TCP_THIN_DUPACK = 17;
    }




    static if(!is(typeof(TCP_USER_TIMEOUT))) {
        enum TCP_USER_TIMEOUT = 18;
    }




    static if(!is(typeof(TCP_REPAIR))) {
        enum TCP_REPAIR = 19;
    }




    static if(!is(typeof(TCP_REPAIR_QUEUE))) {
        enum TCP_REPAIR_QUEUE = 20;
    }




    static if(!is(typeof(TCP_QUEUE_SEQ))) {
        enum TCP_QUEUE_SEQ = 21;
    }




    static if(!is(typeof(TCP_REPAIR_OPTIONS))) {
        enum TCP_REPAIR_OPTIONS = 22;
    }




    static if(!is(typeof(TCP_FASTOPEN))) {
        enum TCP_FASTOPEN = 23;
    }




    static if(!is(typeof(TCP_TIMESTAMP))) {
        enum TCP_TIMESTAMP = 24;
    }




    static if(!is(typeof(TCP_NOTSENT_LOWAT))) {
        enum TCP_NOTSENT_LOWAT = 25;
    }




    static if(!is(typeof(TCP_CC_INFO))) {
        enum TCP_CC_INFO = 26;
    }




    static if(!is(typeof(TCP_SAVE_SYN))) {
        enum TCP_SAVE_SYN = 27;
    }




    static if(!is(typeof(TCP_SAVED_SYN))) {
        enum TCP_SAVED_SYN = 28;
    }




    static if(!is(typeof(TCP_REPAIR_WINDOW))) {
        enum TCP_REPAIR_WINDOW = 29;
    }




    static if(!is(typeof(TCP_FASTOPEN_CONNECT))) {
        enum TCP_FASTOPEN_CONNECT = 30;
    }




    static if(!is(typeof(TCP_ULP))) {
        enum TCP_ULP = 31;
    }




    static if(!is(typeof(TCP_MD5SIG_EXT))) {
        enum TCP_MD5SIG_EXT = 32;
    }




    static if(!is(typeof(TCP_FASTOPEN_KEY))) {
        enum TCP_FASTOPEN_KEY = 33;
    }




    static if(!is(typeof(TCP_FASTOPEN_NO_COOKIE))) {
        enum TCP_FASTOPEN_NO_COOKIE = 34;
    }




    static if(!is(typeof(TCP_ZEROCOPY_RECEIVE))) {
        enum TCP_ZEROCOPY_RECEIVE = 35;
    }




    static if(!is(typeof(TCP_INQ))) {
        enum TCP_INQ = 36;
    }






    static if(!is(typeof(TCP_REPAIR_ON))) {
        enum TCP_REPAIR_ON = 1;
    }




    static if(!is(typeof(TCP_REPAIR_OFF))) {
        enum TCP_REPAIR_OFF = 0;
    }
    static if(!is(typeof(PF_MAX))) {
        enum PF_MAX = 45;
    }




    static if(!is(typeof(PF_XDP))) {
        enum PF_XDP = 44;
    }




    static if(!is(typeof(PF_SMC))) {
        enum PF_SMC = 43;
    }




    static if(!is(typeof(PF_QIPCRTR))) {
        enum PF_QIPCRTR = 42;
    }




    static if(!is(typeof(TH_FIN))) {
        enum TH_FIN = 0x01;
    }




    static if(!is(typeof(TH_SYN))) {
        enum TH_SYN = 0x02;
    }




    static if(!is(typeof(TH_RST))) {
        enum TH_RST = 0x04;
    }




    static if(!is(typeof(TH_PUSH))) {
        enum TH_PUSH = 0x08;
    }




    static if(!is(typeof(TH_ACK))) {
        enum TH_ACK = 0x10;
    }




    static if(!is(typeof(TH_URG))) {
        enum TH_URG = 0x20;
    }




    static if(!is(typeof(PF_KCM))) {
        enum PF_KCM = 41;
    }




    static if(!is(typeof(PF_VSOCK))) {
        enum PF_VSOCK = 40;
    }




    static if(!is(typeof(PF_NFC))) {
        enum PF_NFC = 39;
    }




    static if(!is(typeof(TCPOPT_EOL))) {
        enum TCPOPT_EOL = 0;
    }




    static if(!is(typeof(TCPOPT_NOP))) {
        enum TCPOPT_NOP = 1;
    }




    static if(!is(typeof(TCPOPT_MAXSEG))) {
        enum TCPOPT_MAXSEG = 2;
    }




    static if(!is(typeof(TCPOLEN_MAXSEG))) {
        enum TCPOLEN_MAXSEG = 4;
    }




    static if(!is(typeof(TCPOPT_WINDOW))) {
        enum TCPOPT_WINDOW = 3;
    }




    static if(!is(typeof(TCPOLEN_WINDOW))) {
        enum TCPOLEN_WINDOW = 3;
    }




    static if(!is(typeof(TCPOPT_SACK_PERMITTED))) {
        enum TCPOPT_SACK_PERMITTED = 4;
    }




    static if(!is(typeof(TCPOLEN_SACK_PERMITTED))) {
        enum TCPOLEN_SACK_PERMITTED = 2;
    }




    static if(!is(typeof(TCPOPT_SACK))) {
        enum TCPOPT_SACK = 5;
    }




    static if(!is(typeof(TCPOPT_TIMESTAMP))) {
        enum TCPOPT_TIMESTAMP = 8;
    }




    static if(!is(typeof(TCPOLEN_TIMESTAMP))) {
        enum TCPOLEN_TIMESTAMP = 10;
    }
    static if(!is(typeof(TCP_MSS))) {
        enum TCP_MSS = 512;
    }




    static if(!is(typeof(TCP_MAXWIN))) {
        enum TCP_MAXWIN = 65535;
    }




    static if(!is(typeof(TCP_MAX_WINSHIFT))) {
        enum TCP_MAX_WINSHIFT = 14;
    }




    static if(!is(typeof(SOL_TCP))) {
        enum SOL_TCP = 6;
    }




    static if(!is(typeof(TCPI_OPT_TIMESTAMPS))) {
        enum TCPI_OPT_TIMESTAMPS = 1;
    }




    static if(!is(typeof(TCPI_OPT_SACK))) {
        enum TCPI_OPT_SACK = 2;
    }




    static if(!is(typeof(TCPI_OPT_WSCALE))) {
        enum TCPI_OPT_WSCALE = 4;
    }




    static if(!is(typeof(TCPI_OPT_ECN))) {
        enum TCPI_OPT_ECN = 8;
    }




    static if(!is(typeof(TCPI_OPT_ECN_SEEN))) {
        enum TCPI_OPT_ECN_SEEN = 16;
    }




    static if(!is(typeof(TCPI_OPT_SYN_DATA))) {
        enum TCPI_OPT_SYN_DATA = 32;
    }




    static if(!is(typeof(PF_ALG))) {
        enum PF_ALG = 38;
    }




    static if(!is(typeof(PF_CAIF))) {
        enum PF_CAIF = 37;
    }




    static if(!is(typeof(TCP_MD5SIG_MAXKEYLEN))) {
        enum TCP_MD5SIG_MAXKEYLEN = 80;
    }




    static if(!is(typeof(TCP_MD5SIG_FLAG_PREFIX))) {
        enum TCP_MD5SIG_FLAG_PREFIX = 1;
    }




    static if(!is(typeof(PF_IEEE802154))) {
        enum PF_IEEE802154 = 36;
    }




    static if(!is(typeof(PF_PHONET))) {
        enum PF_PHONET = 35;
    }




    static if(!is(typeof(PF_ISDN))) {
        enum PF_ISDN = 34;
    }




    static if(!is(typeof(PF_RXRPC))) {
        enum PF_RXRPC = 33;
    }




    static if(!is(typeof(TCP_COOKIE_MIN))) {
        enum TCP_COOKIE_MIN = 8;
    }




    static if(!is(typeof(TCP_COOKIE_MAX))) {
        enum TCP_COOKIE_MAX = 16;
    }
    static if(!is(typeof(TCP_MSS_DEFAULT))) {
        enum TCP_MSS_DEFAULT = 536U;
    }




    static if(!is(typeof(TCP_MSS_DESIRED))) {
        enum TCP_MSS_DESIRED = 1220U;
    }




    static if(!is(typeof(PF_IUCV))) {
        enum PF_IUCV = 32;
    }




    static if(!is(typeof(PF_BLUETOOTH))) {
        enum PF_BLUETOOTH = 31;
    }




    static if(!is(typeof(PF_TIPC))) {
        enum PF_TIPC = 30;
    }




    static if(!is(typeof(PF_CAN))) {
        enum PF_CAN = 29;
    }




    static if(!is(typeof(PF_MPLS))) {
        enum PF_MPLS = 28;
    }




    static if(!is(typeof(_RPC_NETDB_H))) {
        enum _RPC_NETDB_H = 1;
    }




    static if(!is(typeof(PF_IB))) {
        enum PF_IB = 27;
    }




    static if(!is(typeof(PF_LLC))) {
        enum PF_LLC = 26;
    }




    static if(!is(typeof(PF_WANPIPE))) {
        enum PF_WANPIPE = 25;
    }




    static if(!is(typeof(PF_PPPOX))) {
        enum PF_PPPOX = 24;
    }




    static if(!is(typeof(PF_IRDA))) {
        enum PF_IRDA = 23;
    }




    static if(!is(typeof(PF_SNA))) {
        enum PF_SNA = 22;
    }




    static if(!is(typeof(PF_RDS))) {
        enum PF_RDS = 21;
    }




    static if(!is(typeof(PF_ATMSVC))) {
        enum PF_ATMSVC = 20;
    }




    static if(!is(typeof(PF_ECONET))) {
        enum PF_ECONET = 19;
    }




    static if(!is(typeof(PF_ASH))) {
        enum PF_ASH = 18;
    }




    static if(!is(typeof(PF_PACKET))) {
        enum PF_PACKET = 17;
    }






    static if(!is(typeof(PF_NETLINK))) {
        enum PF_NETLINK = 16;
    }




    static if(!is(typeof(PF_KEY))) {
        enum PF_KEY = 15;
    }




    static if(!is(typeof(PF_SECURITY))) {
        enum PF_SECURITY = 14;
    }




    static if(!is(typeof(PF_NETBEUI))) {
        enum PF_NETBEUI = 13;
    }




    static if(!is(typeof(PF_DECnet))) {
        enum PF_DECnet = 12;
    }




    static if(!is(typeof(PF_ROSE))) {
        enum PF_ROSE = 11;
    }




    static if(!is(typeof(PF_INET6))) {
        enum PF_INET6 = 10;
    }




    static if(!is(typeof(PF_X25))) {
        enum PF_X25 = 9;
    }




    static if(!is(typeof(PF_ATMPVC))) {
        enum PF_ATMPVC = 8;
    }




    static if(!is(typeof(PF_BRIDGE))) {
        enum PF_BRIDGE = 7;
    }




    static if(!is(typeof(_STDC_PREDEF_H))) {
        enum _STDC_PREDEF_H = 1;
    }




    static if(!is(typeof(_STDINT_H))) {
        enum _STDINT_H = 1;
    }




    static if(!is(typeof(PF_NETROM))) {
        enum PF_NETROM = 6;
    }




    static if(!is(typeof(PF_APPLETALK))) {
        enum PF_APPLETALK = 5;
    }




    static if(!is(typeof(PF_IPX))) {
        enum PF_IPX = 4;
    }




    static if(!is(typeof(PF_AX25))) {
        enum PF_AX25 = 3;
    }




    static if(!is(typeof(PF_INET))) {
        enum PF_INET = 2;
    }
    static if(!is(typeof(PF_LOCAL))) {
        enum PF_LOCAL = 1;
    }




    static if(!is(typeof(PF_UNSPEC))) {
        enum PF_UNSPEC = 0;
    }






    static if(!is(typeof(_SS_SIZE))) {
        enum _SS_SIZE = 128;
    }
    static if(!is(typeof(_BITS_SOCKADDR_H))) {
        enum _BITS_SOCKADDR_H = 1;
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




    static if(!is(typeof(_STDIO_H))) {
        enum _STDIO_H = 1;
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






    static if(!is(typeof(_POSIX_BARRIERS))) {
        enum _POSIX_BARRIERS = 200809L;
    }




    static if(!is(typeof(P_tmpdir))) {
        enum P_tmpdir = "/tmp";
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




    static if(!is(typeof(POLLNVAL))) {
        enum POLLNVAL = 0x020;
    }




    static if(!is(typeof(POLLHUP))) {
        enum POLLHUP = 0x010;
    }




    static if(!is(typeof(POLLERR))) {
        enum POLLERR = 0x008;
    }




    static if(!is(typeof(POLLWRBAND))) {
        enum POLLWRBAND = 0x200;
    }




    static if(!is(typeof(POLLWRNORM))) {
        enum POLLWRNORM = 0x100;
    }




    static if(!is(typeof(POLLRDBAND))) {
        enum POLLRDBAND = 0x080;
    }




    static if(!is(typeof(POLLRDNORM))) {
        enum POLLRDNORM = 0x040;
    }




    static if(!is(typeof(POLLOUT))) {
        enum POLLOUT = 0x004;
    }




    static if(!is(typeof(POLLPRI))) {
        enum POLLPRI = 0x002;
    }




    static if(!is(typeof(POLLIN))) {
        enum POLLIN = 0x001;
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




    static if(!is(typeof(IPV6_RTHDR_TYPE_0))) {
        enum IPV6_RTHDR_TYPE_0 = 0;
    }




    static if(!is(typeof(IPV6_RTHDR_STRICT))) {
        enum IPV6_RTHDR_STRICT = 1;
    }




    static if(!is(typeof(IPV6_RTHDR_LOOSE))) {
        enum IPV6_RTHDR_LOOSE = 0;
    }




    static if(!is(typeof(SOL_ICMPV6))) {
        enum SOL_ICMPV6 = 58;
    }




    static if(!is(typeof(SOL_IPV6))) {
        enum SOL_IPV6 = 41;
    }




    static if(!is(typeof(IPV6_PMTUDISC_OMIT))) {
        enum IPV6_PMTUDISC_OMIT = 5;
    }




    static if(!is(typeof(IPV6_PMTUDISC_INTERFACE))) {
        enum IPV6_PMTUDISC_INTERFACE = 4;
    }




    static if(!is(typeof(IPV6_PMTUDISC_PROBE))) {
        enum IPV6_PMTUDISC_PROBE = 3;
    }




    static if(!is(typeof(IPV6_PMTUDISC_DO))) {
        enum IPV6_PMTUDISC_DO = 2;
    }




    static if(!is(typeof(IPV6_PMTUDISC_WANT))) {
        enum IPV6_PMTUDISC_WANT = 1;
    }




    static if(!is(typeof(IPV6_PMTUDISC_DONT))) {
        enum IPV6_PMTUDISC_DONT = 0;
    }
    static if(!is(typeof(IPV6_FREEBIND))) {
        enum IPV6_FREEBIND = 78;
    }




    static if(!is(typeof(IPV6_RECVFRAGSIZE))) {
        enum IPV6_RECVFRAGSIZE = 77;
    }




    static if(!is(typeof(IPV6_UNICAST_IF))) {
        enum IPV6_UNICAST_IF = 76;
    }




    static if(!is(typeof(IPV6_TRANSPARENT))) {
        enum IPV6_TRANSPARENT = 75;
    }






    static if(!is(typeof(IPV6_ORIGDSTADDR))) {
        enum IPV6_ORIGDSTADDR = 74;
    }




    static if(!is(typeof(IPV6_MINHOPCOUNT))) {
        enum IPV6_MINHOPCOUNT = 73;
    }




    static if(!is(typeof(IPV6_ADDR_PREFERENCES))) {
        enum IPV6_ADDR_PREFERENCES = 72;
    }




    static if(!is(typeof(IPV6_AUTOFLOWLABEL))) {
        enum IPV6_AUTOFLOWLABEL = 70;
    }




    static if(!is(typeof(IPV6_TCLASS))) {
        enum IPV6_TCLASS = 67;
    }




    static if(!is(typeof(IPV6_RECVTCLASS))) {
        enum IPV6_RECVTCLASS = 66;
    }




    static if(!is(typeof(IPV6_DONTFRAG))) {
        enum IPV6_DONTFRAG = 62;
    }




    static if(!is(typeof(IPV6_PATHMTU))) {
        enum IPV6_PATHMTU = 61;
    }




    static if(!is(typeof(IPV6_RECVPATHMTU))) {
        enum IPV6_RECVPATHMTU = 60;
    }




    static if(!is(typeof(IPV6_DSTOPTS))) {
        enum IPV6_DSTOPTS = 59;
    }




    static if(!is(typeof(IPV6_RECVDSTOPTS))) {
        enum IPV6_RECVDSTOPTS = 58;
    }




    static if(!is(typeof(IPV6_RTHDR))) {
        enum IPV6_RTHDR = 57;
    }




    static if(!is(typeof(IPV6_RECVRTHDR))) {
        enum IPV6_RECVRTHDR = 56;
    }




    static if(!is(typeof(IPV6_RTHDRDSTOPTS))) {
        enum IPV6_RTHDRDSTOPTS = 55;
    }




    static if(!is(typeof(IPV6_HOPOPTS))) {
        enum IPV6_HOPOPTS = 54;
    }




    static if(!is(typeof(IPV6_RECVHOPOPTS))) {
        enum IPV6_RECVHOPOPTS = 53;
    }




    static if(!is(typeof(IPV6_HOPLIMIT))) {
        enum IPV6_HOPLIMIT = 52;
    }




    static if(!is(typeof(IPV6_RECVHOPLIMIT))) {
        enum IPV6_RECVHOPLIMIT = 51;
    }




    static if(!is(typeof(IPV6_PKTINFO))) {
        enum IPV6_PKTINFO = 50;
    }




    static if(!is(typeof(IPV6_RECVPKTINFO))) {
        enum IPV6_RECVPKTINFO = 49;
    }




    static if(!is(typeof(IPV6_HDRINCL))) {
        enum IPV6_HDRINCL = 36;
    }




    static if(!is(typeof(IPV6_XFRM_POLICY))) {
        enum IPV6_XFRM_POLICY = 35;
    }




    static if(!is(typeof(IPV6_IPSEC_POLICY))) {
        enum IPV6_IPSEC_POLICY = 34;
    }




    static if(!is(typeof(IPV6_MULTICAST_ALL))) {
        enum IPV6_MULTICAST_ALL = 29;
    }




    static if(!is(typeof(IPV6_LEAVE_ANYCAST))) {
        enum IPV6_LEAVE_ANYCAST = 28;
    }




    static if(!is(typeof(IPV6_JOIN_ANYCAST))) {
        enum IPV6_JOIN_ANYCAST = 27;
    }




    static if(!is(typeof(IPV6_V6ONLY))) {
        enum IPV6_V6ONLY = 26;
    }




    static if(!is(typeof(IPV6_RECVERR))) {
        enum IPV6_RECVERR = 25;
    }




    static if(!is(typeof(IPV6_MTU))) {
        enum IPV6_MTU = 24;
    }




    static if(!is(typeof(IPV6_MTU_DISCOVER))) {
        enum IPV6_MTU_DISCOVER = 23;
    }




    static if(!is(typeof(IPV6_ROUTER_ALERT))) {
        enum IPV6_ROUTER_ALERT = 22;
    }




    static if(!is(typeof(IPV6_LEAVE_GROUP))) {
        enum IPV6_LEAVE_GROUP = 21;
    }




    static if(!is(typeof(IPV6_JOIN_GROUP))) {
        enum IPV6_JOIN_GROUP = 20;
    }




    static if(!is(typeof(IPV6_MULTICAST_LOOP))) {
        enum IPV6_MULTICAST_LOOP = 19;
    }




    static if(!is(typeof(IPV6_MULTICAST_HOPS))) {
        enum IPV6_MULTICAST_HOPS = 18;
    }






    static if(!is(typeof(IPV6_MULTICAST_IF))) {
        enum IPV6_MULTICAST_IF = 17;
    }




    static if(!is(typeof(IPV6_UNICAST_HOPS))) {
        enum IPV6_UNICAST_HOPS = 16;
    }




    static if(!is(typeof(_STDLIB_H))) {
        enum _STDLIB_H = 1;
    }




    static if(!is(typeof(IPV6_AUTHHDR))) {
        enum IPV6_AUTHHDR = 10;
    }




    static if(!is(typeof(IPV6_NEXTHOP))) {
        enum IPV6_NEXTHOP = 9;
    }
    static if(!is(typeof(IPV6_2292HOPLIMIT))) {
        enum IPV6_2292HOPLIMIT = 8;
    }






    static if(!is(typeof(IPV6_CHECKSUM))) {
        enum IPV6_CHECKSUM = 7;
    }




    static if(!is(typeof(IPV6_2292PKTOPTIONS))) {
        enum IPV6_2292PKTOPTIONS = 6;
    }




    static if(!is(typeof(IPV6_2292RTHDR))) {
        enum IPV6_2292RTHDR = 5;
    }




    static if(!is(typeof(IPV6_2292DSTOPTS))) {
        enum IPV6_2292DSTOPTS = 4;
    }




    static if(!is(typeof(IPV6_2292HOPOPTS))) {
        enum IPV6_2292HOPOPTS = 3;
    }




    static if(!is(typeof(__ldiv_t_defined))) {
        enum __ldiv_t_defined = 1;
    }




    static if(!is(typeof(IPV6_2292PKTINFO))) {
        enum IPV6_2292PKTINFO = 2;
    }




    static if(!is(typeof(IPV6_ADDRFORM))) {
        enum IPV6_ADDRFORM = 1;
    }




    static if(!is(typeof(IP_MAX_MEMBERSHIPS))) {
        enum IP_MAX_MEMBERSHIPS = 20;
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






    static if(!is(typeof(IP_DEFAULT_MULTICAST_LOOP))) {
        enum IP_DEFAULT_MULTICAST_LOOP = 1;
    }




    static if(!is(typeof(IP_DEFAULT_MULTICAST_TTL))) {
        enum IP_DEFAULT_MULTICAST_TTL = 1;
    }




    static if(!is(typeof(SOL_IP))) {
        enum SOL_IP = 0;
    }




    static if(!is(typeof(IP_UNICAST_IF))) {
        enum IP_UNICAST_IF = 50;
    }




    static if(!is(typeof(IP_MULTICAST_ALL))) {
        enum IP_MULTICAST_ALL = 49;
    }




    static if(!is(typeof(IP_MSFILTER))) {
        enum IP_MSFILTER = 41;
    }




    static if(!is(typeof(IP_DROP_SOURCE_MEMBERSHIP))) {
        enum IP_DROP_SOURCE_MEMBERSHIP = 40;
    }




    static if(!is(typeof(IP_ADD_SOURCE_MEMBERSHIP))) {
        enum IP_ADD_SOURCE_MEMBERSHIP = 39;
    }




    static if(!is(typeof(IP_BLOCK_SOURCE))) {
        enum IP_BLOCK_SOURCE = 38;
    }




    static if(!is(typeof(IP_UNBLOCK_SOURCE))) {
        enum IP_UNBLOCK_SOURCE = 37;
    }




    static if(!is(typeof(IP_DROP_MEMBERSHIP))) {
        enum IP_DROP_MEMBERSHIP = 36;
    }




    static if(!is(typeof(IP_ADD_MEMBERSHIP))) {
        enum IP_ADD_MEMBERSHIP = 35;
    }




    static if(!is(typeof(IP_MULTICAST_LOOP))) {
        enum IP_MULTICAST_LOOP = 34;
    }




    static if(!is(typeof(IP_MULTICAST_TTL))) {
        enum IP_MULTICAST_TTL = 33;
    }




    static if(!is(typeof(IP_MULTICAST_IF))) {
        enum IP_MULTICAST_IF = 32;
    }




    static if(!is(typeof(IP_PMTUDISC_OMIT))) {
        enum IP_PMTUDISC_OMIT = 5;
    }




    static if(!is(typeof(IP_PMTUDISC_INTERFACE))) {
        enum IP_PMTUDISC_INTERFACE = 4;
    }




    static if(!is(typeof(IP_PMTUDISC_PROBE))) {
        enum IP_PMTUDISC_PROBE = 3;
    }




    static if(!is(typeof(IP_PMTUDISC_DO))) {
        enum IP_PMTUDISC_DO = 2;
    }




    static if(!is(typeof(IP_PMTUDISC_WANT))) {
        enum IP_PMTUDISC_WANT = 1;
    }




    static if(!is(typeof(IP_PMTUDISC_DONT))) {
        enum IP_PMTUDISC_DONT = 0;
    }




    static if(!is(typeof(IP_RECVFRAGSIZE))) {
        enum IP_RECVFRAGSIZE = 25;
    }




    static if(!is(typeof(IP_BIND_ADDRESS_NO_PORT))) {
        enum IP_BIND_ADDRESS_NO_PORT = 24;
    }




    static if(!is(typeof(IP_CHECKSUM))) {
        enum IP_CHECKSUM = 23;
    }




    static if(!is(typeof(IP_NODEFRAG))) {
        enum IP_NODEFRAG = 22;
    }




    static if(!is(typeof(IP_MINTTL))) {
        enum IP_MINTTL = 21;
    }






    static if(!is(typeof(IP_ORIGDSTADDR))) {
        enum IP_ORIGDSTADDR = 20;
    }




    static if(!is(typeof(IP_TRANSPARENT))) {
        enum IP_TRANSPARENT = 19;
    }




    static if(!is(typeof(IP_PASSSEC))) {
        enum IP_PASSSEC = 18;
    }




    static if(!is(typeof(IP_XFRM_POLICY))) {
        enum IP_XFRM_POLICY = 17;
    }




    static if(!is(typeof(IP_IPSEC_POLICY))) {
        enum IP_IPSEC_POLICY = 16;
    }




    static if(!is(typeof(IP_FREEBIND))) {
        enum IP_FREEBIND = 15;
    }




    static if(!is(typeof(IP_MTU))) {
        enum IP_MTU = 14;
    }




    static if(!is(typeof(IP_RECVTOS))) {
        enum IP_RECVTOS = 13;
    }




    static if(!is(typeof(IP_RECVTTL))) {
        enum IP_RECVTTL = 12;
    }




    static if(!is(typeof(IP_RECVERR))) {
        enum IP_RECVERR = 11;
    }




    static if(!is(typeof(IP_MTU_DISCOVER))) {
        enum IP_MTU_DISCOVER = 10;
    }




    static if(!is(typeof(IP_PMTUDISC))) {
        enum IP_PMTUDISC = 10;
    }




    static if(!is(typeof(IP_PKTOPTIONS))) {
        enum IP_PKTOPTIONS = 9;
    }




    static if(!is(typeof(IP_PKTINFO))) {
        enum IP_PKTINFO = 8;
    }




    static if(!is(typeof(IP_ROUTER_ALERT))) {
        enum IP_ROUTER_ALERT = 5;
    }




    static if(!is(typeof(MCAST_INCLUDE))) {
        enum MCAST_INCLUDE = 1;
    }




    static if(!is(typeof(MCAST_EXCLUDE))) {
        enum MCAST_EXCLUDE = 0;
    }




    static if(!is(typeof(MCAST_MSFILTER))) {
        enum MCAST_MSFILTER = 48;
    }




    static if(!is(typeof(MCAST_LEAVE_SOURCE_GROUP))) {
        enum MCAST_LEAVE_SOURCE_GROUP = 47;
    }




    static if(!is(typeof(MCAST_JOIN_SOURCE_GROUP))) {
        enum MCAST_JOIN_SOURCE_GROUP = 46;
    }




    static if(!is(typeof(MCAST_LEAVE_GROUP))) {
        enum MCAST_LEAVE_GROUP = 45;
    }




    static if(!is(typeof(MCAST_UNBLOCK_SOURCE))) {
        enum MCAST_UNBLOCK_SOURCE = 44;
    }




    static if(!is(typeof(MCAST_BLOCK_SOURCE))) {
        enum MCAST_BLOCK_SOURCE = 43;
    }




    static if(!is(typeof(MCAST_JOIN_GROUP))) {
        enum MCAST_JOIN_GROUP = 42;
    }




    static if(!is(typeof(IP_RETOPTS))) {
        enum IP_RETOPTS = 7;
    }






    static if(!is(typeof(IP_RECVOPTS))) {
        enum IP_RECVOPTS = 6;
    }




    static if(!is(typeof(IP_TTL))) {
        enum IP_TTL = 2;
    }




    static if(!is(typeof(IP_TOS))) {
        enum IP_TOS = 1;
    }




    static if(!is(typeof(IP_HDRINCL))) {
        enum IP_HDRINCL = 3;
    }




    static if(!is(typeof(IP_OPTIONS))) {
        enum IP_OPTIONS = 4;
    }




    static if(!is(typeof(__USE_KERNEL_IPV6_DEFS))) {
        enum __USE_KERNEL_IPV6_DEFS = 0;
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
    static if(!is(typeof(_BITS_BYTESWAP_H))) {
        enum _BITS_BYTESWAP_H = 1;
    }
    static if(!is(typeof(__BITS_PER_LONG))) {
        enum __BITS_PER_LONG = 64;
    }






    static if(!is(typeof(SIOCGSTAMPNS))) {
        enum SIOCGSTAMPNS = 0x8907;
    }




    static if(!is(typeof(SIOCGSTAMP))) {
        enum SIOCGSTAMP = 0x8906;
    }




    static if(!is(typeof(SIOCATMARK))) {
        enum SIOCATMARK = 0x8905;
    }




    static if(!is(typeof(SIOCGPGRP))) {
        enum SIOCGPGRP = 0x8904;
    }




    static if(!is(typeof(FIOGETOWN))) {
        enum FIOGETOWN = 0x8903;
    }




    static if(!is(typeof(SIOCSPGRP))) {
        enum SIOCSPGRP = 0x8902;
    }




    static if(!is(typeof(FIOSETOWN))) {
        enum FIOSETOWN = 0x8901;
    }
    static if(!is(typeof(_STRINGS_H))) {
        enum _STRINGS_H = 1;
    }
    static if(!is(typeof(SO_SNDTIMEO_NEW))) {
        enum SO_SNDTIMEO_NEW = 67;
    }




    static if(!is(typeof(SO_RCVTIMEO_NEW))) {
        enum SO_RCVTIMEO_NEW = 66;
    }




    static if(!is(typeof(SO_TIMESTAMPING_NEW))) {
        enum SO_TIMESTAMPING_NEW = 65;
    }




    static if(!is(typeof(SO_TIMESTAMPNS_NEW))) {
        enum SO_TIMESTAMPNS_NEW = 64;
    }




    static if(!is(typeof(SO_TIMESTAMP_NEW))) {
        enum SO_TIMESTAMP_NEW = 63;
    }




    static if(!is(typeof(SO_TIMESTAMPING_OLD))) {
        enum SO_TIMESTAMPING_OLD = 37;
    }




    static if(!is(typeof(SO_TIMESTAMPNS_OLD))) {
        enum SO_TIMESTAMPNS_OLD = 35;
    }




    static if(!is(typeof(SO_TIMESTAMP_OLD))) {
        enum SO_TIMESTAMP_OLD = 29;
    }




    static if(!is(typeof(SO_BINDTOIFINDEX))) {
        enum SO_BINDTOIFINDEX = 62;
    }






    static if(!is(typeof(SO_TXTIME))) {
        enum SO_TXTIME = 61;
    }




    static if(!is(typeof(SO_ZEROCOPY))) {
        enum SO_ZEROCOPY = 60;
    }




    static if(!is(typeof(SO_PEERGROUPS))) {
        enum SO_PEERGROUPS = 59;
    }




    static if(!is(typeof(SCM_TIMESTAMPING_PKTINFO))) {
        enum SCM_TIMESTAMPING_PKTINFO = 58;
    }




    static if(!is(typeof(SO_COOKIE))) {
        enum SO_COOKIE = 57;
    }




    static if(!is(typeof(SO_INCOMING_NAPI_ID))) {
        enum SO_INCOMING_NAPI_ID = 56;
    }




    static if(!is(typeof(SO_MEMINFO))) {
        enum SO_MEMINFO = 55;
    }




    static if(!is(typeof(SCM_TIMESTAMPING_OPT_STATS))) {
        enum SCM_TIMESTAMPING_OPT_STATS = 54;
    }




    static if(!is(typeof(SO_CNX_ADVICE))) {
        enum SO_CNX_ADVICE = 53;
    }




    static if(!is(typeof(SO_ATTACH_REUSEPORT_EBPF))) {
        enum SO_ATTACH_REUSEPORT_EBPF = 52;
    }




    static if(!is(typeof(SO_ATTACH_REUSEPORT_CBPF))) {
        enum SO_ATTACH_REUSEPORT_CBPF = 51;
    }






    static if(!is(typeof(SO_ATTACH_BPF))) {
        enum SO_ATTACH_BPF = 50;
    }




    static if(!is(typeof(SO_INCOMING_CPU))) {
        enum SO_INCOMING_CPU = 49;
    }




    static if(!is(typeof(SO_BPF_EXTENSIONS))) {
        enum SO_BPF_EXTENSIONS = 48;
    }




    static if(!is(typeof(SO_MAX_PACING_RATE))) {
        enum SO_MAX_PACING_RATE = 47;
    }




    static if(!is(typeof(SO_BUSY_POLL))) {
        enum SO_BUSY_POLL = 46;
    }




    static if(!is(typeof(SO_SELECT_ERR_QUEUE))) {
        enum SO_SELECT_ERR_QUEUE = 45;
    }




    static if(!is(typeof(SO_LOCK_FILTER))) {
        enum SO_LOCK_FILTER = 44;
    }




    static if(!is(typeof(SO_NOFCS))) {
        enum SO_NOFCS = 43;
    }




    static if(!is(typeof(SO_PEEK_OFF))) {
        enum SO_PEEK_OFF = 42;
    }






    static if(!is(typeof(SO_WIFI_STATUS))) {
        enum SO_WIFI_STATUS = 41;
    }




    static if(!is(typeof(SO_RXQ_OVFL))) {
        enum SO_RXQ_OVFL = 40;
    }




    static if(!is(typeof(SO_DOMAIN))) {
        enum SO_DOMAIN = 39;
    }




    static if(!is(typeof(SO_PROTOCOL))) {
        enum SO_PROTOCOL = 38;
    }




    static if(!is(typeof(SO_MARK))) {
        enum SO_MARK = 36;
    }




    static if(!is(typeof(SO_PASSSEC))) {
        enum SO_PASSSEC = 34;
    }




    static if(!is(typeof(SO_PEERSEC))) {
        enum SO_PEERSEC = 31;
    }




    static if(!is(typeof(SO_ACCEPTCONN))) {
        enum SO_ACCEPTCONN = 30;
    }




    static if(!is(typeof(SO_PEERNAME))) {
        enum SO_PEERNAME = 28;
    }






    static if(!is(typeof(SO_DETACH_FILTER))) {
        enum SO_DETACH_FILTER = 27;
    }




    static if(!is(typeof(SO_ATTACH_FILTER))) {
        enum SO_ATTACH_FILTER = 26;
    }




    static if(!is(typeof(SO_BINDTODEVICE))) {
        enum SO_BINDTODEVICE = 25;
    }




    static if(!is(typeof(SO_SECURITY_ENCRYPTION_NETWORK))) {
        enum SO_SECURITY_ENCRYPTION_NETWORK = 24;
    }




    static if(!is(typeof(SO_SECURITY_ENCRYPTION_TRANSPORT))) {
        enum SO_SECURITY_ENCRYPTION_TRANSPORT = 23;
    }




    static if(!is(typeof(SO_SECURITY_AUTHENTICATION))) {
        enum SO_SECURITY_AUTHENTICATION = 22;
    }




    static if(!is(typeof(SO_SNDTIMEO_OLD))) {
        enum SO_SNDTIMEO_OLD = 21;
    }




    static if(!is(typeof(SO_RCVTIMEO_OLD))) {
        enum SO_RCVTIMEO_OLD = 20;
    }




    static if(!is(typeof(SO_SNDLOWAT))) {
        enum SO_SNDLOWAT = 19;
    }




    static if(!is(typeof(SO_RCVLOWAT))) {
        enum SO_RCVLOWAT = 18;
    }




    static if(!is(typeof(_SYS_CDEFS_H))) {
        enum _SYS_CDEFS_H = 1;
    }




    static if(!is(typeof(SO_PEERCRED))) {
        enum SO_PEERCRED = 17;
    }




    static if(!is(typeof(SO_PASSCRED))) {
        enum SO_PASSCRED = 16;
    }




    static if(!is(typeof(SO_REUSEPORT))) {
        enum SO_REUSEPORT = 15;
    }




    static if(!is(typeof(SO_BSDCOMPAT))) {
        enum SO_BSDCOMPAT = 14;
    }




    static if(!is(typeof(SO_LINGER))) {
        enum SO_LINGER = 13;
    }
    static if(!is(typeof(SO_PRIORITY))) {
        enum SO_PRIORITY = 12;
    }
    static if(!is(typeof(SO_NO_CHECK))) {
        enum SO_NO_CHECK = 11;
    }




    static if(!is(typeof(SO_OOBINLINE))) {
        enum SO_OOBINLINE = 10;
    }
    static if(!is(typeof(SO_KEEPALIVE))) {
        enum SO_KEEPALIVE = 9;
    }
    static if(!is(typeof(SO_RCVBUFFORCE))) {
        enum SO_RCVBUFFORCE = 33;
    }




    static if(!is(typeof(SO_SNDBUFFORCE))) {
        enum SO_SNDBUFFORCE = 32;
    }






    static if(!is(typeof(__glibc_c99_flexarr_available))) {
        enum __glibc_c99_flexarr_available = 1;
    }




    static if(!is(typeof(SO_RCVBUF))) {
        enum SO_RCVBUF = 8;
    }




    static if(!is(typeof(SO_SNDBUF))) {
        enum SO_SNDBUF = 7;
    }
    static if(!is(typeof(SO_BROADCAST))) {
        enum SO_BROADCAST = 6;
    }




    static if(!is(typeof(SO_DONTROUTE))) {
        enum SO_DONTROUTE = 5;
    }




    static if(!is(typeof(SO_ERROR))) {
        enum SO_ERROR = 4;
    }






    static if(!is(typeof(SO_TYPE))) {
        enum SO_TYPE = 3;
    }






    static if(!is(typeof(SO_REUSEADDR))) {
        enum SO_REUSEADDR = 2;
    }






    static if(!is(typeof(SO_DEBUG))) {
        enum SO_DEBUG = 1;
    }






    static if(!is(typeof(SOL_SOCKET))) {
        enum SOL_SOCKET = 1;
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




    static if(!is(typeof(__HAVE_GENERIC_SELECTION))) {
        enum __HAVE_GENERIC_SELECTION = 1;
    }




    static if(!is(typeof(_SYS_POLL_H))) {
        enum _SYS_POLL_H = 1;
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




    static if(!is(typeof(_SYS_SELECT_H))) {
        enum _SYS_SELECT_H = 1;
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




    static if(!is(typeof(_SYS_SOCKET_H))) {
        enum _SYS_SOCKET_H = 1;
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




    static if(!is(typeof(_SYS_STAT_H))) {
        enum _SYS_STAT_H = 1;
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
    static if(!is(typeof(_ARPA_INET_H))) {
        enum _ARPA_INET_H = 1;
    }






    static if(!is(typeof(_ALLOCA_H))) {
        enum _ALLOCA_H = 1;
    }
    static if(!is(typeof(MONGOC_WRITE_CONCERN_W_UNACKNOWLEDGED))) {
        enum MONGOC_WRITE_CONCERN_W_UNACKNOWLEDGED = 0;
    }
    static if(!is(typeof(MONGOC_URI_SSLALLOWINVALIDHOSTNAMES))) {
        enum MONGOC_URI_SSLALLOWINVALIDHOSTNAMES = "sslallowinvalidhostnames";
    }
    static if(!is(typeof(MONGOC_URI_SSLALLOWINVALIDCERTIFICATES))) {
        enum MONGOC_URI_SSLALLOWINVALIDCERTIFICATES = "sslallowinvalidcertificates";
    }
    static if(!is(typeof(S_BLKSIZE))) {
        enum S_BLKSIZE = 512;
    }




    static if(!is(typeof(MONGOC_URI_SSLCERTIFICATEAUTHORITYFILE))) {
        enum MONGOC_URI_SSLCERTIFICATEAUTHORITYFILE = "sslcertificateauthorityfile";
    }




    static if(!is(typeof(MONGOC_URI_SSLCLIENTCERTIFICATEKEYPASSWORD))) {
        enum MONGOC_URI_SSLCLIENTCERTIFICATEKEYPASSWORD = "sslclientcertificatekeypassword";
    }




    static if(!is(typeof(MONGOC_URI_SSLCLIENTCERTIFICATEKEYFILE))) {
        enum MONGOC_URI_SSLCLIENTCERTIFICATEKEYFILE = "sslclientcertificatekeyfile";
    }




    static if(!is(typeof(MONGOC_URI_SSL))) {
        enum MONGOC_URI_SSL = "ssl";
    }




    static if(!is(typeof(MONGOC_URI_ZLIBCOMPRESSIONLEVEL))) {
        enum MONGOC_URI_ZLIBCOMPRESSIONLEVEL = "zlibcompressionlevel";
    }




    static if(!is(typeof(MONGOC_URI_WTIMEOUTMS))) {
        enum MONGOC_URI_WTIMEOUTMS = "wtimeoutms";
    }




    static if(!is(typeof(MONGOC_URI_WAITQUEUETIMEOUTMS))) {
        enum MONGOC_URI_WAITQUEUETIMEOUTMS = "waitqueuetimeoutms";
    }




    static if(!is(typeof(MONGOC_URI_WAITQUEUEMULTIPLE))) {
        enum MONGOC_URI_WAITQUEUEMULTIPLE = "waitqueuemultiple";
    }




    static if(!is(typeof(MONGOC_URI_W))) {
        enum MONGOC_URI_W = "w";
    }




    static if(!is(typeof(MONGOC_URI_TLSINSECURE))) {
        enum MONGOC_URI_TLSINSECURE = "tlsinsecure";
    }




    static if(!is(typeof(MONGOC_URI_TLSALLOWINVALIDHOSTNAMES))) {
        enum MONGOC_URI_TLSALLOWINVALIDHOSTNAMES = "tlsallowinvalidhostnames";
    }




    static if(!is(typeof(MONGOC_URI_TLSALLOWINVALIDCERTIFICATES))) {
        enum MONGOC_URI_TLSALLOWINVALIDCERTIFICATES = "tlsallowinvalidcertificates";
    }




    static if(!is(typeof(MONGOC_URI_TLSCAFILE))) {
        enum MONGOC_URI_TLSCAFILE = "tlscafile";
    }




    static if(!is(typeof(MONGOC_URI_TLSCERTIFICATEKEYFILEPASSWORD))) {
        enum MONGOC_URI_TLSCERTIFICATEKEYFILEPASSWORD = "tlscertificatekeyfilepassword";
    }




    static if(!is(typeof(MONGOC_URI_TLSCERTIFICATEKEYFILE))) {
        enum MONGOC_URI_TLSCERTIFICATEKEYFILE = "tlscertificatekeyfile";
    }




    static if(!is(typeof(MONGOC_URI_TLS))) {
        enum MONGOC_URI_TLS = "tls";
    }




    static if(!is(typeof(MONGOC_URI_SOCKETTIMEOUTMS))) {
        enum MONGOC_URI_SOCKETTIMEOUTMS = "sockettimeoutms";
    }




    static if(!is(typeof(MONGOC_URI_SOCKETCHECKINTERVALMS))) {
        enum MONGOC_URI_SOCKETCHECKINTERVALMS = "socketcheckintervalms";
    }




    static if(!is(typeof(MONGOC_URI_SLAVEOK))) {
        enum MONGOC_URI_SLAVEOK = "slaveok";
    }




    static if(!is(typeof(MONGOC_URI_SERVERSELECTIONTRYONCE))) {
        enum MONGOC_URI_SERVERSELECTIONTRYONCE = "serverselectiontryonce";
    }




    static if(!is(typeof(MONGOC_URI_SERVERSELECTIONTIMEOUTMS))) {
        enum MONGOC_URI_SERVERSELECTIONTIMEOUTMS = "serverselectiontimeoutms";
    }




    static if(!is(typeof(MONGOC_URI_SAFE))) {
        enum MONGOC_URI_SAFE = "safe";
    }




    static if(!is(typeof(MONGOC_URI_RETRYWRITES))) {
        enum MONGOC_URI_RETRYWRITES = "retrywrites";
    }




    static if(!is(typeof(MONGOC_URI_RETRYREADS))) {
        enum MONGOC_URI_RETRYREADS = "retryreads";
    }




    static if(!is(typeof(MONGOC_URI_REPLICASET))) {
        enum MONGOC_URI_REPLICASET = "replicaset";
    }




    static if(!is(typeof(MONGOC_URI_READPREFERENCETAGS))) {
        enum MONGOC_URI_READPREFERENCETAGS = "readpreferencetags";
    }




    static if(!is(typeof(MONGOC_URI_READPREFERENCE))) {
        enum MONGOC_URI_READPREFERENCE = "readpreference";
    }




    static if(!is(typeof(MONGOC_URI_READCONCERNLEVEL))) {
        enum MONGOC_URI_READCONCERNLEVEL = "readconcernlevel";
    }




    static if(!is(typeof(MONGOC_URI_MINPOOLSIZE))) {
        enum MONGOC_URI_MINPOOLSIZE = "minpoolsize";
    }




    static if(!is(typeof(MONGOC_URI_MAXSTALENESSSECONDS))) {
        enum MONGOC_URI_MAXSTALENESSSECONDS = "maxstalenessseconds";
    }




    static if(!is(typeof(MONGOC_URI_MAXPOOLSIZE))) {
        enum MONGOC_URI_MAXPOOLSIZE = "maxpoolsize";
    }




    static if(!is(typeof(MONGOC_URI_MAXIDLETIMEMS))) {
        enum MONGOC_URI_MAXIDLETIMEMS = "maxidletimems";
    }




    static if(!is(typeof(MONGOC_URI_LOCALTHRESHOLDMS))) {
        enum MONGOC_URI_LOCALTHRESHOLDMS = "localthresholdms";
    }




    static if(!is(typeof(MONGOC_URI_JOURNAL))) {
        enum MONGOC_URI_JOURNAL = "journal";
    }




    static if(!is(typeof(MONGOC_URI_HEARTBEATFREQUENCYMS))) {
        enum MONGOC_URI_HEARTBEATFREQUENCYMS = "heartbeatfrequencyms";
    }




    static if(!is(typeof(MONGOC_URI_GSSAPISERVICENAME))) {
        enum MONGOC_URI_GSSAPISERVICENAME = "gssapiservicename";
    }




    static if(!is(typeof(MONGOC_URI_COMPRESSORS))) {
        enum MONGOC_URI_COMPRESSORS = "compressors";
    }




    static if(!is(typeof(MONGOC_URI_CONNECTTIMEOUTMS))) {
        enum MONGOC_URI_CONNECTTIMEOUTMS = "connecttimeoutms";
    }




    static if(!is(typeof(MONGOC_URI_CANONICALIZEHOSTNAME))) {
        enum MONGOC_URI_CANONICALIZEHOSTNAME = "canonicalizehostname";
    }




    static if(!is(typeof(MONGOC_URI_AUTHSOURCE))) {
        enum MONGOC_URI_AUTHSOURCE = "authsource";
    }




    static if(!is(typeof(MONGOC_URI_AUTHMECHANISMPROPERTIES))) {
        enum MONGOC_URI_AUTHMECHANISMPROPERTIES = "authmechanismproperties";
    }




    static if(!is(typeof(MONGOC_URI_AUTHMECHANISM))) {
        enum MONGOC_URI_AUTHMECHANISM = "authmechanism";
    }




    static if(!is(typeof(MONGOC_URI_APPNAME))) {
        enum MONGOC_URI_APPNAME = "appname";
    }




    static if(!is(typeof(MONGOC_DEFAULT_PORT))) {
        enum MONGOC_DEFAULT_PORT = 27017;
    }
    static if(!is(typeof(MONGOC_SMALLEST_MAX_STALENESS_SECONDS))) {
        enum MONGOC_SMALLEST_MAX_STALENESS_SECONDS = 90;
    }
    static if(!is(typeof(MONGOC_READ_CONCERN_LEVEL_SNAPSHOT))) {
        enum MONGOC_READ_CONCERN_LEVEL_SNAPSHOT = "snapshot";
    }




    static if(!is(typeof(MONGOC_READ_CONCERN_LEVEL_LINEARIZABLE))) {
        enum MONGOC_READ_CONCERN_LEVEL_LINEARIZABLE = "linearizable";
    }




    static if(!is(typeof(MONGOC_READ_CONCERN_LEVEL_MAJORITY))) {
        enum MONGOC_READ_CONCERN_LEVEL_MAJORITY = "majority";
    }




    static if(!is(typeof(_MKNOD_VER))) {
        enum _MKNOD_VER = 0;
    }




    static if(!is(typeof(MONGOC_READ_CONCERN_LEVEL_LOCAL))) {
        enum MONGOC_READ_CONCERN_LEVEL_LOCAL = "local";
    }




    static if(!is(typeof(MONGOC_READ_CONCERN_LEVEL_AVAILABLE))) {
        enum MONGOC_READ_CONCERN_LEVEL_AVAILABLE = "available";
    }
    static if(!is(typeof(MONGOC_LOG_DOMAIN))) {
        enum MONGOC_LOG_DOMAIN = "mongoc";
    }
    static if(!is(typeof(_SYS_TIME_H))) {
        enum _SYS_TIME_H = 1;
    }
    static if(!is(typeof(MONGOC_HANDSHAKE_APPNAME_MAX))) {
        enum MONGOC_HANDSHAKE_APPNAME_MAX = 128;
    }
    static if(!is(typeof(MONGOC_ERROR_API_VERSION_2))) {
        enum MONGOC_ERROR_API_VERSION_2 = 2;
    }




    static if(!is(typeof(MONGOC_ERROR_API_VERSION_LEGACY))) {
        enum MONGOC_ERROR_API_VERSION_LEGACY = 1;
    }
    static if(!is(typeof(MONGOC_NAMESPACE_MAX))) {
        enum MONGOC_NAMESPACE_MAX = 128;
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
    static if(!is(typeof(_SYS_UIO_H))) {
        enum _SYS_UIO_H = 1;
    }
    static if(!is(typeof(_SYS_UN_H))) {
        enum _SYS_UN_H = 1;
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
    static if(!is(typeof(MONGOC_VERSION_S))) {
        enum MONGOC_VERSION_S = "1.11.1-pre";
    }
    static if(!is(typeof(MONGOC_ENABLE_ICU))) {
        enum MONGOC_ENABLE_ICU = 1;
    }




    static if(!is(typeof(MONGOC_TRACE))) {
        enum MONGOC_TRACE = 0;
    }




    static if(!is(typeof(MONGOC_HAVE_SCHED_GETCPU))) {
        enum MONGOC_HAVE_SCHED_GETCPU = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_RDTSCP))) {
        enum MONGOC_ENABLE_RDTSCP = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_SHM_COUNTERS))) {
        enum MONGOC_ENABLE_SHM_COUNTERS = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_COMPRESSION_ZSTD))) {
        enum MONGOC_ENABLE_COMPRESSION_ZSTD = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_COMPRESSION_ZLIB))) {
        enum MONGOC_ENABLE_COMPRESSION_ZLIB = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_COMPRESSION_SNAPPY))) {
        enum MONGOC_ENABLE_COMPRESSION_SNAPPY = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_COMPRESSION))) {
        enum MONGOC_ENABLE_COMPRESSION = 1;
    }
    static if(!is(typeof(MONGOC_HAVE_RES_SEARCH))) {
        enum MONGOC_HAVE_RES_SEARCH = 0;
    }




    static if(!is(typeof(MONGOC_HAVE_RES_NCLOSE))) {
        enum MONGOC_HAVE_RES_NCLOSE = 1;
    }




    static if(!is(typeof(MONGOC_HAVE_RES_NDESTROY))) {
        enum MONGOC_HAVE_RES_NDESTROY = 0;
    }




    static if(!is(typeof(MONGOC_HAVE_RES_NSEARCH))) {
        enum MONGOC_HAVE_RES_NSEARCH = 1;
    }




    static if(!is(typeof(MONGOC_HAVE_DNSAPI))) {
        enum MONGOC_HAVE_DNSAPI = 0;
    }




    static if(!is(typeof(MONGOC_HAVE_SOCKLEN))) {
        enum MONGOC_HAVE_SOCKLEN = 1;
    }




    static if(!is(typeof(MONGOC_NO_AUTOMATIC_GLOBALS))) {
        enum MONGOC_NO_AUTOMATIC_GLOBALS = 0;
    }




    static if(!is(typeof(MONGOC_HAVE_SASL_CLIENT_DONE))) {
        enum MONGOC_HAVE_SASL_CLIENT_DONE = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_SASL_SSPI))) {
        enum MONGOC_ENABLE_SASL_SSPI = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_SASL_CYRUS))) {
        enum MONGOC_ENABLE_SASL_CYRUS = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_SASL))) {
        enum MONGOC_ENABLE_SASL = 1;
    }




    static if(!is(typeof(MONGOC_HAVE_ASN1_STRING_GET0_DATA))) {
        enum MONGOC_HAVE_ASN1_STRING_GET0_DATA = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_CRYPTO_SYSTEM_PROFILE))) {
        enum MONGOC_ENABLE_CRYPTO_SYSTEM_PROFILE = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_CRYPTO))) {
        enum MONGOC_ENABLE_CRYPTO = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_SSL))) {
        enum MONGOC_ENABLE_SSL = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_CRYPTO_LIBCRYPTO))) {
        enum MONGOC_ENABLE_CRYPTO_LIBCRYPTO = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_SSL_OPENSSL))) {
        enum MONGOC_ENABLE_SSL_OPENSSL = 1;
    }




    static if(!is(typeof(MONGOC_ENABLE_SSL_LIBRESSL))) {
        enum MONGOC_ENABLE_SSL_LIBRESSL = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_CRYPTO_COMMON_CRYPTO))) {
        enum MONGOC_ENABLE_CRYPTO_COMMON_CRYPTO = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_SSL_SECURE_TRANSPORT))) {
        enum MONGOC_ENABLE_SSL_SECURE_TRANSPORT = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_CRYPTO_CNG))) {
        enum MONGOC_ENABLE_CRYPTO_CNG = 0;
    }




    static if(!is(typeof(MONGOC_ENABLE_SSL_SECURE_CHANNEL))) {
        enum MONGOC_ENABLE_SSL_SECURE_CHANNEL = 0;
    }




    static if(!is(typeof(MONGOC_CC))) {
        enum MONGOC_CC = "/usr/bin/cc";
    }




    static if(!is(typeof(MONGOC_USER_SET_LDFLAGS))) {
        enum MONGOC_USER_SET_LDFLAGS = "";
    }




    static if(!is(typeof(MONGOC_USER_SET_CFLAGS))) {
        enum MONGOC_USER_SET_CFLAGS = "";
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
mixin dpp.EnumD!("DeleteFlags",mongoc_delete_flags_t,"MONGOC_DELETE_");
mixin dpp.EnumD!("RemoveFlags",mongoc_remove_flags_t,"MONGOC_REMOVE_");
mixin dpp.EnumD!("InsertFlags",mongoc_insert_flags_t,"MONGOC_INSERT_");
mixin dpp.EnumD!("QueryFlags",mongoc_query_flags_t,"MONGOC_QUERY_");
mixin dpp.EnumD!("ReplyFlags",mongoc_reply_flags_t,"MONGOC_REPLY_");
mixin dpp.EnumD!("UpdateFlags",mongoc_update_flags_t,"MONGOC_UPDATE_");
