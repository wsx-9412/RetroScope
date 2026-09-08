#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <ctype.h>  
/* 过滤配置选项 */
#define ENABLE_DEPTH_INDENT   1     /* 启用调用深度缩进显示 */
#define FILTER_LIBC           1     /* 过滤C标准库函数 */
#define FILTER_LD             1     /* 过滤动态链接器函数 */
#define ENABLE_THREAD_TRACKING 0    /* 启用线程跟踪（会增加开销） */

/* 全局跟踪状态 */
static int call_depth = -1;

/* 需要过滤的库列表（可根据需要扩展） */
static const char *filtered_libraries[] = {
    "libc.so",           /* C标准库 */
    "libpthread.so",     /* 线程库 */
    "libm.so",           /* 数学库 */
    "libdl.so",          /* 动态链接库 */
    "ld-linux",          /* 动态链接器 */
    "libgcc_s.so",       /* GCC运行时库 */
    NULL                 /* 结束标记 */
};

/* 需要过滤的特定函数名前缀 */
static const char *filtered_function_prefixes[] = {
    "__",                /* 内部/系统函数 */
    "_GLOBAL_",          /* 全局构造/析构 */
    "std::",             /* C++标准库（如适用） */
    NULL
};

/* 检查是否为需要过滤的库 */
static int should_filter_library(const char *libname) {
    if (!libname) return 0;
    
    for (int i = 0; filtered_libraries[i] != NULL; i++) {
        if (strstr(libname, filtered_libraries[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* 检查是否为需要过滤的函数名 */
static int should_filter_function(const char *funcname) {
    if (!funcname) return 0;
    
    for (int i = 0; filtered_function_prefixes[i] != NULL; i++) {
        if (strncmp(funcname, filtered_function_prefixes[i], 
                   strlen(filtered_function_prefixes[i])) == 0) {
            return 1;
        }
    }
    return 0;
}

/* 打印缩进（根据调用深度） */
void __attribute__((no_instrument_function))
print_indent(void) {
#if ENABLE_DEPTH_INDENT
    for (int i = 0; i < call_depth; i++) {
        fprintf(stderr, "  │ ");  /* 使用树状结构符号 */
    }
    if (call_depth > 0) {
        fprintf(stderr, "  ├─");
    }
#endif
}

/* 获取可读的函数名（简化C++修饰名） */
const char* __attribute__((no_instrument_function))
demangle_function_name(const char *mangled) {
    if (!mangled) return "unknown";
    
    /* 简单的C++名称简化（可根据需要扩展） */
    if (strncmp(mangled, "_Z", 2) == 0) {
        /* 简单的demangling尝试 */
        for (const char *p = mangled; *p; p++) {
            if (*p == 'N') continue; /* 忽略命名空间标记 */
            if (isalpha((unsigned char)*p)) {
                /* 返回第一个字母开始的位置 */
                return p;
            }
        }
    }
    return mangled;
}

void __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *this_fn, void *call_site) {
    call_depth++;
    
    Dl_info this_info;
    if (dladdr(this_fn, &this_info)) {
        /* 库过滤检查 */
        #if FILTER_LIBC
        if (should_filter_library(this_info.dli_fname)) {
            call_depth--;  /* 立即减少深度，因为不会显示退出 */
            return;
        }
        #endif
        
        /* 函数名过滤检查 */
        if (this_info.dli_sname && 
            should_filter_function(this_info.dli_sname)) {
            call_depth--;
            return;
        }
        
        /* 获取简化的函数名 */
        const char *func_name = demangle_function_name(this_info.dli_sname);
        
        print_indent();
        
        if (func_name) {
            fprintf(stderr, "?→ %s [depth:%d]\n", func_name, call_depth);
            
            /* 记录到日志文件 */
            FILE *log = fopen("function_trace.log", "a");
            if (log) {
                fprintf(log, "%s [depth:%d]\n", func_name, call_depth);
                fclose(log);
            }
        }
    }
}

void __attribute__((no_instrument_function))
__cyg_profile_func_exit(void *this_fn, void *call_site) {
    Dl_info this_info;
    int should_output = 1;
    
    #if FILTER_LIBC
    if (dladdr(this_fn, &this_info)) {
        if (should_filter_library(this_info.dli_fname) ||
            (this_info.dli_sname && should_filter_function(this_info.dli_sname))) {
            should_output = 0;
        }
    }
    #endif
    
    if (should_output) {
        Dl_info this_info;
        if (dladdr(this_fn, &this_info) && this_info.dli_sname) {
            #if FILTER_LIBC
            if (should_filter_library(this_info.dli_fname) ||
                should_filter_function(this_info.dli_sname)) {
                call_depth--;
                return;
            }
            #endif
            
            print_indent();
            const char *func_name = demangle_function_name(this_info.dli_sname);
            fprintf(stderr, "?─ %s [exit]\n", func_name ? func_name : "unknown");
        }
    }
    
    call_depth--;
}

/* 初始化函数（可选） */
void __attribute__((no_instrument_function, constructor))
init_instrumentation(void) {
    fprintf(stderr, "=== 函数调用跟踪开始 ===\n");
    fprintf(stderr, "配置: 深度缩进:%d, 过滤libc:%d\n", 
            ENABLE_DEPTH_INDENT, FILTER_LIBC);
}

/* 清理函数（可选） */
void __attribute__((no_instrument_function, destructor))
cleanup_instrumentation(void) {
    fprintf(stderr, "=== 函数调用跟踪结束 ===\n");
}




