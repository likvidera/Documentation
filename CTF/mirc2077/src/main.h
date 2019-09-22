#if !defined(MAIN_H_INCLUDED)
#define MAIN_H_INCLUDED

#define _DEFAULT_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "curl/include/curl/curl.h"
#include "duktape/src-custom/duktape.h"
#include "duktape/extras/console/duk_console.h"

#define RESULT_PAGE_MAX 4096 * 3
#define MAX_DATA_SIZE 4096 * 8
#define MAX_CMD_SIZE 250

typedef void v0;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define IPC_JS_SUCCESS      0xac1d0001
#define IPC_JS_FAILURE      0xac1d0002
#define IPC_CACHE_CREATE    0xac1d0003
#define IPC_CACHE_DUP       0xac1d0004
#define IPC_CACHE_CLOSE     0xac1d0005
#define IPC_CACHE_CREATE_DATA 0xac1d0006
#define IPC_CACHE_SET_DATA  0xac1d0007
#define IPC_CACHE_GET_DATA  0xac1d0008
#define IPC_REQUEST_FLAG    0xac1d1337

#define IPC_ERROR           0x0
#define IPC_SUCCESS         0x1

#define MAX_EVENTS 100
#define MAX_DATA 1000
#define MAX_CACHE 2048

static u32 ipc_cache_num = 1;
static v0 *ipc_cache_arr[MAX_CACHE] = {0};

struct cache {
  v0 *data_ptr;
  u8 refcount;
  u64 size;
};

struct cache_head {
  u64 id;
  struct cache *cache_ptr;
};

struct ipc_msg {
 u8 magic[8];
 u64 id;
 u64 debug;
 u64 status;
 u64 result;
 u64 arg0;
 u64 arg1;
};

struct url_data {
  size_t size;
  u8 *data;
};

#endif