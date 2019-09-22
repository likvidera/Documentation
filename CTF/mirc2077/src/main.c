
#include "main.h"

v0 *js_result = NULL;
int ipc_fds[2] = {0};
int log_fds[2] = {0};

v0 verify_malloc(v0 * p)
{
  if(p == NULL) {
    puts("Malloc failed, contact an Admin if it a reoccuring error");
    exit(0);
  }
}

u32 _read(u8 * buf, u32 len)
{
  return read(0, buf, len);  
}

u32 _write(u8 * buf, u32 len)
{
  return write(1, buf, len);  
}

v0 _write_str(u8 * buf)
{
  _write(buf, strlen(buf));
}

u32 read_int()
{
  u8 choice_buf[40] =  "";
  _read(choice_buf, 40);
  return strtoul(choice_buf, NULL, 0);
}

u32 read_answer()
{
  u8 choice_buf[20] =  "";
  _read(choice_buf, 2);
  if(choice_buf[0] == 'y'){
    return 1;
  }
  return 0;
}

v0 init()
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
}

v0 banner()
{
puts("\n\e[49m  \e[48;5;61m \e[48;5;61m\e[38;5;69m▄▄▄▄▄▄\e[49m\e[38;5;61m▄\e[48;5;61m \e[48;5;61m\e[38;5;62m▄▄\e[48;5;61m\e[38;5;69m▄▄\e[48;5;61m\e[38;5;68m▄\e[49m\e[38;5;61m▄▄▄\e[48;5;61m \e[48;5;61m\e[38;5;62m▄▄▄\e[48;5;61m\e[38;5;68m▄\e[48;5;61m\e[38;5;62m▄\e[49m\e[38;5;61m▄\e[49m      \n\e[0m " \ 
"\e[49m  \e[48;5;61m \e[48;5;62m \e[48;5;69m \e[48;5;111m\e[38;5;69m▄▄▄▄\e[48;5;62m \e[48;5;61m\e[38;5;68m▄\e[48;5;62m\e[38;5;69m▄\e[48;5;69m \e[48;5;111m\e[38;5;69m▄▄▄\e[48;5;69m \e[48;5;61m\e[38;5;62m▄\e[48;5;61m \e[48;5;61m\e[38;5;68m▄\e[48;5;62m\e[38;5;111m▄\e[48;5;69m \e[48;5;111m\e[38;5;69m▄▄\e[48;5;69m  \e[48;5;61m\e[38;5;69m▄\e[49m\e[38;5;61m▄\e[49m    \n\e[0m " \ 
"\e[49m  \e[48;5;61m \e[48;5;62m \e[48;5;69m \e[48;5;69m\e[38;5;68m▄▄▄▄\e[48;5;62m\e[38;5;68m▄\e[48;5;69m \e[48;5;69m\e[38;5;68m▄▄▄▄▄▄▄\e[48;5;68m\e[38;5;69m▄\e[48;5;69m \e[48;5;69m\e[38;5;68m▄▄▄▄▄▄▄\e[48;5;62m \e[49m\e[38;5;24m▄\e[49m   \n\e[0m " \ 
"\e[49m  \e[48;5;61m\e[38;5;24m▄\e[48;5;62m\e[38;5;61m▄\e[48;5;62m       \e[48;5;62m\e[38;5;61m▄▄▄\e[48;5;62m      \e[48;5;62m\e[38;5;61m▄▄▄\e[48;5;62m     \e[48;5;24m\e[38;5;61m▄\e[49m   \n\e[0m " \ 
"\e[49m  \e[48;5;24m \e[48;5;61m \e[48;5;62m\e[38;5;61m▄▄▄▄▄▄\e[48;5;61m\e[38;5;24m▄\e[49m \e[48;5;24m \e[48;5;61m \e[48;5;62m \e[48;5;62m\e[38;5;61m▄▄▄▄\e[48;5;61m\e[38;5;24m▄\e[49m\e[38;5;24m▀\e[48;5;24m \e[48;5;25m\e[38;5;61m▄\e[48;5;62m \e[48;5;62m\e[38;5;61m▄▄▄▄\e[48;5;24m \e[49m   \n\e[0m " \ 
"\e[49m  \e[48;5;24m \e[48;5;25m\e[38;5;24m▄\e[48;5;61m \e[48;5;61m\e[38;5;25m▄▄▄▄▄\e[48;5;24m \e[49m \e[48;5;24m \e[48;5;61m\e[38;5;62m▄\e[48;5;62m\e[38;5;61m▄\e[48;5;61m\e[38;5;25m▄▄▄▄\e[48;5;24m \e[49m \e[48;5;24m \e[48;5;61m \e[48;5;62m\e[38;5;61m▄\e[48;5;61m\e[38;5;25m▄▄▄▄\e[48;5;24m \e[49m   \n\e[0m " \ 
"\e[49m  \e[48;5;24m \e[48;5;24m\e[38;5;18m▄\e[48;5;24m \e[48;5;24m\e[38;5;18m▄▄▄▄▄\e[48;5;24m \e[49m \e[48;5;24m \e[48;5;62m\e[38;5;61m▄\e[48;5;61m \e[48;5;24m\e[38;5;18m▄▄▄▄\e[48;5;24m \e[49m \e[48;5;24m \e[48;5;61m  \e[48;5;24m\e[38;5;18m▄▄▄▄\e[48;5;24m \e[49m   \n\e[0m " \ 
"\e[48;5;124m\e[38;5;160m▄\e[48;5;160m\e[38;5;202m▄▄▄▄▄▄\e[48;5;124m\e[38;5;160m▄\e[48;5;160m \e[48;5;160m\e[38;5;202m▄▄▄▄▄▄▄▄\e[48;5;160m \e[48;5;88m\e[38;5;160m▄\e[48;5;239m\e[38;5;130m▄\e[48;5;130m\e[38;5;178m▄\e[48;5;94m\e[38;5;220m▄\e[48;5;130m\e[38;5;220m▄▄\e[48;5;94m\e[38;5;220m▄\e[48;5;239m\e[38;5;178m▄\e[48;5;238m\e[38;5;136m▄\e[48;5;18m\e[38;5;94m▄\e[48;5;18m\e[38;5;238m▄\e[49m   \n\e[0m " \ 
"\e[48;5;124m \e[48;5;202m\e[38;5;160m▄\e[48;5;208m\e[38;5;202m▄\e[48;5;202m     \e[48;5;124m \e[48;5;208m \e[48;5;208m\e[38;5;202m▄▄▄▄▄▄▄▄▄\e[48;5;130m \e[48;5;221m    \e[48;5;220m\e[38;5;221m▄\e[48;5;220m \e[48;5;214m \e[48;5;172m\e[38;5;214m▄\e[48;5;94m\e[38;5;172m▄\e[49m\e[38;5;130m▄\e[49m  \n\e[0m " \ 
"\e[48;5;124m\e[38;5;88m▄\e[48;5;160m \e[48;5;202m \e[48;5;202m\e[38;5;160m▄▄▄▄▄\e[48;5;124m \e[48;5;208m \e[48;5;202m         \e[48;5;130m \e[48;5;221m \e[48;5;227m \e[48;5;227m\e[38;5;179m▄\e[48;5;221m\e[38;5;179m▄\e[48;5;221m \e[48;5;172m \e[48;5;94m \e[48;5;130m\e[38;5;58m▄\e[48;5;172m  \e[48;5;94m\e[38;5;130m▄\e[49m \n\e[0m " \ 
"\e[48;5;124m \e[48;5;124m\e[38;5;160m▄\e[48;5;88m\e[38;5;202m▄▄▄▄▄▄\e[48;5;88m\e[38;5;124m▄\e[48;5;208m\e[38;5;202m▄\e[48;5;202m         \e[48;5;130m \e[48;5;221m  \e[48;5;94m  \e[48;5;178m\e[38;5;136m▄\e[48;5;178m\e[38;5;220m▄\e[48;5;94m\e[38;5;178m▄\e[48;5;58m\e[38;5;172m▄\e[48;5;172m  \e[48;5;166m\e[38;5;130m▄\e[48;5;94m \n\e[0m " \ 
"\e[48;5;124m\e[38;5;88m▄\e[48;5;160m \e[48;5;208m\e[38;5;202m▄\e[48;5;202m     \e[48;5;124m \e[48;5;202m      \e[48;5;124m \e[48;5;88m\e[38;5;172m▄▄\e[48;5;88m\e[38;5;178m▄\e[48;5;130m\e[38;5;214m▄\e[48;5;220m  \e[48;5;172m\e[38;5;220m▄\e[48;5;94m\e[38;5;220m▄\e[48;5;172m\e[38;5;214m▄\e[48;5;214m \e[48;5;214m\e[38;5;172m▄\e[48;5;172m\e[38;5;130m▄\e[48;5;166m\e[38;5;88m▄\e[48;5;88m \e[48;5;94m \e[49m \n\e[0m " \ 
"\e[48;5;88m \e[48;5;160m \e[48;5;202m      \e[48;5;124m\e[38;5;88m▄\e[48;5;202m \e[48;5;202m\e[38;5;160m▄▄▄\e[48;5;160m  \e[48;5;124m\e[38;5;88m▄\e[48;5;172m\e[38;5;166m▄\e[48;5;172m \e[48;5;178m\e[38;5;172m▄\e[48;5;214m\e[38;5;172m▄▄\e[48;5;214m\e[38;5;166m▄\e[48;5;214m\e[38;5;130m▄▄\e[48;5;172m\e[38;5;124m▄\e[48;5;130m\e[38;5;124m▄\e[48;5;88m\e[38;5;124m▄\e[48;5;124m\e[38;5;166m▄▄\e[48;5;130m\e[38;5;166m▄\e[48;5;94m \e[49m \n\e[0m " \ 
"\e[48;5;88m \e[48;5;160m\e[38;5;124m▄\e[48;5;202m \e[48;5;160m     \e[48;5;88m \e[48;5;202m \e[48;5;160m     \e[48;5;88m \e[48;5;166m\e[38;5;130m▄\e[48;5;172m\e[38;5;166m▄\e[48;5;130m\e[38;5;166m▄\e[48;5;88m\e[38;5;130m▄\e[48;5;124m\e[38;5;166m▄▄▄\e[48;5;166m \e[48;5;166m\e[38;5;202m▄▄▄▄\e[48;5;202m\e[38;5;208m▄\e[48;5;166m\e[38;5;94m▄\e[49m\e[38;5;94m▀\e[49m \n\e[0m " \ 
"\e[48;5;88m \e[48;5;124m \e[48;5;166m \e[48;5;160m     \e[48;5;88m \e[48;5;166m \e[48;5;160m  \e[48;5;160m\e[38;5;124m▄▄▄\e[48;5;88m \e[49m\e[38;5;94m▀\e[48;5;130m\e[38;5;94m▄\e[48;5;130m  \e[48;5;166m\e[38;5;130m▄\e[48;5;208m\e[38;5;130m▄\e[48;5;202m\e[38;5;172m▄▄\e[48;5;208m \e[48;5;208m\e[38;5;172m▄▄\e[48;5;208m\e[38;5;130m▄\e[48;5;136m\e[38;5;94m▄\e[49m\e[38;5;94m▀\e[49m  \n\e[0m " \ 
"\e[49m\e[38;5;52m▀\e[48;5;88m\e[38;5;52m▄\e[48;5;166m\e[38;5;88m▄\e[48;5;124m\e[38;5;88m▄▄▄▄▄\e[48;5;88m\e[38;5;52m▄\e[48;5;166m\e[38;5;88m▄\e[48;5;124m\e[38;5;88m▄▄▄▄▄\e[48;5;88m \e[49m  \e[49m\e[38;5;94m▀▀\e[48;5;130m\e[38;5;58m▄▄▄▄▄▄\e[49m\e[38;5;94m▀\e[49m\e[38;5;58m▀\e[49m    \n\e[0m "); 

puts("[droidpwn] !mirc2077-01.pwn.beer *** Looking up your hostname...\n" \
"[droidpwn] !mirc2077-01.pwn.beer *** Checking Ident\n" \
"[droidpwn] !mirc2077-01.pwn.beer *** Got Ident response\n" \
"[droidpwn] !mirc2077-01.pwn.beer *** Spoofing your IP\n" \
"-!- you [~you@mullvad.net] has joined #pwners-delight\n" \
"-!- Topic for #pwners-delight: Trading warez and 0-days, no skidz or humans!\n" \
"-!- Topic set by likvidera [] [Mon Jun 25 17:46:41 2019]\n" \
"[Users #pwners-delight]\n" \
"[@likvidera   ]");
}

static void my_fatal(void *udata, const char *msg) {
  (void) udata;
  fprintf(stderr, "*** FATAL ERROR: %s\n", (msg ? msg : "no message"));
  fflush(stderr);
  exit(0);
}

/* https://www.w0lfzhang.com/2017/11/29/Linux-Seccomp-Learning/ */
u32 sandbox(void)
{
  int rc = -1;
  scmp_filter_ctx ctx = {0};
  ctx = seccomp_init(SCMP_ACT_KILL);
  //ctx = seccomp_init(SCMP_ACT_TRAP); // DEBUG PURPOSES 
  if(ctx == NULL)
    return -1;

  do 
  {
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);  /* harden this */
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);  /* harden this */
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);  /* harden this */
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0); /* harden this */
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    if(rc < 0)
      break;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    if(rc < 0)
      break;      
    return seccomp_load(ctx);
  } while(1);

  seccomp_release(ctx);
  return -1;
}

int set_blocking(int fd, int blocking) {
    /* Save the current flags */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return 0;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags) != -1;
}

static u32 event_fd = 0;
static struct epoll_event event_fds[2], events[MAX_EVENTS];
static u8 data[MAX_DATA+1] = "";

v0 ipc_create(v0)
{
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, ipc_fds) < 0) {
    _write_str("Failed to create IPC - contact Admin");
    exit(1);
  }
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, log_fds) < 0) {
    _write_str("Failed to create IPC - contact Admin");
    exit(1);
  }

  event_fd = epoll_create(1);
  if(!event_fd) {
    _write_str("Failed to create IPC 2 - contact Admin");
    exit(1);
  }

  event_fds[0].events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLPRI;
  event_fds[0].data.fd = ipc_fds[0];
  event_fds[1].events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLPRI;
  event_fds[1].data.fd = log_fds[0];

  if(epoll_ctl(event_fd, EPOLL_CTL_ADD, ipc_fds[0], &event_fds[0]) == -1) {
    _write_str("Failed to create IPC 3 - contact Admin");
    exit(1);
  }

  if(epoll_ctl(event_fd, EPOLL_CTL_ADD, log_fds[0], &event_fds[1]) == -1) {
    _write_str("Failed to create IPC 3 - contact Admin");
    exit(1);
  }
}

u64 ipc_cache_create_data(u64 id, u64 size)
{
  struct cache_head *c = (struct cache_head*)ipc_cache_arr[id];
  if(c == NULL)
    return IPC_ERROR;
  if(c->cache_ptr->data_ptr == NULL) {
    if(size <= 0 || size > 512)
      return 0;
    c->cache_ptr->data_ptr = malloc(size);
  }
  return IPC_SUCCESS;
}

u64 ipc_cache_set_data(u64 id)
{
  struct cache_head *c = (struct cache_head*)ipc_cache_arr[id];
  if(c == NULL)
    return IPC_ERROR;
  if(c->cache_ptr != NULL) {
    if(c->cache_ptr->data_ptr != NULL) {
      return IPC_SUCCESS;
    }
  }
  return IPC_ERROR;
}

u64 ipc_cache_get_data(u64 id)
{
  struct cache_head *c = (struct cache_head*)ipc_cache_arr[id];
  if(c == NULL)
    return IPC_ERROR;
  if(c->cache_ptr != NULL) {
    if(c->cache_ptr->data_ptr != NULL) {
      return IPC_SUCCESS;
    }
  }
  return IPC_ERROR;
}

u64 ipc_cache_create(u64 id, u64 size)
{
  struct cache_head *old = NULL;

  if(ipc_cache_num >= MAX_CACHE){
    printf("Out of cache-memory!");
    return IPC_ERROR;
  }

  if(id) {
    old = (struct cache_head*)ipc_cache_arr[id];
    if(old == NULL)
      return IPC_ERROR;
  }

  struct cache_head *c = malloc(sizeof(struct cache_head));
  if(c == NULL)
    return IPC_ERROR;

  c->id = ipc_cache_num;
  if(!id) {
    c->cache_ptr = malloc(sizeof(struct cache));
    if(c->cache_ptr == NULL) {
      free(c);
      return IPC_ERROR;
    }

    c->cache_ptr->refcount = 1;
    c->cache_ptr->size = size;
    c->cache_ptr->data_ptr = NULL;
  } else {
    c->cache_ptr = old->cache_ptr;
    c->cache_ptr->refcount++;
  }

  ipc_cache_arr[ipc_cache_num] = c;
  ipc_cache_num++;
  return c->id;
}

u64 ipc_cache_dup(u64 id)
{
  u64 new_id = ipc_cache_create(id, 0);
  if(new_id == IPC_ERROR)
    return IPC_ERROR;
  return new_id;
}

u32 ipc_cache_close(u64 id)
{
  struct cache_head *c = (struct cache_head*)ipc_cache_arr[id];
  if(c == NULL)
    return IPC_ERROR;

  if(c->cache_ptr != NULL) {
    c->cache_ptr->refcount--;
    if(c->cache_ptr->refcount <= 0) {
      if(c->cache_ptr->data_ptr != NULL) {
        free(c->cache_ptr->data_ptr);
        c->cache_ptr->data_ptr = NULL;        
      }
      free(c->cache_ptr);
      c->cache_ptr = NULL;
      free(c);
      ipc_cache_arr[id] =  NULL;
    }
  }
  return IPC_SUCCESS;
}

u32 ipc_handler(u8 * data)
{
  struct ipc_msg *msg = (struct ipc_msg*)data;
  u8 flag_data[150] = "";

  if(msg == NULL)
    return 1337;

  if(memcmp(&msg->magic, "IRC_IPC\0", 8) != 0){
    if(msg->debug)
      _write_str("<IRC-IPC-DBG> Invalid IPC-header\n");
    return 0;
  }

  switch(msg->id) 
  {
    case IPC_JS_SUCCESS:
      if(msg->debug)
        _write_str("<IRC-IPC-DBG> JS renderer returned success!\n");
      return 1337;
      break;

    case IPC_JS_FAILURE:
      if(msg->debug)
        _write_str("<IRC-IPC-DBG> JS renderer returned failure\n");
      return 1337;
      break;
    
    case IPC_CACHE_CREATE:
      msg->result = ipc_cache_create(0, msg->arg0);
      if(msg->result != IPC_ERROR) {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Created cache with id %ld and size %ld \n", msg->result, msg->arg0);
      } else {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Failed to create cache\n");        
      }
      write(ipc_fds[0], msg, sizeof(struct ipc_msg));
      break;
    
    case IPC_CACHE_DUP:
      if(msg->arg0 < 1 || msg->arg0 >= MAX_CACHE) {
        msg->result = IPC_ERROR;
        write(ipc_fds[0], msg, sizeof(struct ipc_msg));
        return 0;
      }
        
      msg->result = ipc_cache_dup(msg->arg0);
      if(msg->result != IPC_ERROR) {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Duped cache with id %ld to %ld \n", msg->arg0, msg->result);
      } else {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Failed to dup cache\n");        
      }
      write(ipc_fds[0], msg, sizeof(struct ipc_msg));
      break;

    case IPC_CACHE_CLOSE:
      if(msg->arg0 < 1 || msg->arg0 >= MAX_CACHE) {
        msg->result = IPC_ERROR;
        write(ipc_fds[0], msg, sizeof(struct ipc_msg));
        return 0;
      }
        
      msg->result = ipc_cache_close(msg->arg0);
      if(msg->result != IPC_ERROR) {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Closed cache with id %ld\n", msg->arg0);
      } else {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Failed to close cache\n");        
      }
      write(ipc_fds[0], msg, sizeof(struct ipc_msg));
      break;

    case IPC_CACHE_CREATE_DATA:
      if(msg->arg0 < 1 || msg->arg0 >= MAX_CACHE) {
        msg->result = IPC_ERROR;
        write(ipc_fds[0], msg, sizeof(struct ipc_msg));
        return 0;
      }
        
      msg->result = ipc_cache_create_data(msg->arg0, msg->arg1);
      if(msg->result != IPC_ERROR) {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Create cache data for id %ld\n", msg->arg0);
      } else {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Failed to create cache data\n");        
      }
      write(ipc_fds[0], msg, sizeof(struct ipc_msg));
      break;

    case IPC_CACHE_SET_DATA:
      if(msg->arg0 < 1 || msg->arg0 >= MAX_CACHE) {
        msg->result = IPC_ERROR;
        write(ipc_fds[0], msg, sizeof(struct ipc_msg));
        return 0;
      }
        
      msg->result = ipc_cache_set_data(msg->arg0);
      if(msg->result != IPC_ERROR) {
          printf("<IRC-IPC-DBG> Recieved SET cache data request for id %ld\n", msg->arg0);
      } else {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Failed to set cache data\n");        
      }
      write(ipc_fds[0], msg, sizeof(struct ipc_msg));
      if(msg->result != IPC_ERROR){
        struct cache_head *c = (struct cache_head*)ipc_cache_arr[msg->arg0];
        if(c != NULL) {
          read(ipc_fds[0], c->cache_ptr->data_ptr, c->cache_ptr->size);
          printf("<IRC-IPC-DBG> SET cache data for id: %ld \n", c->id);   
        }
      }
      break;

    case IPC_CACHE_GET_DATA:
      if(msg->arg0 < 1 || msg->arg0 >= MAX_CACHE) {
        msg->result = IPC_ERROR;
        write(ipc_fds[0], msg, sizeof(struct ipc_msg));
        return 0;
      }
        
      msg->result = ipc_cache_get_data(msg->arg0);
      if(msg->result != IPC_ERROR) {
          printf("<IRC-IPC-DBG> Recieved GET cache data request for id %ld\n", msg->arg0);
      } else {
        if(msg->debug)
          printf("<IRC-IPC-DBG> Failed to set cache data\n");        
      }
      write(ipc_fds[0], msg, sizeof(struct ipc_msg));
      if(msg->result != IPC_ERROR){
        struct cache_head *c = (struct cache_head*)ipc_cache_arr[msg->arg0];
        if(c != NULL) {
          write(ipc_fds[0], c->cache_ptr->data_ptr, c->cache_ptr->size);
          printf("<IRC-IPC-DBG> GET cache data for id: %ld \n", c->id);   
        }
      }
      break;

    case IPC_REQUEST_FLAG:
      if(msg->debug)
        _write_str("<IRC-IPC-DBG> FLAG request :-)\n");

      int fd = open("./flag", O_RDONLY);
      if(fd >= 0) {
        int res =  read(fd, flag_data, 100);
        if(res > 0)
          write(ipc_fds[0], flag_data, res);
        else
          write(ipc_fds[0], ":( - contact Admin", 18);
        close(fd);
      }
      break;

    default:
      break;
  }
  return 0;
}

u32 ipc_loop(u32 pid) 
{
  u32 event_num = 0;
  u32 res = 0;
  
  for(;;) 
  {
    //printf("waiting ..\n");
    event_num = epoll_wait(event_fd, events, MAX_EVENTS, 30000);
    if(event_num == -1) {
      printf("<IRC-IPC-DBG> IPC disconnected\n");
      return 0;
    }

    if((res = kill(pid, 0)) == -1) {
      printf("<IRC-IPC-DBG> I/O error - killing\n");
      return 0;
    }

    for(int i = 0; i < event_num; i++) 
    {
      if((events[i].events & EPOLLERR) || 
        (events[i].events & EPOLLHUP) ||
        (events[i].events & EPOLLPRI &&
        !events[i].events & EPOLLIN)){
        return 0;
      }

      if(events[i].events & EPOLLIN)
      {
        if(events[i].data.fd == log_fds[0])
        {
          res = read(log_fds[0], data, MAX_DATA);
          if(res > 0) {
            printf("%s", data);
            memset(data, 0, MAX_DATA);
          }
          else
            return 0;
        }
        if(events[i].data.fd == ipc_fds[0])
        {
          res = read(ipc_fds[0], data, MAX_DATA);
          if(res > 0) {
            res = ipc_handler(data);
            memset(data, 0, MAX_DATA);
            if(res == 1337)
              return res;
          }
          else
            return 0;
        }
      }
    }
  }
  return 1;
}

v0 ipc_cli_msg_send(u32 status) 
{
  struct ipc_msg msg = {0};
  memcpy(msg.magic, "IRC_IPC\0", 8);
  msg.id = status;
  msg.debug = 1;
  write(ipc_fds[1], &msg, sizeof(struct ipc_msg));
}

u32 run_js(u8 * script)
{
  void *my_udata = (void *) 0xdeadbeef;
  duk_context *ctx = duk_create_heap(NULL, NULL, NULL, my_udata, my_fatal);
  if(ctx)
  {
    dprintf(log_fds[1], "<IRC-LOG> %s", "#### ANALYSING JAVASCRIPT ####\n");
    duk_console_init(ctx, 0);
    if(duk_peval_lstring(ctx, script, strlen(script)) != 0)
    {
      dprintf(log_fds[1], "<IRC-LOG> Analysis failed, exiting! %s\n", duk_safe_to_string(ctx, -1));
      return IPC_JS_FAILURE;
    } 
    dprintf(log_fds[1], "<IRC-LOG> %s", "#### ANALYSIS DONE - SEEMS OK! ####\n");
    duk_destroy_heap(ctx);
  }
  return IPC_JS_SUCCESS;
}

v0 exec_js_renderer(u8 * script)
{
  u32 status = 0;
  u32 js_res = 0;
  
  /* init IPC */
  ipc_create();
  /* create js render process */
  signal(SIGCHLD, SIG_IGN); 
  u32 pid = fork();
  if(pid == -1) {
    _write_str("Failed to create js_render process - contact Admin\n");
    exit(1);
  }

  /* js render process */
  if(pid == 0) 
  {
    /* close all handles except IPC */
    for(int i = 0; i < 1000; i++) {
      if(i != ipc_fds[1] && i != log_fds[1])
        close(i);
    }

    /* init sandbox and run ipc_loop */
    if(sandbox() == -1) {
      dprintf(log_fds[1], "<IRC-LOG> %s", "Failed to enable SANDBOX for js_render process - contact Admin\n");
      exit(1);
    }
    js_res = run_js(script);
    ipc_cli_msg_send(js_res);
    
    close(ipc_fds[1]);
    close(log_fds[1]);
    exit(0);
  }

  ipc_loop(pid);
  waitpid(pid, &status, 0);
}

u32 is_js(u8 * url)
{
  if(strlen(url) > 4 && !strcmp(url + strlen(url) - 3, ".js"))
    return 1;
  return 0;
}

u32 is_html(u8 * url)
{
  if(strlen(url) > 6 && !strcmp(url + strlen(url) - 5, ".html"))
    return 1;
  return 0;
}

size_t write_cb(void *ptr, size_t size, size_t nmemb, struct url_data *data) {
    size_t index = data->size;
    size_t n = (size * nmemb);
    char* tmp = NULL;

    data->size += (size * nmemb);
#ifdef DEBUG
    fprintf(stderr, "data at %p size=%ld nmemb=%ld\n", ptr, size, nmemb);
#endif
    tmp = realloc(data->data, data->size + 1); /* +1 for '\0' */
    if(tmp) {
        data->data = tmp;
    } else {
        if(data->data) {
            free(data->data);
        }
        fprintf(stderr, "Failed to allocate memory.\n");
        exit(0);
    }

    memcpy((data->data + index), ptr, n);
    data->data[data->size] = '\0';
    return size * nmemb;
}

v0 visit_url(u8 * url)
{
  CURL *curl = NULL;
  CURLcode res = 0;

  if(!is_js(url) && !is_html(url))
  {
    _write_str("<@likvidera> Yeah, I'm not clicking that\n");
    return;
  }

  curl = curl_easy_init();
  if(curl)
  {
    struct url_data data;
    data.size = 0;
    data.data = malloc(MAX_DATA_SIZE); 
    verify_malloc(data.data);
    memset(data.data, 0, MAX_DATA_SIZE);

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, MAX_DATA_SIZE);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    res = curl_easy_perform(curl);
    if(res == CURLE_OK)
    {
      if(is_js(url))
      {
        exec_js_renderer(data.data);
        _write_str("<@likvidera> lame, come back when you got something worth my time!\n");
        exit(0);
      }
      else if(is_html)
      {
        _write_str("<@likvidera> super-lame, stop wasting my time!\n");
        exit(0);
      }
    }

    if(data.data) {
      free(data.data);
      data.data = 0;
    }
    curl_easy_cleanup(curl);
  }
}

v0 irc_load()
{
  banner();
  sleep(1);
  _write_str("<@likvidera> sup?\n");
}

v0 next_command(u8 * cmd, u32 size)
{
  u32 len = 0;
  _write_str("<you> ");
  _read(cmd, size);
  len = strlen(cmd);
  if(len > 1) {
    if(cmd[len-1] == '\n')
      cmd[len-1] = '\0';
  }
}

v0 run_irc_client()
{
  u8 cmd[MAX_CMD_SIZE] = "";
  int found = 0;
  irc_load();

  while(1)
  {
    next_command(cmd, MAX_CMD_SIZE);
    if(strstr(cmd, "hello") != 0){
      found = 1;
      _write_str("<@likvidera> Greetings! I am model PWN-1337 ... or just call me likvidera\n");
    }
    
    if(strstr(cmd, "warez") != 0) {
      found = 1;
      _write_str("<@likvidera> Yeah dude, I got more warez than the Piratebay\n");
    }

    if(strstr(cmd, "0-day") != 0) {
      found = 1;
      _write_str("<@likvidera> Are you selling or buying?\n");
    }

    if(memcmp(cmd, "http://", 7) == 0) {
      found = 1;
      _write_str("<@likvidera> This better not be a rick-roll ...\n");
      visit_url(cmd);
    }

    if(strstr(cmd, "bye") != 0) {
      found = 1;
      _write_str("<@likvidera> Leaving already? How about some IRC-trivia?\n");
      _write_str("-!- you [~you@mullvad.net] has quit [Quit: Leaving]\n");
      exit(0);
    }

    if(!found) {
      _write_str("<@likvidera> ...\n");
    }

    memset(cmd, 0, MAX_CMD_SIZE);
    found = 0;
  }
}

int main(int argc, char **argv)
{
  init();
  run_irc_client();
	return 0;
}