#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "LightHook.h"
#include "pmparser.h"
#include <sys/capability.h>
#include <sys/prctl.h>

static int g_Enable = 0;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////
/////// Part1: Keep CAP_SYS_CHROOT capability between setuid
///////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int g_trigger = 0; // become 1 when we do_setusercontext -> permanently_set_uid
__attribute__((visibility("default"))) void endgrent() { // do_setusercontext calls endgrent()
  void (*ori_endgrent)() = dlsym(RTLD_NEXT, "endgrent");
  ori_endgrent();
  g_trigger = 1;
}

__attribute__((visibility("default"))) int setresuid(uid_t ruid, uid_t euid, uid_t suid) { // permanently_set_uid calls setresuid
  int result = 0;
  int (*ori_setresuid)(uid_t ruid, uid_t euid, uid_t suid) = dlsym(RTLD_NEXT, "setresuid");
  if (g_Enable && g_trigger) {
    g_trigger = 0;
    // FILE *f = fopen("/tmp/chrootssh-setuid", "w");
    // fprintf(f, "uid %d -> %d %d %d\n", getuid(), ruid, euid, suid);
    // fflush(f);
    
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    result = ori_setresuid(ruid, euid, suid);

    cap_value_t cap_values[] = {CAP_SYS_CHROOT};
    cap_t caps = cap_get_proc();
    cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_values, CAP_SET);
    cap_set_flag(caps, CAP_PERMITTED, 1, cap_values, CAP_SET);
    int capret = cap_set_proc(caps);
    // FILE *loggingfd = fopen("/tmp/chrootssh-cap", "w");
    // if (!!capret) {
    //   fprintf(loggingfd, "failed to cap_set_proc: %d\n", errno);
    // } else {
    //   fprintf(loggingfd, "success to cap_set_proc\n");
    // }
    cap_free(caps);
  } else {
    result = ori_setresuid(ruid, euid, suid);
  }
  return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////
/////// Part1: Find and hook sftp_server_main to execute chroot() beforehand
///////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define SSHD_PATHNAME "/usr/sbin/sshd"

static const char* get_self_exe_name(int full) {
  static char buffer[4096] = "";
  readlink("/proc/self/exe", buffer, 4096);
  if (full) {
    return buffer;
  }
  char* ptr = &buffer[strlen(buffer)];
  while (*ptr != '/') --ptr;
  return (ptr + 1);
}

static uintptr_t sshd_addr = 0;
static uintptr_t sshd_size = 0;

static int find_sshd_exec() {
  // fprintf(stderr, "pid: %d\n", getpid());
  procmaps_iterator *maps = pmparser_parse(-1);
  procmaps_struct* maps_tmp = NULL;
  while (maps_tmp = pmparser_next(maps)) {
    // fprintf(stderr, "path: %s\n", maps_tmp->pathname);
    if (!strcmp(maps_tmp->pathname, SSHD_PATHNAME)) {
      if (!sshd_addr) {
        sshd_addr = (uintptr_t)maps_tmp->addr_start;
      }
      sshd_size = (uintptr_t)maps_tmp->addr_end - sshd_addr;
    } else if (sshd_addr) { // have already found
      break;
    }
  }
  pmparser_free(maps);
  if (!sshd_addr || !sshd_size) {
    return 1;
  }
  return 0;
}

static unsigned char SERVER_MAIN_ARG_PAT[] = "d:f:l:P:p:Q:u:cehR";
static uintptr_t lea_arg_ptr = 0;
static int find_sftp_server_main() {
  unsigned char *argPtr = memmem((void *)sshd_addr, sshd_size, SERVER_MAIN_ARG_PAT, sizeof(SERVER_MAIN_ARG_PAT) - 1);
  fprintf(stderr, "argPtr %p\n", argPtr);
  for (uintptr_t _ea = sshd_addr; _ea < sshd_addr + sshd_size; _ea++) {
    unsigned char *ea = (unsigned char *)_ea;
    if (*ea == 0x4C && *(ea+1) == 0x8D) { // lea r1X, [XXX]
      int32_t delta = *(int32_t *)(ea + 3);
      if (ea + 7 + delta == argPtr) {
        // found lea rXX, [ARGPAT]
        // lea_arg_ptr = ea - 0x2E; 
        lea_arg_ptr = _ea + 7; // skip this instruction, as this instruction is position-dependent
        return 0;
      }
    }
  }
  return 1;
}

static HookInformation HOOKINFO_sftp_server_main;
typedef void (*sftp_server_main_t)(int argc, char **argv, void *user_pw);
static sftp_server_main_t ori_sftp_server_main = 0;

#define CHROOT_PATH "/mnt/user"

void do_chroot() {
  FILE *loggingfd = fopen("/tmp/chrootssh", "w");
  if (loggingfd) {
    fprintf(loggingfd, "curuid %d euid %d\n", getuid(), geteuid());
    fprintf(loggingfd, "chrooting into %s\n", CHROOT_PATH);
    if (!!chroot(CHROOT_PATH)) {
      fprintf(loggingfd, "chroot failed, errno %d\n", errno);
    } else {
      fprintf(loggingfd, "chroot succeeded!\n");
    }
    fclose(loggingfd);
  } else {
    chroot(CHROOT_PATH);
  }
}

// void sftp_server_main(int argc, char **argv, struct passwd *user_pw) {
// static void hook_sftp_server_main(int argc, char **argv, void *user_pw) {
__attribute__ ( ( naked ) ) void hook_sftp_server_main( void )
{
    __asm (
        "push %rdi;"
        "push %rsi;"
        "push %rdx;"
        "push %rcx;"
        "push %r8;"
        "push %r9;"
        "push %r12;"
        "push %r13;"
        "sub $0x1000, %rsp;"
        "call do_chroot;"
        "add $0x1000, %rsp;"
        "pop %r13;"
        "pop %r12;"
        "pop %r9;"
        "pop %r8;"
        "pop %rcx;"
        "pop %rdx;"
        "pop %rsi;"
        "pop %rdi;"
        "jmp  *ori_sftp_server_main(%rip);"
    );
}

static int inithook_sftp_server_main() {
  // PlatformProtect(lea_arg_ptr - 0x2e, 0x100, PROTECTION_READ_WRITE_EXECUTE);
  // *(uint32_t *)(lea_arg_ptr-0x2e) = 0x90909090;
  int ins_deltas[20] = {};
  int ins_pie[20] = {};
  int size = 0;
  for (int i = 0; i < 20; i++) {
    ins_deltas[i] = size;
    ins_pie[i] = 0;
    if (*(unsigned char *)(lea_arg_ptr + size) == 0x48 && *(unsigned char *)(lea_arg_ptr + size + 1) == 0x8D) {
      ins_pie[i] = 1;
    }
    else if (*(unsigned char *)(lea_arg_ptr + size) == 0x4C && *(unsigned char *)(lea_arg_ptr + size + 1) == 0x8D) {
      ins_pie[i] = 1;
    }
    else if (*(unsigned char *)(lea_arg_ptr + size) == 0xE8) {
      ins_pie[i] = 1;
    }
    fprintf(stderr, "ins%d size %d ispie %d\n", i, size, ins_pie[i]);
    size += GetInstructionSize((unsigned char*)lea_arg_ptr + size);
  }
  uintptr_t final_hook_addr = 0;
  for (int i = 0; i < 10; i++) {
    int can_use = 1;
    for (int j = i; j < 20; j++) {
      if (ins_deltas[j] - ins_deltas[i] > sizeof(JUMP_CODE)) {
        break;
      }
      if (ins_pie[j]) { // cannot move this ins
        can_use = 0;
        break;
      }
      //fprintf(stderr, "ins %d -> %d checked\n", i, j);
    }
    if (can_use) {
      final_hook_addr = lea_arg_ptr + ins_deltas[i];
      break;
    }
  }

  fprintf(stderr, "final hook point %p\n", final_hook_addr);
  
  HOOKINFO_sftp_server_main = CreateHook((void*)final_hook_addr, (void*)&hook_sftp_server_main);
  int status = EnableHook(&HOOKINFO_sftp_server_main);
  assert(status == 1);
  ori_sftp_server_main = (sftp_server_main_t)HOOKINFO_sftp_server_main.Trampoline;
  return 0;
}

__attribute__((constructor)) void chroot_init() {
  if (!!strcmp(get_self_exe_name(0), "sshd")) {
    return;
  }
  
  g_Enable = 1;

  if (!!find_sshd_exec()) {
    fprintf(stderr, "cannot find sshd exec!\n");
    return;
  }
  fprintf(stderr, "got sshd exec at %p, size %p!\n", sshd_addr, sshd_size);
  if (!!find_sftp_server_main()) {
    fprintf(stderr, "cannot find sftp_server_main!\n");
    return;
  }
  fprintf(stderr, "got sshd sftp_server_main %p!\n", lea_arg_ptr);


  if (!!inithook_sftp_server_main()) {
    fprintf(stderr, "cannot hook sftp_server_main!\n");
    return;
  }
  fprintf(stderr, "successfully hooked sftp_server_main!\n");
  return;
}
