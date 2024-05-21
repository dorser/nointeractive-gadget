#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/filesystem.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef SIGKILL
#define SIGKILL 9
#endif

#define TIOCSCTTY 21518
#define RUNC_INIT "runc:[2:INIT]"
#define RUNC_INIT_LEN 13

struct event {
  gadget_mntns_id mntns_id;
  gadget_timestamp timestamp;
  __u32 ppid;
  __u32 tid;
  __u32 uid;
  __u32 gid;
  char comm[TASK_COMM_LEN];
  char filepath[TASK_COMM_LEN];
};

const volatile int target_signal = SIGKILL;

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(nointeractive, events, event);

static __always_inline int
submit_event_and_kill(struct syscall_trace_enter *ctx) {
  gadget_mntns_id mntns_id = gadget_get_mntns_id();
  u64 uid_gid = bpf_get_current_uid_gid();
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 uid = (u32)uid_gid;
  u32 gid = (u32)(uid_gid >> 32);
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  // event data
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = mntns_id;
  event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
  event->tid = (__u32)pid_tgid;
  event->uid = uid;
  event->gid = gid;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  struct path f_path = BPF_CORE_READ(task, mm, exe_file, f_path);
  char *c_path = get_path_str(&f_path);
  bpf_probe_read_kernel_str(&event->filepath, sizeof(event->filepath), c_path);

  // emit event
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  // kill target process
  bpf_send_signal(target_signal);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int enter_ioctl(struct syscall_trace_enter *ctx) {
  __u8 comm[TASK_COMM_LEN];
  int fd;
  int req;

  bpf_get_current_comm(comm, sizeof(comm));
  fd = (int)ctx->args[0];
  req = (int)ctx->args[1];

  // stop processing if this is not an attempt to set an interactive terminal
  // file descriptors 0-2 are reserved for STDIN, STDOUT and STDERR
  if (fd > 2 || req != TIOCSCTTY ||
      __builtin_memcmp(comm, RUNC_INIT, RUNC_INIT_LEN))
    return 0;

  return submit_event_and_kill(ctx);
}

char LICENSE[] SEC("license") = "GPL";
