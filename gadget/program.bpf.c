#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 64
#endif

#ifndef SIGKILL
#define SIGKILL 9
#endif

#define TIOCSCTTY 21518
#define RUNC_INIT "runc:[2:INIT]"
#define RUNC_INIT_LEN 13

struct mntns_id_res {
  u64 mntns_id;
  bool err;  
};

struct event {
	gadget_mntns_id mntns_id;
	gadget_timestamp timestamp;
	__u8 comm[TASK_COMM_LEN];
};

const volatile int target_signal = SIGKILL;

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(nointeractive, events, event);

static __always_inline struct mntns_id_res get_container_mntns_id(void) {
	struct mntns_id_res res;
 
  // enrich events and stop processing an event when it does not originate from 
  // a container
	res.mntns_id = gadget_get_mntns_id();
	res.err = false;
	if (gadget_should_discard_mntns_id(res.mntns_id))
	  res.err = true;

  return res;
}

static __always_inline int submit_event_and_kill(struct syscall_trace_enter *ctx, gadget_mntns_id mntns_id) {
	struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  // event data
  event->timestamp = bpf_ktime_get_boot_ns();
	event->mntns_id = mntns_id;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // emit event
	gadget_submit_buf(ctx, &events, event, sizeof(*event));

  // kill target process
  bpf_send_signal(target_signal);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int enter_ioctl(struct syscall_trace_enter *ctx)
{
  struct mntns_id_res mntns_id_res = get_container_mntns_id();
  u64 mntns_id = mntns_id_res.mntns_id;
  if (mntns_id_res.err)
    return 0;
  
	__u8 comm[TASK_COMM_LEN];
  int fd;
  int req;

	bpf_get_current_comm(comm, sizeof(comm));
  fd = (int)ctx->args[0];
  req = (int)ctx->args[1];

  // stop processing if this is not an attempt to set an interactive terminal
  // file descriptors 0-2 are reserved for STDIN, STDOUT and STDERR
  if (fd > 2 || req != TIOCSCTTY || __builtin_memcmp(comm, RUNC_INIT, RUNC_INIT_LEN)) 
    return 0;

  return submit_event_and_kill(ctx, mntns_id);
}

char LICENSE[] SEC("license") = "GPL";
