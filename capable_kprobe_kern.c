#include <linux/filter.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") capabilities_map = {
	.type = 		BPF_MAP_TYPE_HASH,
	.key_size 		= sizeof(u32),
	.value_size		= sizeof(int),
	.max_entries	= PID_MAX_DEFAULT,
	.map_flags   	= 0
};

SEC("kprobe/capable")
int bpf_prog1(struct pt_regs *ctx)
{
	u32 *val, cap_start = 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
	int cap = (int)PT_REGS_PARM1(ctx); // param 1 is capability
	//u32 uid = bpf_get_current_uid_gid();
	//unsigned long unknown1 = PT_REGS_PARM2(ctx); //???
	//unsigned long unknown2 = PT_REGS_PARM3(ctx); //???
	
	//val = bpf_map_lookup_elem(&capabilities_map, &pid);
	bpf_map_update_elem(&capabilities_map, &pid, &cap_start, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
