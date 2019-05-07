#include <linux/filter.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include "bpf_helpers.h"

SEC("kprobe/capable")
int bpf_prog1(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 uid = bpf_get_current_uid_gid();
	int cap = (int)PT_REGS_PARM1(ctx); // param 1 is capability
	unsigned long unknown1 = PT_REGS_PARM2(ctx); //???
	unsigned long unknown2 = PT_REGS_PARM3(ctx); //???
	
	char data_format[] = "pid: %lu\tuid: %lu\tcap: %d\n";

	bpf_trace_printk(data_format, sizeof(data_format), pid,uid,cap);

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
