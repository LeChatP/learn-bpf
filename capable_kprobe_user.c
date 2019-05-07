#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"

int main(int argc, char **argv)
{
	char filename[256];
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}
	
	int key, value;
	int res, prev_key = -1;
	sleep(1);
	while(bpf_map_get_next_key(map_fd[0], &prev_key, &key) == 0){
		res = bpf_map_lookup_elem(map_fd[0], &key, &value);
		if(res < 0 ){
			printf("No value??\n");
        	continue;
		}
		printf("got pid : %d\tcaps : %d\n",key,value);
		prev_key=key;
	}

	return 0;
}
