#include "common_types.h"

struct process_info {
	char             *name;
	char             *binaryname;
	char             *arg1;
	char             *arg2;
	char             *arg3;
	char             *arg4;
	clock_t          start_time;
	int              pid;
	
} process[] = {
#ifdef CONFIG_LAYER3
	{"RTM", "/opt/NetworkOS/sbin/zebra", "-u root -d", NULL, NULL, NULL},
	{"BGP", "/opt/NetworkOS/sbin/bgpd", "-u root -d", NULL, NULL, NULL},
	{"OSPF", "/opt/NetworkOS/sbin/ospfd", "-u root -d", NULL, NULL, NULL},
#endif
//	{"CLI", "/opt/NetworkOS/sbin/cli", NULL, NULL, NULL, NULL},
	{NULL,  NULL,       NULL, NULL, NULL, NULL}
}; 

int main (int argc, char **argv)
{
	int i = 0;
	int pid = 0;
	printf ("Network-OS Init");

	while (i < sizeof (process) / sizeof (process[0])) {
		if (process[i].name && process[i].binaryname) {
			pid = fork ();

			switch (pid) {
				case -1:
					fprintf (stderr, "Error: \"%s\"  process creation failed\n", 
					process[i].name);
					break;
				case 0:
					execlp(process[i].binaryname, process[i].arg1, process[i].arg2, 
					       process[i].arg3, process[i].arg4);
					break;
				default:
					process[i].pid = pid;
					process[i].start_time = times (NULL);
					break;	
			}
			usleep (500);
		}
		i++;
	}
		
	sleep (1);
	system ("echo 1>  /opt/NetworkOS/NwtMgrDone");
	while (1) {
		sleep (1);
	}
}
