#include "common_types.h"
#include "signal.h"

struct process_info {
	char             *name;
	char             *binaryname;
	char             *arg[4];
	clock_t          start_time;
	int              pid;
	
} process[] = {

	{"IFMGR", "/opt/NetworkOS/sbin/ifMgrd", "ifMgrd", "-u", "root", NULL, 0, 0},
#ifdef CONFIG_STP
	{"STP", "/opt/NetworkOS/sbin/stpd", "stp", "-u", "root", NULL, 0, 0},
#endif
#ifdef CONFIG_LAYER3
	{"RTM", "/opt/NetworkOS/sbin/zebra", "zebra", "-u", "root", NULL, 0, 0},
	{"BGP", "/opt/NetworkOS/sbin/bgpd",  "bgpd",  "-u", "root", NULL, 0, 0},
	{"OSPF", "/opt/NetworkOS/sbin/ospfd","ospfd", "-u", "root", NULL, 0, 0},
	{"OSPF6D", "/opt/NetworkOS/sbin/ospf6d", "ospfd6d", "-u", "root", NULL, 0, 0},
	{"RIP", "/opt/NetworkOS/sbin/ripd", "ripd", "-u", "root", NULL, 0, 0},
	{"RIPNGD", "/opt/NetworkOS/sbin/ripngd", "ripngd", "-u", "root", NULL, 0, 0},
#endif
	{NULL,  NULL,       NULL, NULL, NULL, NULL}
}; 

void terminate_all_process (int signo)
{
	int  i =  sizeof (process) / sizeof (process[0]);
	if (signo == SIGTERM) {
		do {
			i--;
			if (process[i].name && process[i].binaryname && process[i].pid) {
				kill (process[i].pid, SIGKILL);
			}
		}while (i);
	}
	unlink ("/opt/NetworkOS/NwtMgrDone");
	exit (0);
}

int main (int argc, char **argv)
{
	int i = 0;
	int pid = 0;
	
	signal (SIGTERM, terminate_all_process);

	while (i < sizeof (process) / sizeof (process[0])) {
		if (process[i].name && process[i].binaryname) {
			pid = fork ();

			switch (pid) {
				case -1:
					fprintf (stderr, "Error: \"%s\"  process creation failed\n", 
					process[i].name);
					break;
				case 0:
					setsid();
					execvp(process[i].binaryname, process[i].arg);
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
