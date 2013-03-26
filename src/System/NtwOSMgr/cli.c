#include "main.h"
#include "vtysh.h"
#include "libclient.h"
#include "libserv.h"
#include "linklist.h"

extern struct process_info process[];
extern int process_count;

DEFUN (show_process, show_process_cmd,
       "show process",  
       SHOW_STR
       "Process information\n")
{
	int i = 0;

	vty_out (vty, "%-10s %-10s  %-10s\n", "PROCESS", "STATE", "PID");
	vty_out (vty, "%-10s %-10s  %-10s\n", "-------", "-----", "----");

	while (i < process_count) {
		if (process[i].name && process[i].binaryname) {
			vty_out (vty, "%-10s %-10s  %-10d\n", process[i].name,
				state_str[process[i].state], process[i].pid );
		}
		i++;
	}


}

DEFUN (show_process_cpu, show_process_cpu_cmd,
       "show process cpu",  
       SHOW_STR
       "Process information\n"
       "CPU usage\n")
{
	int i = 0;

	vty_out (vty, "%-10s %-10s %-10s\n", "PROCESS", "STATE", "%CPU");
	vty_out (vty, "%-10s %-10s %-10s\n", "-------", "-----", "----");

	while (i < process_count) {
		if (process[i].name && process[i].binaryname) {
			vty_out (vty, "%-10s %-10s %-0.2f\n", process[i].name,
				state_str[process[i].state], process[i].total_cpu_usgae);
		}
		i++;
	}


}

void cli_init (void)
{
  install_element (VIEW_NODE, &show_process_cmd);
  install_element (ENABLE_NODE, &show_process_cmd);
  install_element (VIEW_NODE, &show_process_cpu_cmd);
  install_element (ENABLE_NODE, &show_process_cpu_cmd);
}
