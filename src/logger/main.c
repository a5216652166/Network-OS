#include "common_types.h"
#include "signal.h"
#include <zebra.h>
#include "getopt.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "keychain.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"

struct thread_master *master;

static struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "socket",      required_argument, NULL, 'z'},
  { "help",        no_argument,       NULL, 'h'},
  { "dryrun",      no_argument,       NULL, 'C'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "retain",      no_argument,       NULL, 'r'},
  { "user",        required_argument, NULL, 'u'},
  { "group",       required_argument, NULL, 'g'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};



zebra_capabilities_t _caps_p [] =
{
  ZCAP_NET_RAW,
  ZCAP_BIND,
};

struct zebra_privs_t logger_privs =
{
  .user = "root",
  .group = "root",
  .vty_group = "root",
  .caps_p = _caps_p,
  .cap_num_p = 2,
  .cap_num_i = 0
};


int main (int argc, char **argv)
{
	int i = 0;
	int pid = 0;
  	const char *pid_file = "/opt/NetworkOS/etc/logger.pid";
	struct thread thread;
  	char *progname, *p;
	
	/* Set umask before anything for security */
	umask (0027);

	/* Get program name. */
	progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

	/* Command line option parse. */
	while (1) 
	{
		int opt;

		opt = getopt_long (argc, argv, "df:i:z:hA:P:u:g:rvC", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) 
		{
			case 0:
				break;
			case 'd':
				break;
			case 'f':
		//		config_file = optarg;
				break;
			case 'i':
				pid_file = optarg;
				break;
			case 'z':
				zclient_serv_path_set (optarg);
				break;
			case 'r':
				break;
			case 'C':
				break;
			case 'u':
				logger_privs.user = optarg;
				break;
			case 'g':
				logger_privs.group = optarg;
				break;
			case 'v':
				print_version (progname);
				exit (0);
				break;
			default:
				break;
		}
	}

	master = thread_master_create();

  	zprivs_init (&logger_privs);
	cmd_init (1);
	vty_init (master);

	pid_output (pid_file);

  	vty_serv_sock (NULL, 2612, RUN_SOCK_PATH"logger.vty");

	while (thread_fetch (master, &thread))
		thread_call (&thread);
	return 0;
}
