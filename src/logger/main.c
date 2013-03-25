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
  	const char *pidfile = "/opt/NetworkOS/etc/logger.pid";
	struct thread thread;
  	char *progname, *p;
	
	/* Set umask before anything for security */
	umask (0027);

	/* Get program name. */
	progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

	master = thread_master_create();

  	zprivs_init (&logger_privs);
	cmd_init (1);
	vty_init (master);

	if (daemon (0, 0) < 0)
	{
		zlog_err("logger daemon failed: %s", strerror(errno));
		exit (1);
	}

	pid_output (pidfile);

  	vty_serv_sock (NULL, 2612, "/opt/NetworkOS/etc/logger.vty");

	while (thread_fetch (master, &thread))
		thread_call (&thread);
	return 0;
}
