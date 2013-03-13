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

extern vector cmdvec;
/* ifMgrd options. */
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

/* ifMgrd privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_NET_RAW,
  ZCAP_BIND
};

struct zebra_privs_t ifMgrd_privs =
{
  .user = "root",
  .group = "root",
  .vty_group = "root",
  .caps_p = _caps_p,
  .cap_num_p = 2,
  .cap_num_i = 0
};

struct zebra_privs_t server_privs =
{
  .user = "root",
  .group = "root",
  .vty_group = "root",
  .caps_p = _caps_p,
  .cap_num_p = 2,
  .cap_num_i = 0
};



/* Configuration file and directory. */
char config_default[] = "/opt/NetworkOS/etc/ifMgrd.conf";
char *config_file = NULL;

/* ifMgrd program name */

/* Route retain mode flag. */
int retain_mode = 0;

/* RIP VTY bind address. */
char *vty_addr = NULL;

/* RIP VTY connection port. */
int vty_port = 2610;

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = "/opt/NetworkOS/etc/ifMgrd.pid";

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
Daemon which manages RIP version 1 and 2.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-z, --socket       Set path of zebra socket\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-C, --dryrun       Check configuration for validity and exit\n\
-r, --retain       When program terminates, retain added route by ifMgrd.\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname);
    }

  exit (status);
}

/* SIGHUP handler. */
static void 
sighup (void)
{
  zlog_info ("SIGHUP received");
  //ifMgr_clean ();
  //ifMgr_reset ();
  zlog_info ("ifMgrd restarting!");

  /* Reload config file. */
  vty_read_config (config_file, config_default);

  /* Create VTY's socket */
  vty_serv_sock (vty_addr, vty_port, "/opt/NetworkOS/etc/ifMgrd.vty");

  /* Try to return to normal operation. */
}

/* SIGINT handler. */
static void
sigint (void)
{
  zlog_notice ("Terminating on signal");

  if (! retain_mode)
    //ifMgr_clean ();

  exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

static struct quagga_signal_t ifMgrd_signals[] =
{
  { 
    .signal = SIGHUP,
    .handler = &sighup,
  },
  { 
    .signal = SIGUSR1,
    .handler = &sigusr1,
  },
  {
    .signal = SIGINT,
    .handler = &sigint,
  },
  {
    .signal = SIGTERM,
    .handler = &sigint,
  },
};  

/* Main routine of ifMgrd. */
int
main (int argc, char **argv)
{
  char *p;
  int daemon_mode = 0;
  int dryrun = 0;
  char *progname;
  struct thread thread;

  /* Set umask before anything for security */
  umask (0027);

  /* Get program name. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* First of all we need logging init. */
  zlog_default = openzlog (progname, ZLOG_IFMGR,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

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
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
	  break;
        case 'i':
          pid_file = optarg;
          break;
	case 'z':
	  zclient_serv_path_set (optarg);
	  break;
	case 'P':
          /* Deal with atoi() returning 0 on failure, and ifMgrd not
             listening on ifMgr port... */
          if (strcmp(optarg, "0") == 0) 
            {
              vty_port = 0;
              break;
            } 
          vty_port = atoi (optarg);
	  break;
	case 'r':
	  retain_mode = 1;
	  break;
	case 'C':
	  dryrun = 1;
	  break;
	case 'u':
	  ifMgrd_privs.user = optarg;
	  break;
	case 'g':
	  ifMgrd_privs.group = optarg;
	  break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Prepare master thread. */
  master = thread_master_create ();

  /* Library initialization. */
  zprivs_init (&ifMgrd_privs);
  memcpy (&server_privs, &ifMgrd_privs, sizeof (server_privs));
  signal_init (master, array_size(ifMgrd_signals), ifMgrd_signals);

  cmd_init (1);
  vty_init (master);
  memory_init ();
  //keychain_init ();

  if_init ();
  ifMgr_if_init ();

  /* Get configuration file. */
  //vty_read_config (config_file, config_default);

  /* Start execution only if not in dry-run mode */
  if(dryrun)
    return (0);
  
  /* Change to the daemon program. */
  if (daemon_mode && daemon (0, 0) < 0)
    {
      zlog_err("STPD daemon failed: %s", strerror(errno));
      exit (1);
    }

  /* Pid file create. */
  pid_output (pid_file);

  server_set_port (2611);
  server_init ();
  server_socket_init (NULL);
  /* Create VTY's socket */
  vty_serv_sock (vty_addr, vty_port, "/opt/NetworkOS/etc/ifMgrd.vty");

  /* Print banner. */
  //zlog_notice ("RIPd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

  /* Execute each thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}
