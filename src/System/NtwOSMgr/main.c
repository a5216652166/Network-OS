#include "main.h"
#include "sys/un.h"

#define ERRNO_IO_RETRY(EN) \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

#ifndef MIN
#define MIN(X,Y) (((X) <= (Y)) ? (X) : (Y))
#endif

/* Macros to help randomize timers. */
#define JITTER(X) ((random() % ((X)+1))-((X)/2))
#define FUZZY(X) ((X)+JITTER((X)/20))

#define DEFAULT_PERIOD		5
#define DEFAULT_TIMEOUT		10
#define DEFAULT_RESTART_TIMEOUT	20
#define DEFAULT_LOGLEVEL	LOG_INFO
#define DEFAULT_MIN_RESTART	60
#define DEFAULT_MAX_RESTART	600
#define PATH_WATCHQUAGGA_PID "/opt/NetworkOS/etc/watchquagga.pid"
#define DEFAULT_PIDFILE		PATH_WATCHQUAGGA_PID
#define VTYDIR			"/opt/NetworkOS/etc"

#define PING_TOKEN	"PING"


static int wakeup_send_echo(struct thread *t_wakeup);
static int try_connect(struct process_info *dmn);
static void try_restart(struct process_info *dmn);
static inline pid_t restart_process (struct process_info *process);

typedef enum
{
  MODE_MONITOR = 0,
  MODE_GLOBAL_RESTART,
  MODE_SEPARATE_RESTART,
  MODE_PHASED_ZEBRA_RESTART,
  MODE_PHASED_ALL_RESTART
} watch_mode_t;

static const char *mode_str[] =
{
  "monitor",
  "global restart",
  "individual daemon restart",
  "phased zebra restart",
  "phased global restart for any failure",
};

typedef enum
{
  PHASE_NONE = 0,
  PHASE_STOPS_PENDING,
  PHASE_WAITING_DOWN,
  PHASE_ZEBRA_RESTART_PENDING,
  PHASE_WAITING_ZEBRA_UP
} restart_phase_t;

static const char *phase_str[] =
{
  "None",
  "Stop jobs running",
  "Waiting for other daemons to come down",
  "Zebra restart job running",
  "Waiting for zebra to come up",
  "Start jobs running",
};

#define PHASE_TIMEOUT (3*gs.restart_timeout)




static struct global_state
{
  watch_mode_t mode;
  restart_phase_t phase;
  struct thread *t_phase_hanging;
  const char *vtydir;
  long period;
  long timeout;
  long restart_timeout;
  long min_restart_interval;
  long max_restart_interval;
  int do_ping;
  struct daemon *daemons;
  const char *restart_command;
  const char *start_command;
  const char *stop_command;
  struct restart_info restart;
  int unresponsive_restart;
  int loglevel;
  int numdaemons;
  int numpids;
  int numdown;		/* # of daemons that are not UP or UNRESPONSIVE */
} gs = {
  .mode = MODE_MONITOR,
  .phase = PHASE_NONE,
  .vtydir = VTYDIR,
  .period = 1000*DEFAULT_PERIOD,
  .timeout = DEFAULT_TIMEOUT,
  .restart_timeout = DEFAULT_RESTART_TIMEOUT,
  .loglevel = DEFAULT_LOGLEVEL,
  .min_restart_interval = DEFAULT_MIN_RESTART,
  .max_restart_interval = DEFAULT_MAX_RESTART,
  .do_ping = 1,
};

struct thread_master *master;

struct process_info process[] = {
	{"IFMGR", "/opt/NetworkOS/sbin/ifMgrd", "ifMgrd", "-u", "root", NULL, 0, 0},
#ifdef CONFIG_STP
	{"STP", "/opt/NetworkOS/sbin/stpd", "stp", "-u", "root", NULL, 0, 0},
#endif
#ifdef CONFIG_LAYER3
	{"RTM", "/opt/NetworkOS/sbin/zebra", "zebra", "-u", "root", NULL, 0, 0},
#ifdef CONFIG_BGP
	{"BGP", "/opt/NetworkOS/sbin/bgpd",  "bgpd",  "-u", "root", NULL, 0, 0},
#endif
#ifdef CONFIG_OSPF
	{"OSPF", "/opt/NetworkOS/sbin/ospfd","ospfd", "-u", "root", NULL, 0, 0},
	{"OSPF6D", "/opt/NetworkOS/sbin/ospf6d", "ospf6d", "-u", "root", NULL, 0, 0},
#endif
#ifdef CONFIG_RIP
	{"RIP", "/opt/NetworkOS/sbin/ripd", "ripd", "-u", "root", NULL, 0, 0},
	{"RIPNGD", "/opt/NetworkOS/sbin/ripngd", "ripngd", "-u", "root", NULL, 0, 0},
#endif
#ifdef CONFIG_ISISD
	{"ISISD", "/opt/NetworkOS/sbin/isisd", "isisd", "-u", "root", NULL, 0, 0},
#endif
#ifdef CONFIG_BABELD
	{"BABELD", "/opt/NetworkOS/sbin/babeld", "babeld", "-u", "root", NULL, 0, 0},
#endif
#endif
}; 

static pid_t run_background (struct process_info *process)
{
	pid_t child;

	switch (child = fork())
	{
		case -1:
			fprintf (stderr, "Error: \"%s\"  process creation failed : %s\n", 
					process->name, strerror (errno));
			return -1;
		case 0:
			printf ("-> Starting process \033[31m%s\033[0m\n", process->name);
			/* Child process. */
			/* Use separate process group so child processes can be killed easily. */
			if (setpgid(0,0) < 0)
				warn ("warning: setpgid(0,0) failed: %s",strerror(errno));
			if (execvp(process->binaryname, process->arg) < 0) {
				fprintf (stderr, "Error: \"%s\"  process creation failed : %s\n", 
					process->name, strerror (errno));
			}
			_exit(127);
		default:
			//zlog_err("Forked background command [pid %d]: %s",(int)child,shell_cmd);
			return child;
	}
}



static struct timeval * time_elapsed(struct timeval *result, const struct timeval *start_time)
{
	gettimeofday(result,NULL);
	result->tv_sec -= start_time->tv_sec;
	result->tv_usec -= start_time->tv_usec;
	while (result->tv_usec < 0) {
		result->tv_usec += 1000000L;
		result->tv_sec--;
	}
	return result;
}

static int restart_kill(struct thread *t_kill)
{
	struct process_info *process = THREAD_ARG(t_kill);
	struct timeval delay;

	time_elapsed(&delay,&process->restart.time);

	zlog_warn("Warning: %s child process %d still running after "
			"%ld seconds, sending signal %d", process->name,
			(int)process->pid,delay.tv_sec,
			(process->restart.kills ? SIGKILL : SIGTERM));

	kill(-process->pid,(process->restart.kills ? SIGKILL : SIGTERM));

	process->restart.kills++;
	process->restart.t_kill = thread_add_timer(master,restart_kill, process,
			process->restart_timeout);
	return 0;
}

static struct process_info * find_process_by_pid (pid_t child)
{
	int i = 0;
	while (process[i].pid) {
		if (process[i].pid == child)
			return &process[i];
	}
	return NULL;
}

static void sigchild(void)
{
	pid_t child;
	int status;
	const char *name;
	struct process_info *process;

	switch (child = waitpid(-1,&status,WNOHANG))  {
		case -1:
			zlog_err("waitpid failed: %s",safe_strerror(errno));
			return;
		case 0:
			zlog_warn("SIGCHLD received, but waitpid did not reap a child");
			return;
	}

	if ((process = find_process_by_pid (child)) != NULL) {
		name = process->name;
		process->pid = 0;
		//thread_cancel(process->restart.t_kill);
		//process->restart.t_kill = NULL;
		/* Update restart time to reflect the time the command completed. */
		gettimeofday(&process->restart.time,NULL);
	}
	else
	{
		zlog_err("waitpid returned status for an unknown child process %d",
				(int)child);
		name = "(unknown)";
	}
	if (WIFSTOPPED(status))
		zlog_warn("warning: %s process %d is stopped",
				name,(int)child);
	else if (WIFSIGNALED(status))
		zlog_warn("%s process %d terminated due to signal %d",
				name,(int)child,WTERMSIG(status));
	else if (WIFEXITED(status))
	{
		if (WEXITSTATUS(status) != 0)
			zlog_warn("%s process %d exited with non-zero status %d",
					name,(int)child,WEXITSTATUS(status));
		else
			zlog_debug("%s process %d exited normally",name,(int)child);
	}
	else
		zlog_err("cannot interpret %s process %d wait status 0x%x",
				name,(int)child,status);
}


#define SET_READ_HANDLER(DMN) \
	(DMN)->t_read = thread_add_read(master,handle_read,(DMN),(DMN)->fd)

#define SET_WAKEUP_DOWN(DMN)	\
	(DMN)->t_wakeup = thread_add_timer_msec(master,wakeup_down,(DMN),	\
			FUZZY(gs.period))

#define SET_WAKEUP_UNRESPONSIVE(DMN)	\
	(DMN)->t_wakeup = thread_add_timer_msec(master,wakeup_unresponsive,(DMN), \
			FUZZY(gs.period))

#define SET_WAKEUP_ECHO(DMN) \
	(DMN)->t_wakeup = thread_add_timer_msec(master,wakeup_send_echo,(DMN), \
			FUZZY(gs.period))

static int wakeup_down(struct thread *t_wakeup)
{
	struct process_info *dmn = THREAD_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (try_connect(dmn) < 0)
		SET_WAKEUP_DOWN(dmn);
	if ((dmn->connect_tries > 1) && (dmn->state != DAEMON_UP))
		try_restart(dmn);
	return 0;
}

static int wakeup_init(struct thread *t_wakeup)
{
	struct process_info *dmn = THREAD_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (try_connect(dmn) < 0)
	{
		SET_WAKEUP_DOWN(dmn);
		zlog_err("%s state -> down : initial connection attempt failed",
				dmn->name);
		dmn->state = DAEMON_DOWN;
	}
	return 0;
}

static void daemon_down(struct process_info *dmn, const char *why)
{
	if (IS_UP(dmn) || (dmn->state == DAEMON_INIT))
		zlog_err("%s state -> down : %s",dmn->name,why);
	else if (gs.loglevel > LOG_DEBUG)
		zlog_debug("%s still down : %s",dmn->name,why);
	if (IS_UP(dmn))
		gs.numdown++;
	dmn->state = DAEMON_DOWN;
	if (dmn->fd >= 0)
	{
		close(dmn->fd);
		dmn->fd = -1;
	}
	THREAD_OFF(dmn->t_read);
	THREAD_OFF(dmn->t_write);
	THREAD_OFF(dmn->t_wakeup);
	if (try_connect(dmn) < 0)
		SET_WAKEUP_DOWN(dmn);
}

static int handle_read(struct thread *t_read)
{
	struct process_info *dmn = THREAD_ARG(t_read);
	static const char resp[sizeof(PING_TOKEN)+4] = PING_TOKEN "\n";
	char buf[sizeof(resp)+100];
	ssize_t rc;
	struct timeval delay;

	dmn->t_read = NULL;
	if ((rc = read(dmn->fd,buf,sizeof(buf))) < 0)
	{
		char why[100];

		if (ERRNO_IO_RETRY(errno))
		{
			/* Pretend it never happened. */
			SET_READ_HANDLER(dmn);
			return 0;
		}
		snprintf(why,sizeof(why),"unexpected read error: %s",
				safe_strerror(errno));
		daemon_down(dmn,why);
		return 0;
	}
	if (rc == 0)
	{
		daemon_down(dmn,"read returned EOF");
		return 0;
	}
	if (!dmn->echo_sent.tv_sec)
	{
		char why[sizeof(buf)+100];
		snprintf(why,sizeof(why),"unexpected read returns %d bytes: %.*s",
				(int)rc,(int)rc,buf);
		daemon_down(dmn,why);
		return 0;
	}

	/* We are expecting an echo response: is there any chance that the
	   response would not be returned entirely in the first read?  That
	   seems inconceivable... */
	if ((rc != sizeof(resp)) || memcmp(buf,resp,sizeof(resp)))
	{
		char why[100+sizeof(buf)];
		snprintf(why,sizeof(why),"read returned bad echo response of %d bytes "
				"(expecting %u): %.*s",
				(int)rc,(u_int)sizeof(resp),(int)rc,buf);
		daemon_down(dmn,why);
		return 0;
	}

	time_elapsed(&delay,&dmn->echo_sent);
	dmn->echo_sent.tv_sec = 0;
	if (dmn->state == DAEMON_UNRESPONSIVE)
	{
		if (delay.tv_sec < gs.timeout)
		{
			dmn->state = DAEMON_UP;
			zlog_warn("%s state -> up : echo response received after %ld.%06ld "
					"seconds", dmn->name,delay.tv_sec,delay.tv_usec);
		}
		else
			zlog_warn("%s: slow echo response finally received after %ld.%06ld "
					"seconds", dmn->name,delay.tv_sec,delay.tv_usec);
	}
	else if (gs.loglevel > LOG_DEBUG+1)
		zlog_debug("%s: echo response received after %ld.%06ld seconds",
				dmn->name,delay.tv_sec,delay.tv_usec);

	SET_READ_HANDLER(dmn);
	if (dmn->t_wakeup)
		thread_cancel(dmn->t_wakeup);
	SET_WAKEUP_ECHO(dmn);

	return 0;
}

static void daemon_up(struct process_info *dmn, const char *why)
{
	dmn->state = DAEMON_UP;
	dmn->connect_tries = 0;
	zlog_notice("%s state -> up",dmn->name);
	SET_WAKEUP_ECHO(dmn);
}

static int check_connect(struct thread *t_write)
{
	struct process_info *dmn = THREAD_ARG(t_write);
	int sockerr;
	socklen_t reslen = sizeof(sockerr);

	dmn->t_write = NULL;
	if (getsockopt(dmn->fd,SOL_SOCKET,SO_ERROR,(char *)&sockerr,&reslen) < 0)
	{
		zlog_warn("%s: check_connect: getsockopt failed: %s",
				dmn->name,safe_strerror(errno));
		daemon_down(dmn,"getsockopt failed checking connection success");
		return 0;
	}
	if ((reslen == sizeof(sockerr)) && sockerr)
	{
		char why[100];
		snprintf(why,sizeof(why),
				"getsockopt reports that connection attempt failed: %s",
				safe_strerror(sockerr));
		daemon_down(dmn,why);
		return 0;
	}

	daemon_up(dmn,"delayed connect succeeded");
	return 0;
}

static int wakeup_connect_hanging(struct thread *t_wakeup)
{
	struct process_info *dmn = THREAD_ARG(t_wakeup);
	char why[100];

	dmn->t_wakeup = NULL;
#if 0
	snprintf(why,sizeof(why),"connection attempt timed out after %ld seconds",
			gs.timeout);
#endif
	daemon_down(dmn,why);
	return 0;
}

/* Making connection to protocol daemon. */
static int try_connect(struct process_info *dmn)
{
	int sock;
	struct sockaddr_un addr;
	socklen_t len;

	if (gs.loglevel > LOG_DEBUG+1)
		zlog_debug("%s: attempting to connect",dmn->name);

	dmn->connect_tries++;

	memset (&addr, 0, sizeof (struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s.vty",
			gs.vtydir,dmn->arg[0]);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof (addr.sun_family) + strlen (addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	/* Quick check to see if we might succeed before we go to the trouble
	   of creating a socket. */
	if (access(addr.sun_path, W_OK) < 0)
	{
		if (errno != ENOENT)
			zlog_err("%s: access to socket %s denied: %s",
					dmn->name,addr.sun_path,safe_strerror(errno));
		return -1;
	}

	if ((sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		zlog_err("%s(%s): cannot make socket: %s",
				__func__,addr.sun_path, safe_strerror(errno));
		return -1;
	}

	if (set_nonblocking(sock) < 0)
	{
		zlog_err("%s(%s): set_nonblocking(%d) failed",
				__func__, addr.sun_path, sock);
		close(sock);
		return -1;
	}

	if (connect (sock, (struct sockaddr *) &addr, len) < 0)
	{
		if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK))
		{
			if (gs.loglevel > LOG_DEBUG)
				zlog_debug("%s(%s): connect failed: %s",
						__func__,addr.sun_path, safe_strerror(errno));
			close (sock);
			return -1;
		}
		if (gs.loglevel > LOG_DEBUG)
			zlog_debug("%s: connection in progress",dmn->name);
		dmn->state = DAEMON_CONNECTING;
		dmn->fd = sock;
		dmn->t_write = thread_add_write(master,check_connect,dmn,dmn->fd);
		dmn->t_wakeup = thread_add_timer(master,wakeup_connect_hanging,dmn,
				gs.timeout);
		SET_READ_HANDLER(dmn);
		return 0;
	}

	dmn->fd = sock;
	SET_READ_HANDLER(dmn);
	daemon_up(dmn,"connect succeeded");
	return 1;
}

static int phase_hanging(struct thread *t_hanging)
{
	gs.t_phase_hanging = NULL;
	zlog_err("Phase [%s] hanging for %ld seconds, aborting phased restart",
			phase_str[gs.phase],PHASE_TIMEOUT);
	gs.phase = PHASE_NONE;
	return 0;
}

static void try_restart(struct process_info *dmn)
{
	dmn->pid = restart_process (dmn);
}

static int wakeup_unresponsive(struct thread *t_wakeup)
{
	struct process_info *dmn = THREAD_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (dmn->state != DAEMON_UNRESPONSIVE)
		zlog_err("%s: no longer unresponsive (now %s), "
				"wakeup should have been cancelled!",
				dmn->name,state_str[dmn->state]);
	else
	{
		SET_WAKEUP_UNRESPONSIVE(dmn);
		try_restart(dmn);
	}
	return 0;
}

static int wakeup_no_answer(struct thread *t_wakeup)
{
	struct process_info *dmn = THREAD_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	dmn->state = DAEMON_UNRESPONSIVE;
	zlog_err("%s state -> unresponsive : no response yet to ping "
			"sent %ld seconds ago",dmn->name,gs.timeout);
	SET_WAKEUP_UNRESPONSIVE(dmn);
	try_restart(dmn);
	return 0;
}

static int wakeup_send_echo(struct thread *t_wakeup)
{
	static const char echocmd[] = "echo " PING_TOKEN;
	ssize_t rc;
	struct process_info *dmn = THREAD_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (((rc = write(dmn->fd,echocmd,sizeof(echocmd))) < 0) ||
			((size_t)rc != sizeof(echocmd)))
	{
		char why[100+sizeof(echocmd)];
		snprintf(why,sizeof(why),"write '%s' returned %d instead of %u",
				echocmd,(int)rc,(u_int)sizeof(echocmd));
		daemon_down(dmn,why);
	}
	else
	{
		gettimeofday(&dmn->echo_sent,NULL);
		dmn->t_wakeup = thread_add_timer(master,wakeup_no_answer,dmn,gs.timeout);
	}
	return 0;
}

static void sigint(void)
{
	zlog_notice("Terminating on signal");
	exit(0);
}

static int valid_command(const char *cmd)
{
	char *p;

	return ((p = strchr(cmd,'%')) != NULL) && (*(p+1) == 's') && !strchr(p+1,'%');
}

/* This is an ugly hack to circumvent problems with passing command-line
   arguments that contain spaces.  The fix is to use a configuration file. */
	static char *
translate_blanks(const char *cmd, const char *blankstr)
{
	char *res;
	char *p;
	size_t bslen = strlen(blankstr);

	if (!(res = strdup(cmd)))
	{
		perror("strdup");
		exit(1);
	}
	while ((p = strstr(res,blankstr)) != NULL)
	{
		*p = ' ';
		if (bslen != 1)
			memmove(p+1,p+bslen,strlen(p+bslen)+1);
	}
	return res;
}

static inline void kill_process (struct process_info *process)
{
	if (process->pid)
		kill (process->pid, SIGKILL);	
}


static inline pid_t restart_process (struct process_info *process)
{
	kill_process (process);

	return run_background (process);
}

void terminate_all_process (int signo)
{
	int  i =  sizeof (process) / sizeof (process[0]);
	do {
		i--;
		kill_process (&process[i]);
	} while (i);

	unlink ("/opt/NetworkOS/NwtMgrDone");
	exit (0);
}

void init_signals (void)
{
	signal (SIGTERM, terminate_all_process);
	signal (SIGCHLD, sigchild);
}

void start_process (void) 
{
	int i = 0, pid = 0;

	unlink ("/opt/NetworkOS/NwtMgrDone");

	while (i < sizeof (process) / sizeof (process[0])) {
		if (process[i].name && process[i].binaryname) {
			pid = run_background (&process[i]);
			if (pid > 0) {
				process[i].pid = pid;
				process[i].start_time = times (NULL);
				process[i].state = DAEMON_INIT;
				process[i].fd = -1;
				process[i].t_wakeup = thread_add_timer_msec(master,wakeup_init, 
							&process[i], 100+(random() % 900));

				usleep (500);
			}
		}
		i++;
	}
}

void do_process_monitor (void)
{
	int i = 0;
	while (i < sizeof (process) / sizeof (process[0])) {
		track_and_update_cpu_usage (i);
		i++;
	}
}

int main (int argc, char **argv)
{
	int i = 0;
	int pid = 0;
  	const char *pidfile = DEFAULT_PIDFILE;
	
	init_signals ();

	master = thread_master_create();

	srandom(time(NULL));

	pid_output (pidfile);

        start_process ();

	sleep (1);

	printf ("-> All process started successfully\n");

	if (creat("/opt/NetworkOS/NwtMgrDone", S_IRWXU) < 0)
		system ("echo 1>  /opt/NetworkOS/NwtMgrDone");

	{
		struct thread thread;

		while (thread_fetch (master, &thread))
			thread_call (&thread);
	}

	//while (1) {
	//	do_process_monitor ();
	//	sleep (1);
	//}
}
