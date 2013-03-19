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


struct pstat
{
	long unsigned int utime;
	long unsigned int stime;
	long unsigned int tcpu;
};

typedef enum
{
  DAEMON_INIT,
  DAEMON_DOWN,
  DAEMON_CONNECTING,
  DAEMON_UP,
  DAEMON_UNRESPONSIVE
} daemon_state_t;

#define IS_UP(DMN) \
  (((DMN)->state == DAEMON_UP) || ((DMN)->state == DAEMON_UNRESPONSIVE))


struct restart_info
{
  struct timeval  time;
  long            interval;
  struct thread   *t_kill;
  int             kills;
};

static const char *state_str[] =
{
  "Init",
  "Down",
  "Connecting",
  "Up",
  "Unresponsive",
};

struct process_info {
	const char             *name;
	const char             *binaryname;
	const char             *arg[4];
	clock_t                start_time;
	struct     pstat       cpu_stats;
	float                  cpu_user_usage;
	float                  cpu_system_usage;
	float                  total_cpu_usgae;
	int                    pid;
	daemon_state_t 	       state;
	int                    fd;
	struct timeval         echo_sent;
	unsigned int          connect_tries;
	struct thread          *t_wakeup;
	struct thread          *t_read;
	struct thread          *t_write;
	struct daemon          *next;
	struct restart_info    restart;
	int                    restart_timeout;

};
