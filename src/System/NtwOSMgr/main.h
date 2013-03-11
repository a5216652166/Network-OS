#include "common_types.h"
#include "signal.h"

struct pstat
{
	long unsigned int utime;
	long unsigned int stime;
	long unsigned int tcpu;
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
};
