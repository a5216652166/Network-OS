#include "main.h"
extern struct process_info process[];

struct pstat_temp
{
	long unsigned int utime;
	long unsigned int stime;
	long unsigned int tcpu;
	long int cstime;
	long int cutime;
};

static int get_usage(pid_t pid, struct pstat_temp* result)
{
	char pid_s[20];
	char stat_filepath[30] = "/proc/";
	int i =0;
	FILE *fpstat = NULL;
	FILE *fpprocstat = NULL;
	long unsigned int cpu_time[10];

	memset(cpu_time, 0, sizeof(cpu_time));

	snprintf(pid_s, sizeof(pid_s), "%d", pid);
	strncat(stat_filepath, pid_s, sizeof(stat_filepath) - strlen(stat_filepath) -1);
	strncat(stat_filepath, "/stat", sizeof(stat_filepath) - strlen(stat_filepath) -1);

	fpstat = fopen(stat_filepath, "r");

	if(!fpstat){
		return -1;
	}

	fpprocstat = fopen("/proc/stat", "r");
	if(!fpprocstat){
		fclose(fpprocstat);
		return -1;
	}
	bzero(result, sizeof(struct pstat));

	if(fscanf(fpstat, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %ld %ld", 
		  &result->utime, &result->stime, &result->cutime, &result->cstime) == EOF){
		fclose(fpstat);
		fclose(fpprocstat);
		return -1;
	}
	fclose(fpstat);

	//read+calc cpu total time from /proc/stat, on linux 2.6.35-23 x86_64 the cpu row has 10values could differ on different architectures :/
	if(fscanf(fpprocstat, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", 
		         &cpu_time[0], &cpu_time[1], &cpu_time[2], &cpu_time[3], &cpu_time[4], &cpu_time[5], &cpu_time[6], 
			&cpu_time[7], &cpu_time[8], &cpu_time[9]) == EOF){
		fclose(fpprocstat);
		return -1;
	}
	fclose(fpprocstat);

	for(i=0; i < 10;i++){
		result->tcpu += cpu_time[i];
	}

	return 0;
}

/* calculates the actual CPU usage(curr - lst) in percent
 * curr, lst: both last measured get_usage() results
 * ucpu_usage, scpu_usage: result parameters: user and sys cpu usage in %
 */
static void calc_cpu_usage (struct pstat* curr, struct pstat* lst, float* ucpu_usage, float* scpu_usage, float *tcpu)
{
	*ucpu_usage = ((100 * (curr->utime - lst->utime )) / (float)((curr->tcpu - lst->tcpu)));
	*scpu_usage = ((100 * (curr->stime - lst->stime))  / (float)((curr->tcpu - lst->tcpu)));

	*tcpu = ((100 * ((curr->utime + curr->stime) -(lst->utime + lst->stime))) / (float)((curr->tcpu - lst->tcpu)));
}

int track_and_update_cpu_usage (int i)
{
	struct pstat_temp current;
	struct pstat curr;;

	memset (&current, 0, sizeof(current));

	get_usage (process[i].pid, &current);

	curr.utime = current.utime + current.cutime;
	curr.stime = current.stime + current.cstime;
	curr.tcpu = current.tcpu;

	calc_cpu_usage (&curr, &process[i].cpu_stats, &process[i].cpu_user_usage, 
			&process[i].cpu_system_usage , &process[i].total_cpu_usgae) ;

	process[i].cpu_stats.utime =  curr.utime;
	process[i].cpu_stats.stime = curr.stime;
	process[i].cpu_stats.tcpu = current.tcpu;

	//printf (" %-16s    %-8.1f       %-8.1f\n", process[i].name, process[i].cpu_user_usage * 2, process[i].cpu_system_usage);
}
