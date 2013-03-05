/*
 *  Author:
 *  Sasikanth.V        <sasikanth@email.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <setjmp.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include "common_types.h"
#include "task.h"
#include "libproto.h"
#include "list.h"

tmtaskid_t tsk_selfid (void);
tmtask_t           * get_tsk_info_frm_id (tmtaskid_t tskid);
void * tsk_wrap (void *ptskarg);
int init_task_cpu_usage_moniter_timer (void);
int  show_cpu_usage (void);

static TIMER_ID cpu_timer;

struct pstat_temp
{
	long unsigned int utime;
	long unsigned int stime;
	long unsigned int tcpu;
	long int cstime;
	long int cutime;
};

static LIST_HEAD(tsk_hd);

struct pstat
{
	long unsigned int utime;
	long unsigned int stime;
	long unsigned int tcpu;
};

typedef struct task_info_ {
    struct list_head     tsk_node;
    char            task_name[MAX_TASK_NAME];
    pid_t             tsk_pid;
    void *(*entry)(void *);
    void            *arg;
#ifdef TASK_DEBUG
    int 	    stksze;
    int             prio;
    int             schedalgo;
#endif
    struct pstat    cpu_stats;
}task_t;


int create_sync_lock (sync_lock_t *slock)
{
	if (!slock)
		return -1;
	if (sem_init(slock, 0, 0) < 0) {
		perror ("SEM_INIT: ");
		return -1;
	}
	return 0;
}

int destroy_sync_lock (sync_lock_t *slock)
{
	if (!slock)
		return -1;
	if (sem_destroy(slock) < 0) {
		perror ("SEM_DESTROY: ");
		return -1;
	}
	return 0;
}


int sync_lock (sync_lock_t *slock)
{
	while (sem_wait (slock) < 0)  {
		/*signal interrupts*/
		if (errno == EINTR) {
			continue;
		}
	}

	return 0;
}

int sync_lock_timed_wait (sync_lock_t *slock, int secs, int nanosecs)
{
	struct timespec abs_timeout;

	clock_gettime(CLOCK_REALTIME, &abs_timeout);

	abs_timeout.tv_sec += secs;
	abs_timeout.tv_nsec += nanosecs;

	while (sem_timedwait (slock, &abs_timeout) < 0)  {
		/*signal interrupts*/
		if (errno == EINTR) {
			continue;
		}
		if (errno == ETIMEDOUT) {
			return ETIMEDOUT;
		}
	}

	return 0;
}

int sync_unlock (sync_lock_t *slock)
{
	if (sem_post (slock) < 0) {
		perror ("SEM_POST: ");
		return -1;
	}
	return 0;
}

static void *task_start (void *arg)
{
	task_t *p = arg;
	
	p->tsk_pid = get_tsk_pid ();

	p->entry (p->arg);

	list_del (&p->tsk_node);

	free (p);

	return NULL;
}

retval_t start_task (tmtask_t * ptskinfo, tmtaskid_t * ptskid)
{
    task_t *p = NULL;
    p = calloc (1, sizeof (task_t));
    if (!p) 
	return TSK_FAILURE;

    INIT_LIST_HEAD (&p->tsk_node);
    p->tsk_pid = *ptskid;
    p->entry   = ptskinfo->start_routine;
    p->arg     =  ptskinfo->tskarg;
    strncpy (p->task_name, ptskinfo->task_name, strlen (ptskinfo->task_name));
    p->task_name[strlen (ptskinfo->task_name)] = '\0';

    if (pthread_create (ptskid, &ptskinfo->tsk_attr, task_start,
                        (void *)p))
    {
	free (p);
        return TSK_FAILURE;
    }
    list_add_tail (&p->tsk_node, &tsk_hd);
    return TSK_SUCCESS;
}

tmtaskid_t tsk_selfid (void)
{
    return pthread_self ();
}

void
tsk_cancel (tmtaskid_t task_id)
{
    pthread_cancel (task_id);
}

retval_t deinit_tsk_attr (tmtask_t * ptskinfo)
{
    return pthread_attr_destroy (&ptskinfo->tsk_attr);
}

retval_t init_tsk_attr (tmtask_t * ptskinfo)
{
    struct sched_param  param;

    pthread_attr_init (&ptskinfo->tsk_attr);

    pthread_attr_setstacksize (&ptskinfo->tsk_attr, ptskinfo->stksze);

    pthread_attr_setschedpolicy (&ptskinfo->tsk_attr, ptskinfo->schedalgo);

    param.sched_priority = ptskinfo->prio;

    pthread_attr_setschedparam (&ptskinfo->tsk_attr, &param);

    switch (getuid ())
    {
        case 0:                /* For Root User */
            pthread_attr_setinheritsched (&ptskinfo->tsk_attr,
                                          PTHREAD_EXPLICIT_SCHED);
            break;
        default:                /*For Other Users */
            pthread_attr_setinheritsched (&ptskinfo->tsk_attr,
                                          PTHREAD_INHERIT_SCHED);
            break;
    }
    return TSK_SUCCESS;
}

void tsk_delay (int secs, int nsecs)
{
    struct timespec     delay_tmr;

    delay_tmr.tv_sec = secs;

    delay_tmr.tv_nsec = nsecs;

    nanosleep (&delay_tmr, NULL);
}

void tsk_sleep (int secs)
{
    sleep (secs);
}

void tsk_mdelay (int msecs)
{
    usleep (msecs * 1000);
}

pid_t get_tsk_pid (void)
{
    return syscall (SYS_gettid);
}

int EventInit (EVT_T *p)
{
	if (!p)
		return -1;

	pthread_cond_init (&p->evt_cnd, NULL);
	pthread_mutex_init (&p->evt_mtx, NULL);
	return 0;
}

int EventDeInit (EVT_T *p)
{
	if (!p)
		return -1;

	pthread_cond_destroy (&p->evt_cnd);
	pthread_mutex_destroy (&p->evt_mtx);
	return 0;
}


int EvtRx (EVT_T *evt, int *pevent, int event)
{
	pthread_mutex_lock (&evt->evt_mtx);

	while (1)
	{
		if (evt->event & event)
		{
			*pevent = evt->event;
			evt->event &= 0;
			pthread_mutex_unlock (&evt->evt_mtx);
			return 0;
		}
		pthread_cond_wait (&evt->evt_cnd, &evt->evt_mtx);
	}

	return -1;
}

int EvtRx_timed_wait (EVT_T *evt, int *pevent, int event, int secs, int nsecs)
{
	struct timespec ts;
	int    err = 0;

	pthread_mutex_lock (&evt->evt_mtx);

	clock_gettime(CLOCK_REALTIME, &ts);

	ts.tv_sec  += secs;
	ts.tv_nsec += nsecs;

	while (1)
	{
		if (evt->event & event)
		{
			*pevent = evt->event;
			evt->event &= 0;
			pthread_mutex_unlock (&evt->evt_mtx);
			return 0;
		}
		err =  pthread_cond_timedwait (&evt->evt_cnd, &evt->evt_mtx, &ts);
		if (err == ETIMEDOUT) {
			pthread_mutex_unlock (&evt->evt_mtx);
			return ETIMEDOUT;
		}
	}

	return -1;
}


void EvtSnd (EVT_T *evt, int event)
{

	pthread_mutex_lock (&evt->evt_mtx);

	evt->event |= event;

	pthread_cond_signal (&evt->evt_cnd);
	pthread_mutex_unlock (&evt->evt_mtx);

	return;
}
int EvtLock (EVT_T *evt)
{
	if (!evt)
		return -1;

	return pthread_mutex_lock (&evt->evt_mtx);
}

int EvtUnLock (EVT_T *evt)
{
	if (!evt)
		return -1;

	return pthread_mutex_unlock (&evt->evt_mtx);
}

int EvtWaitOn (EVT_T *evt)
{
	if (!evt)
		return -1;
	return pthread_cond_wait (&evt->evt_cnd, &evt->evt_mtx);
}

int EvtWaitOnTimed (EVT_T *evt, int secs, int nsecs)
{
	struct timespec ts;

	if (!evt)
		return -1;

	clock_gettime(CLOCK_REALTIME, &ts);

	ts.tv_sec  += secs;
	ts.tv_nsec += nsecs;

	return pthread_cond_timedwait (&evt->evt_cnd, &evt->evt_mtx, &ts);
}


void EvtSignal (EVT_T *evt)
{
	if (!evt)
		return;
	pthread_cond_signal (&evt->evt_cnd);
	pthread_mutex_unlock (&evt->evt_mtx);
}

static int get_usage(pid_t pid, struct pstat_temp* result)
{
	char pid_s[20];
	char stat_filepath[30] = "/proc/self/task/";
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

/*
 * calculates the actual CPU usage(curr - lst) in percent
 * curr, lst: both last measured get_usage() results
 * ucpu_usage, scpu_usage: result parameters: user and sys cpu usage in %
 */
static void calc_cpu_usage (struct pstat* curr, struct pstat* lst, float* ucpu_usage, float* scpu_usage, float *tcpu)
{
	*ucpu_usage = ((100 * (curr->utime - lst->utime )) / (float)((curr->tcpu - lst->tcpu)));
	*scpu_usage = ((100 * (curr->stime - lst->stime))  / (float)((curr->tcpu - lst->tcpu)));

	*tcpu = ((100 * ((curr->utime + curr->stime) -(lst->utime + lst->stime))) / (float)((curr->tcpu - lst->tcpu)));
}

int show_cpu_usage (void)
{
	register struct list_head *node = NULL;
	register task_t  *tskinfo = NULL;

	cli_printf
		("\n Task Name         CPU User        System \n");
	cli_printf
		("\r ---------         --------        -------\n");


	list_for_each (node, (&tsk_hd))
	{
		float user_usage = 0.0, system_usage = 0.0, tcpu = 0.0;
		struct pstat_temp current;
		struct pstat curr;;

		memset (&current, 0, sizeof(current));

		tskinfo = (task_t *) node;

		get_usage (tskinfo->tsk_pid, &current);

		curr.utime = current.utime + current.cutime;
		curr.stime = current.stime + current.cstime;
		curr.tcpu = current.tcpu;

		calc_cpu_usage (&curr, &tskinfo->cpu_stats, &user_usage, &system_usage , &tcpu) ;

		cli_printf (" %-16s    %-8.1f       %-8.1f\n", tskinfo->task_name, user_usage * 2, system_usage);
	}
	return 0;
}

int sys_sem_new(sync_lock_t *slock, int count)
{
	if (!slock)
		return -1;
	if (sem_init(slock, 0, count) < 0) {
		perror ("SEM_INIT: ");
		return -1;
	}
	return 0;
}
void sys_sem_signal (sync_lock_t *slock)
{
	sync_unlock (slock);
}

int sys_sem_wait (sync_lock_t *slock)
{
	return sync_lock (slock);
}
unsigned int sys_arch_sem_wait(sync_lock_t *s, uint32_t msecs)
{
	unsigned int nsecs = msecs * 1000 * 1000;
	unsigned int secs = nsecs / (1000 * 1000 * 1000);
	nsecs %= (1000 * 1000 * 1000);

	return sync_lock_timed_wait (s, secs, nsecs);
}

void sys_sem_free(sync_lock_t *s) 
{
	destroy_sync_lock (s);
}

int sys_sem_valid(sync_lock_t *sem) 
{
	int val = 0;

	return sem_getvalue(sem, &val);	
}
