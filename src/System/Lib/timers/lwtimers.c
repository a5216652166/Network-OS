/*
 *  Author:
 *  Sasikanth.V        <sasikanth@email.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include "common_types.h"
#include "list.h"
#include "task.h"

#define    SET_TIMER_MGR_STATE(state)    tmrmgrstate = state

#define    MAX_TIMERS         2000
#define    QUERY_TIMER_EXPIRY  0x1
#define    QUERY_TIMER_INDEX   0x2
#define    TIMER_ONCE  	        0x1
#define    TIMER_REPEAT  	0x2 
#define    TIMER_FOREVER        0x4
#define    TIMER_DELETE         0x8
#define    SYS_MAX_TICKS_IN_SEC    100 /*Since tick timer runs for 10ms: 1 sec = 1000ms (10ms * 100) */
#define    TICK_TIMER_GRANULARITY  10  /*10 milli secs*/
#define    SUCCESS                 0
#define    FAILURE                 1

#define MILLISEC_2_NANOSEC(msec)  msec * 1000 * 1000

typedef struct tm_timer
{
	struct  list_head next;
	void           *data;
 	void           (*time_out_handler)(void *);
	unsigned int    exp;
	unsigned int    time;
	int 	        idx;
	int	        flags;
	int 		is_running;
}TIMER_T;

/************* Private func Prototype  *********************/
static TIMER_T * alloc_timer    (void);
static  int      alloc_timer_id (void);
void             show_uptime    (void);
void    *        tick_service   (void *unused) ;
void    *        tick_clock     (void *unused);
int              init_timer_mgr (void);
static inline void timer_expiry_action (TIMER_T * ptmr);
static unsigned int get_ticks (void);
static void free_timer (TIMER_T *p); 
static void update_times (void);
static int tm_process_tick_and_update_timers (void);
static int timer_restart  (TIMER_T *p);
static void handle_expired_timer (TIMER_T *ptmr);
/****************************************************************/

/************* Private Variable Declaration *********************/
struct timer_mgr {
	struct list_head timers_list;
	volatile unsigned long ticks;
	sync_lock_t  core_timer;
}*tmr_mgr;
static int          timers_count;
static int          indx;
/****************************************************************/


static void timer_lock (void)
{
	sync_lock (&tmr_mgr->core_timer);
}

static void timer_unlock (void)
{
	sync_unlock (&tmr_mgr->core_timer);
}

static void timer_lock_create (void)
{
	create_sync_lock (&tmr_mgr->core_timer);
	timer_unlock ();
}

#if 0
static void debug_timers (void)
{
	int i  = 0;
	TIMER_T *p = NULL;
	return ;

	printf ("\n\n");
	list_for_each_entry (p, &timers_list, next) {
		printf ("Timer value : %d\n", p->exp, i++);
		if (i > timers_count) {
			int *k = NULL;
			*k = 0;
		}
	}
	printf ("\n\n");
}
#endif

static void timer_add_sort (TIMER_T *new)
{
	TIMER_T *cur = NULL;
	struct list_head *head = &tmr_mgr->timers_list;

	timers_count ++;
	if (!list_empty(head)) {
		list_for_each_entry (cur, head, next) {
			if (new->exp <= cur->exp) {
				if (cur->next.prev == head) {
					list_add (&new->next, head);
				} else {
					__list_add (&new->next, cur->next.prev, &cur->next);
				}
				break;
			}
			else if (new->exp > cur->exp) {
				TIMER_T *nxt = (TIMER_T *)cur->next.next;
				if (list_is_last(&cur->next, head)) {
					list_add_tail (&new->next, &nxt->next);  
					break;
				}
				else if ((new->exp <= nxt->exp)) {
					__list_add (&new->next, &cur->next, &nxt->next);  
					break;
				} 
			}
		}
	} else  
		list_add (&new->next, head);
}

static void timer_add (TIMER_T *p)
{
	timer_add_sort (p);
}

void * start_sec_timer (unsigned int secs, void *data, void (*handler) (void *), int flags)
{
	TIMER_T  *new = NULL;
	int idx = 0;


	if ( !(idx = alloc_timer_id ())  || 
             !(new = alloc_timer ())) {
		return NULL;
	}

	INIT_LIST_HEAD (&new->next);
	new->idx = idx;
	new->data = data;
	new->time_out_handler = handler;
	new->exp = tmr_mgr->ticks + secs * SYS_MAX_TICKS_IN_SEC;
	new->time = secs * SYS_MAX_TICKS_IN_SEC;

	if (flags)
		new->flags = flags;
	else
		new->flags = TIMER_ONCE;

	timer_lock ();

	timer_add (new);

	new->is_running = 1;

	timer_unlock ();

	return (void *)new;
}

void * start_timer (unsigned int tick, void *data, void (*handler) (void *), int flags)
{
	TIMER_T  *new = NULL;
	int idx = 0;


	if ( !(idx = alloc_timer_id ())  || 
             !(new = alloc_timer ())) {
		return NULL;
	}

	INIT_LIST_HEAD (&new->next);
	new->idx = idx;
	new->data = data;
	new->time_out_handler = handler;
	new->exp = tmr_mgr->ticks + tick;
	new->time = tick;

	if (flags)
		new->flags = flags;
	else
		new->flags = TIMER_ONCE;

	timer_lock ();

	timer_add (new);

	new->is_running = 1;

	timer_unlock ();

	return (void *)new;
}

int setup_timer (void **p, void (*handler) (void *), void *data)
{
	TIMER_T  *new = NULL;
	int idx = 0;
	

	if ( !(idx = alloc_timer_id ())  || 
             !(new = alloc_timer ())) {
		return -1;
	}

	new->idx = idx;
	new->data = data;
	new->time_out_handler = handler;
	new->flags = TIMER_FOREVER;

	*(TIMER_T **)p = new;

	return 0;
}

int mod_timer (void *timer, unsigned int tick)
{
	TIMER_T  *p = (TIMER_T *)timer;

	if (!p)
		return -1;

	if (p->is_running)
		return -1;
	
	p->exp = tmr_mgr->ticks  + tick;
	p->time =  tick;

	timer_lock ();

	timer_add (p);

	p->is_running = 1;

	timer_unlock ();

	return 0;
}

static int alloc_timer_id (void)
{
	return ++indx;
}

int stop_timer (void *timer)
{
	TIMER_T  *p = (TIMER_T *)timer;

	timer_lock ();

	if (p && p->is_running) {
		p->is_running = 0;
		list_del (&p->next);
	}
	timer_unlock ();
	return 0;
}

int del_timer (void *timer)
{
	stop_timer (timer);
	return 0;
}

static inline TIMER_T * alloc_timer (void)
{
	return calloc (1, sizeof(TIMER_T));
}

static void free_timer (TIMER_T *p) 
{
	free (p);
}

static void update_times ()
{
	timer_lock ();

	tmr_mgr->ticks++;

     	tm_process_tick_and_update_timers ();

	timer_unlock ();
}

unsigned int sys_now (void)
{
	return get_ticks ();
}
unsigned int get_secs (void)
{
	return get_ticks () / 100;
}

static unsigned int get_ticks (void)
{
	return tmr_mgr->ticks ;
}

static unsigned int get_mins (void)
{
	return get_secs() / 60;
}
static unsigned int get_hrs (void)
{
	return get_mins () / (24);
}

unsigned int tm_get_ticks_per_second (void) 
{
	return SYS_MAX_TICKS_IN_SEC;
}

void show_uptime (void)
{
	printf ("Uptime  %d hrs %d mins %d secs %d ticks\n",get_hrs(), 
		 get_mins() % 60, get_secs() % 60, get_ticks() % tm_get_ticks_per_second ());
}

unsigned int milli_secs_to_ticks (unsigned int msecs)
{
	return (msecs / TICK_TIMER_GRANULARITY);
}

void * tick_clock (void *unused)
{
	register clock_t    start, end;
	register int        tick = 0;
	
	timer_lock_create ();

	INIT_LIST_HEAD (&tmr_mgr->timers_list);

	for (;;) {

		start = times (NULL);
		tsk_delay (0, MILLISEC_2_NANOSEC (TICK_TIMER_GRANULARITY));
		end = times (NULL);
		
		tick = end - start;

		if (tick <= 0)
			tick = 1;

		while (tick--) {
			update_times (); 
		}
	}
	return NULL;
}


int init_timer_mgr (void)
{
	tmtaskid_t task_id = 0;
	long       i = 0;

	tmr_mgr = malloc (sizeof (struct timer_mgr));

	if (task_create ("TMRMGR", 99, TSK_SCHED_RR, 32000,
			  tick_clock, NULL, (void *)i, &task_id) == TSK_FAILURE) {
		return FAILURE;
	}

	return SUCCESS;
}



static int timer_restart  (TIMER_T *p)
{

	timer_lock ();

	p->exp = p->time + tmr_mgr->ticks ;
	
	timer_add (p);

	p->is_running = 1;

	timer_unlock ();

	return 0;
}


static void handle_expired_timer (TIMER_T *ptmr)
{
	if (ptmr->time_out_handler) {
		ptmr->time_out_handler (ptmr->data);
	}

	if (ptmr->flags & TIMER_ONCE) {
		free_timer (ptmr);
	} 
	else if (ptmr->flags & TIMER_REPEAT) {
		timer_restart (ptmr);
	}
}

static void timer_expiry_action (TIMER_T * ptmr)
{
	ptmr->is_running = 0;
	timer_unlock ();
	handle_expired_timer (ptmr);
	timer_lock ();
}


static int tm_process_tick_and_update_timers ()
{
	TIMER_T *p, *n;
	struct list_head *head = &tmr_mgr->timers_list;

	list_for_each_entry_safe(p, n, head, next) {
		int diff = p->exp - tmr_mgr->ticks;
		if (diff <= 0) {
#ifdef TIMER_DBG
			printf ("Delete timer : %d %d %d\n", tmr_mgr->ticks, p->exp, diff);
#endif
			timers_count--;
			list_del (&p->next);
			INIT_LIST_HEAD (&p->next);
			timer_expiry_action (p);
			continue;
		} 
	}

	return 0;
}
int timer_pending (void *timer)
{
	TIMER_T  *p = (TIMER_T *)timer;
	
        if (!p)
                return 0;

        return p->is_running;
}

unsigned int timer_get_remaining_time (void *timer)
{
	TIMER_T  *p = (TIMER_T *)timer;
	int t = 0;

        if (!p || !p->is_running) {
                return 0;
        }

        t = p->exp - get_ticks();

        if (t < 0) {
                printf ("\nTIMERS : Oopss negative remainiting time %s\n",__FUNCTION__);
                t = 0;
        }
        return t;
}
