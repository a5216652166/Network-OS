/*
 *	Spanning tree protocol; timer-related code
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#include "stp_info.h"

static int stp_is_designated_for_some_port(const struct stp_instance *br)
{
	struct stp_port_entry *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != DISABLED &&
		    !memcmp(&p->designated_bridge, &br->bridge_id, 8))
			return 1;
	}

	return 0;
}

static void stp_hello_timer_expired(void *arg)
{
	struct stp_instance *br = (struct stp_instance *)arg;

	sync_lock (&br->br_lock);

	stp_config_bpdu_generation(br);

	mod_timer (br->hello_timer, br->hello_time * tm_get_ticks_per_second ());

	sync_unlock (&br->br_lock);
}

static void stp_message_age_timer_expired(void *arg)
{
	struct stp_port_entry *p = (struct stp_port_entry *) arg;
	struct stp_instance *br = p->br;
	int was_root;

	if (p->state == DISABLED)
		return;

	sync_lock (&br->br_lock);
	if (p->state == DISABLED) {
		sync_unlock (&br->br_lock);
		return;
	}
	p->is_own_bpdu = 0;
	was_root = stp_is_root_bridge(br);

	stp_become_designated_port(p);
	stp_configuration_update(br);
	stp_port_state_selection(br);
	if (stp_is_root_bridge(br) && !was_root)
		stp_become_root_bridge(br);
	sync_unlock (&br->br_lock);
}

static void stp_forward_delay_timer_expired(void *arg)
{
	struct stp_port_entry *p = (struct stp_port_entry *) arg;
	struct stp_instance *br = p->br;

	sync_lock (&br->br_lock);
	if (p->state == LISTENING) {
		p->state = LEARNING;
		mod_timer(p->forward_delay_timer,  br->forward_delay * tm_get_ticks_per_second ());
	} else if (p->state == LEARNING) {
		p->state = FORWARDING;
		if (stp_is_designated_for_some_port(br))
			stp_topology_change_detection(br);
	}
	sync_unlock (&br->br_lock);
}

static void stp_tcn_timer_expired(void *arg)
{
	struct stp_instance *br = (struct stp_instance *) arg;

	sync_lock (&br->br_lock);
	stp_transmit_tcn(br);
	mod_timer(br->tcn_timer, br->bridge_hello_time * tm_get_ticks_per_second ());
	sync_unlock (&br->br_lock);
}

static void stp_topology_change_timer_expired(void * arg)
{
	struct stp_instance *br = (struct stp_instance *) arg;

	sync_lock (&br->br_lock);
	br->topology_change_detected = 0;
	br->topology_change = 0;
	sync_unlock (&br->br_lock);
}

static void stp_hold_timer_expired(void *arg)
{
	struct stp_port_entry *p = (struct stp_port_entry *) arg;

	sync_lock (&p->br->br_lock);
	if (p->config_pending)
		stp_transmit_config(p);
	sync_unlock (&p->br->br_lock);
}

void stp_timer_init(struct stp_instance *br)
{
	setup_timer(&br->hello_timer, stp_hello_timer_expired, (void *)br);

	setup_timer(&br->tcn_timer, stp_tcn_timer_expired, (void *)br);

	setup_timer(&br->topology_change_timer, stp_topology_change_timer_expired,
		      (void *) br);
}

void stp_port_timer_init(struct stp_port_entry *p)
{
	setup_timer(&p->message_age_timer, stp_message_age_timer_expired,
		      (void *) p);

	setup_timer(&p->forward_delay_timer, stp_forward_delay_timer_expired,
		      (void *) p);

	setup_timer(&p->hold_timer, stp_hold_timer_expired,
		      (void *) p);
}
