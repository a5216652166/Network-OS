#include <zebra.h>
#include "command.h"
#include "vtysh.h"
#include "stp_info.h"

/******************************************************/
int spanning_tree_enable (char *);
int spanning_tree_disable (char *);
int set_spanning_bridge_port_path_cost (uint32_t path_cost, uint32_t portnum);
int set_spanning_bridge_port_prio (uint32_t prio, uint32_t portnum);
int  show_spanning_tree  (void);
int vlan_spanning_tree_enable_on_vlan (int vlan_id, int mode);
int vlan_spanning_tree_disable_on_vlan (int vlan_id, int mode);
struct stp_instance * get_this_bridge_entry (uint16_t vlan_id);
/******************************************************/

extern struct list_head stp_instance_head;

#define STP_DEFAULT_INSTANCE "linux_stp"

static int add_interfaces_to_bridge (char *br)
{
	int numreqs = 30;
	struct ifconf ifc;
	struct ifreq *ifr;
	int n, err = -1;
	int   skfd      = socket(AF_INET, SOCK_DGRAM, 0);

	if (skfd < 0)
		return (-1);

	ifc.ifc_buf = NULL;
	for (;;) {
		ifc.ifc_len = sizeof(struct ifreq) * numreqs;
		ifc.ifc_buf = realloc(ifc.ifc_buf, ifc.ifc_len);

		if (ioctl(skfd, SIOCGIFCONF, &ifc) < 0) {
			perror("SIOCGIFCONF");
			goto out;
		}
		if (ifc.ifc_len == (int)(sizeof(struct ifreq) * numreqs)) {
			/* assume it overflowed and try again */
			numreqs += 10;
			continue;
		}
		break;
	}

	ifr = ifc.ifc_req;
	for (n = 0; n < ifc.ifc_len; n += sizeof(struct ifreq), ifr++) {
		br_add_interface (br, ifr->ifr_name);
	}
	err = 0;

out:
	free(ifc.ifc_buf);
	return err;
}

int stp_set_bridge_times (int fdly, int maxage, int htime, uint16_t vlan_id)
{
}

int cparser_cmd_show_spanning_tree(void *context UNUSED_PARAM)
{
	if (!show_spanning_tree ())
		return CMD_SUCCESS;
	return CMD_WARNING;
}
int cparser_cmd_config_spanning_tree(void *context UNUSED_PARAM)
{
	return spanning_tree_enable (STP_DEFAULT_INSTANCE);
}
int cparser_cmd_config_spanning_tree_priority_priority(void *context UNUSED_PARAM, int32_t *priority_ptr)
{
	return CMD_WARNING;
}

int cparser_cmd_config_no_spanning_tree_priority_priority(void *context UNUSED_PARAM, int32_t *priority_ptr)
{
	*priority_ptr = STP_DEF_PRIORITY;
//	if (!stp_set_bridge_priority (*priority_ptr, cli_get_vlan_id ()))
//		return CMD_SUCCESS;
	return CMD_WARNING;
}

int cparser_cmd_config_spanning_tree_hello_time_htimesecs_forward_delay_fdlysecs_max_age_maxagesecs (
    void *context UNUSED_PARAM,
    int32_t *htimesecs_ptr,
    int32_t *fdlysecs_ptr,
    int32_t *maxagesecs_ptr)
{
	if (!fdlysecs_ptr && !maxagesecs_ptr) 
	{
	//	if (!stp_set_bridge_hello_time (*htimesecs_ptr, cli_get_vlan_id ()))
	//		return CMD_SUCCESS;
		return CMD_WARNING;
	}

        if (*htimesecs_ptr < STP_MIN_HELLO_TIME || *htimesecs_ptr > STP_MAX_HELLO_TIME)
        {
                printf ("Invaild Spanning tree Hello time. Valid range %d-%d\n",
                        STP_MIN_HELLO_TIME, STP_MAX_HELLO_TIME);
		return CMD_WARNING;
        }

	if (fdlysecs_ptr) {
		if (*fdlysecs_ptr < STP_MIN_FORWARD_DELAY || *fdlysecs_ptr > STP_MAX_FORWARD_DELAY) {
			printf ("Invaild Spanning tree Forward Delay. Valid range %d-%d\n",
				STP_MIN_FORWARD_DELAY, STP_MAX_FORWARD_DELAY);
			return CMD_WARNING;
		}
	}
	
	if (maxagesecs_ptr) {
		if (*maxagesecs_ptr < STP_MIN_MAX_AGE || *maxagesecs_ptr > STP_MAX_MAX_AGE)         {
			printf ("Invaild Spanning tree max age. Valid range %d-%d\n",
				STP_MIN_MAX_AGE, STP_MAX_MAX_AGE);
			return CMD_WARNING;
		}
	}

	if (!stp_set_bridge_times ((fdlysecs_ptr? *fdlysecs_ptr : -1), (maxagesecs_ptr? *maxagesecs_ptr : -1),
				  (htimesecs_ptr? *htimesecs_ptr : -1), 1))
		return CMD_WARNING;
	return CMD_WARNING;
}

int cparser_cmd_config_spanning_tree_forward_delay_fdlysecs_max_age_maxagesecs_hello_time_htimesecs(
    void *context UNUSED_PARAM,
    int32_t *fdlysecs_ptr,
    int32_t *maxagesecs_ptr,
    int32_t *htimesecs_ptr)
{
	if (!htimesecs_ptr && !maxagesecs_ptr) 
	{
	//	if (!stp_set_bridge_forward_delay (*fdlysecs_ptr, cli_get_vlan_id ()))
	//		return CMD_SUCCESS;
		return CMD_WARNING;
	}

	if (*fdlysecs_ptr < STP_MIN_FORWARD_DELAY || *fdlysecs_ptr > STP_MAX_FORWARD_DELAY) {
		printf ("Invaild Spanning tree Forward Delay. Valid range %d-%d\n",
			STP_MIN_FORWARD_DELAY, STP_MAX_FORWARD_DELAY);
		return CMD_WARNING;
	}


	if (htimesecs_ptr) {
		if (*htimesecs_ptr < STP_MIN_HELLO_TIME || *htimesecs_ptr > STP_MAX_HELLO_TIME)
		{
			printf ("Invaild Spanning tree Hello time. Valid range %d-%d\n",
					STP_MIN_HELLO_TIME, STP_MAX_HELLO_TIME);
			return CMD_WARNING;
		}
	}

	
	if (maxagesecs_ptr) {
		if (*maxagesecs_ptr < STP_MIN_MAX_AGE || *maxagesecs_ptr > STP_MAX_MAX_AGE)         {
			printf ("Invaild Spanning tree max age. Valid range %d-%d\n",
				STP_MIN_MAX_AGE, STP_MAX_MAX_AGE);
			return CMD_WARNING;
		}
	}

	if (!stp_set_bridge_times ((fdlysecs_ptr? *fdlysecs_ptr : -1), (maxagesecs_ptr? *maxagesecs_ptr : -1),
				  (htimesecs_ptr? *htimesecs_ptr : -1), 1))
		return CMD_WARNING;
	return CMD_WARNING;
}
int cparser_cmd_config_spanning_tree_max_age_maxagesecs_forward_delay_fdlysecs_hello_time_htimesecs(
    void *context UNUSED_PARAM,
    int32_t *maxagesecs_ptr,
    int32_t *fdlysecs_ptr,
    int32_t *htimesecs_ptr)
{
        if (!fdlysecs_ptr && !htimesecs_ptr)
        {
          //      if (!stp_set_bridge_max_age (*maxagesecs_ptr, cli_get_vlan_id ()))
            //            return CMD_SUCCESS;
                return CMD_WARNING;
        }

	if (*maxagesecs_ptr < STP_MIN_MAX_AGE || *maxagesecs_ptr > STP_MAX_MAX_AGE)         {
		printf ("Invaild Spanning tree max age. Valid range %d-%d\n",
				STP_MIN_MAX_AGE, STP_MAX_MAX_AGE);
		return CMD_WARNING;
	}

        if (fdlysecs_ptr) {
                if (*fdlysecs_ptr < STP_MIN_FORWARD_DELAY || *fdlysecs_ptr > STP_MAX_FORWARD_DELAY) {
                        printf ("Invaild Spanning tree Forward Delay. Valid range %d-%d\n",
                                STP_MIN_FORWARD_DELAY, STP_MAX_FORWARD_DELAY);
                        return CMD_WARNING;
                }
        }

        if (htimesecs_ptr) {
                if (*htimesecs_ptr < STP_MIN_HELLO_TIME || *htimesecs_ptr > STP_MAX_HELLO_TIME)
                {
                        printf ("Invaild Spanning tree Hello time. Valid range %d-%d\n",
                                        STP_MIN_HELLO_TIME, STP_MAX_HELLO_TIME);
                        return CMD_WARNING;
                }
        }

	if (!stp_set_bridge_times ((fdlysecs_ptr? *fdlysecs_ptr : -1), (maxagesecs_ptr? *maxagesecs_ptr : -1),
				  (htimesecs_ptr? *htimesecs_ptr : -1), 1))
		return CMD_WARNING;
	return CMD_WARNING;
}
int cparser_cmd_config_spanning_tree_ethernet_portnum_path_cost_cost(void *context UNUSED_PARAM,
    int32_t *portnum_ptr,
    int32_t *cost_ptr)
{
	return CMD_WARNING;
}
int cparser_cmd_config_spanning_tree_ethernet_portnum_priority_priority(void *context UNUSED_PARAM,
    int32_t *portnum_ptr,
    int32_t *priority_ptr)
{
	return CMD_WARNING;
}
int cparser_cmd_config_no_spanning_tree(void *context UNUSED_PARAM)
{
	return spanning_tree_disable (STP_DEFAULT_INSTANCE);
}

int  show_spanning_tree  (void)
{
	struct stp_instance *pstp_inst = NULL;

	show_bridge (STP_DEFAULT_INSTANCE, NULL);

#if 0
	list_for_each_entry(pstp_inst, &stp_instance_head, next) {

		if (pstp_inst->stp_enabled) {

			uint8_t *mac = NULL;
			struct stp_port_entry *p =  NULL;

			int is_root = stp_is_root_bridge (pstp_inst);

			printf ("\n  Spanning tree enabled protocol ieee on\n");
			printf ("  -------------------------------------- \n\n");

			printf ("  VLAN  : %d\n\n", pstp_inst->vlan_id);

			printf ("  Root ID\n\tPriority    %d\n", pstp_inst->designated_root.prio);

			mac = pstp_inst->designated_root.addr;

			printf ("\tAddress     %02x:%02x:%02x:%02x:%02x:%02x\n", 
				mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

			if (is_root)  {
				printf ("\tThis bridge is the root\n");
			}

			printf ("\tHello Time  %d sec  Max Age %d sec  Forward Delay %d sec\n\n",
					pstp_inst->hello_time, pstp_inst->max_age, pstp_inst->forward_delay);

			printf ("  Bridge ID\n\tPriority    %d\n",pstp_inst->bridge_id.prio);

			mac = pstp_inst->bridge_id.addr;

			printf ("\tAddress     %02x:%02x:%02x:%02x:%02x:%02x\n", 
					mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
			printf ("\tHello Time  %d sec  Max Age %d sec  Forward Delay %d sec\n",
				pstp_inst->bridge_hello_time, pstp_inst->bridge_max_age, 
				pstp_inst->bridge_forward_delay);

			if (!is_root) {
				printf ("\n\tRoot Port : %d\n", pstp_inst->root_port);
			}

			if (!list_empty (&pstp_inst->port_list)) {
				const char *state[] = {"DISABLED", "LISTENING", "LEARNING", 
					               "FORWARDING", "BLOCKING"};
				printf ("\nPort   Cost     State      Bridge Id         Prio \n");
				printf ("----   -----   ------   -----------------    ------\n");
				list_for_each_entry(p, &pstp_inst->port_list, list) {
					mac = p->designated_bridge.addr;
					printf ("%2d   %4d   %10s   %02x:%02x:%02x:%02x:%02x:%02x  %4d\n",
						p->port_no, p->path_cost, state[p->state],
						mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],p->priority);
				}
			} 	
		}
		else {
			printf ("\n  Spanning tree not enabled on");
			printf (" VLAN  : %d\n\n", pstp_inst->vlan_id);
		}
	}
#endif
	return 0;
}

int spanning_tree_enable (char *br_name)
{
	if (br_add_bridge (br_name))
		return CMD_WARNING;
	br_set_stp_state (br_name, 1);
	add_interfaces_to_bridge (br_name);
	return CMD_SUCCESS;
}
int spanning_tree_disable (char *br_name)
{
	if (br_del_bridge (br_name))
		return CMD_WARNING;
	return CMD_SUCCESS;
}
int set_spanning_bridge_port_path_cost (uint32_t path_cost, uint32_t portnum)
{
#if 0
	struct stp_instance *br = get_this_bridge_entry (cli_get_vlan_id ());
	struct stp_port_entry *p = NULL;

	if (!br)
	{
		printf ("Spanning-tree not enabled\n");
		return -1;
	}

	if (!(p = stp_get_port_info (br, portnum)))
	{
		printf ("Invalid Port Number\n");
		return -1;
	}
#endif
	if (path_cost < STP_MIN_PATH_COST || path_cost > STP_MAX_PATH_COST)
	{
		printf ("Invaild spanning tree port path-cost. Valid range %d-%d\n", 
			STP_MIN_PATH_COST, STP_MAX_PATH_COST);
		return -1;
	}

	return 0;
}

int set_spanning_bridge_port_prio (uint32_t prio, uint32_t portnum)
{
#if 0
	struct stp_instance *br = get_this_bridge_entry (cli_get_vlan_id ());
	struct stp_port_entry *p = NULL;

	if (!br)
	{
		printf ("Spanning-tree not enabled\n");
		return -1;
	}

	if (!(p = stp_get_port_info (br, portnum)))
	{
		printf ("Invalid Port Number\n");
		return -1;
	}
#endif
	if (prio > STP_MAX_PORT_PRIORITY)
	{
		printf ("Invaild spanning tree port priority. Valid Range 0-240\n");
		return -1;
	}

//	stp_set_port_priority (p, prio);

	return 0;
}
