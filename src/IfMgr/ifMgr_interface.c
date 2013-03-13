#include <zebra.h>

#include "command.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "memory.h"
#include "network.h"
#include "table.h"
#include "log.h"
#include "stream.h"
#include "thread.h"
#include "zclient.h"
#include "filter.h"
#include "sockopt.h"
#include "privs.h"
#include "vtysh.h"
#include "libclient.h"
#include "libserv.h"
#include "linklist.h"


/* static prototypes */
/* For interface multicast configuration. */
#define IF_ZEBRA_MULTICAST_UNSPEC 0
#define IF_ZEBRA_MULTICAST_ON     1
#define IF_ZEBRA_MULTICAST_OFF    2

/* For interface shutdown configuration. */
#define IF_ZEBRA_SHUTDOWN_UNSPEC 0
#define IF_ZEBRA_SHUTDOWN_ON     1
#define IF_ZEBRA_SHUTDOWN_OFF    2



extern struct zebra_privs_t ifMgrd_privs;
vector ifMgr_enable_interface;

/* This will be executed when interface goes up. */
static void
ifMgr_request_interface (struct interface *ifp)
{
  /* In default ifMgrd doesn't send RIP_REQUEST to the loopback interface. */
  if (if_is_loopback (ifp))
    return;

  /* If interface is down, don't send RIP packet. */
  if (! if_is_operative (ifp))
    return;


}

/* Multicast packet receive socket. */
int
ifMgr_interface_down (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;

  s = zclient->ibuf;  

  /* zebra_interface_state_read() updates interface structure in
     iflist. */
  ifp = zebra_interface_state_read(s);

  if (ifp == NULL)
    return 0;

  ifMgr_if_down(ifp);
 
  if (0)
    zlog_debug ("interface %s index %d flags %llx metric %d mtu %d is down",
	       ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
	       ifp->metric, ifp->mtu);

  return 0;
}

/* Inteface link up message processing */
int
ifMgr_interface_up (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  /* zebra_interface_state_read () updates interface structure in
     iflist. */
  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

//  if (STP_DEBUG)
    zlog_debug ("interface %s index %d flags %#llx metric %d mtu %d is up",
	       ifp->name, ifp->ifindex, (unsigned long long) ifp->flags,
	       ifp->metric, ifp->mtu);

  return 0;
}

/* Inteface addition message from zebra. */
int
ifMgr_interface_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

//  if (IS_RIP_DEBUG_ZEBRA)
    zlog_debug ("interface add %s index %d flags %#llx metric %d mtu %d",
		ifp->name, ifp->ifindex, (unsigned long long) ifp->flags,
		ifp->metric, ifp->mtu);

  return 0;
}

int
ifMgr_interface_delete (int command, struct zclient *zclient,
		      zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;


  s = zclient->ibuf;  
  /* zebra_interface_state_read() updates interface structure in iflist */
  ifp = zebra_interface_state_read(s);

  if (ifp == NULL)
    return 0;

  if (if_is_up (ifp)) {
    //ifMgr_if_down(ifp);
  } 
  
  zlog_info("interface delete %s index %d flags %#llx metric %d mtu %d",
	    ifp->name, ifp->ifindex, (unsigned long long) ifp->flags,
	    ifp->metric, ifp->mtu);
  
  /* To support pseudo interface do not free interface structure.  */
  /* if_delete(ifp); */
  ifp->ifindex = IFINDEX_INTERNAL;

  return 0;
}

void
ifMgr_interface_clean (void)
{
  struct listnode *node;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
    }
}

void
ifMgr_interface_reset (void)
{
  struct listnode *node;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
    }
}

int
ifMgr_if_down(struct interface *ifp)
{
  return 0;
}

/* Needed for stop RIP process. */
void
ifMgr_if_down_all ()
{
  struct interface *ifp;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (iflist, node, nnode, ifp))
    ifMgr_if_down (ifp);
}


static int
ifMgr_enable_if_lookup (const char *ifname)
{
  unsigned int i;
  char *str;

  for (i = 0; i < vector_active (ifMgr_enable_interface); i++)
    if ((str = vector_slot (ifMgr_enable_interface, i)) != NULL)
      if (strcmp (str, ifname) == 0)
	return i;
  return -1;
}

/* Add interface to ifMgr_enable_if. */
static int
ifMgr_enable_if_add (const char *ifname)
{
  int ret;

  ret = ifMgr_enable_if_lookup (ifname);
  if (ret >= 0)
    return -1;

  vector_set (ifMgr_enable_interface, strdup (ifname));


  return 1;
}

/* Delete interface from ifMgr_enable_if. */
static int
ifMgr_enable_if_delete (const char *ifname)
{
  int index;
  char *str;

  index = ifMgr_enable_if_lookup (ifname);
  if (index < 0)
    return -1;

  str = vector_slot (ifMgr_enable_interface, index);
  free (str);
  vector_unset (ifMgr_enable_interface, index);

  return 1;
}

/* Join to multicast group and send request to the interface. */
static int
ifMgr_interface_wakeup (struct thread *t)
{
  struct interface *ifp;

  /* Get interface. */
  ifp = THREAD_ARG (t);

  return 0;
}

/* Write ifMgr configuration of each interface. */
static int
ifMgr_interface_config_write (struct vty *vty)
{
  return 0;
}

static struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
  1,
};

/* Called when interface structure allocated. */
static int
ifMgr_interface_new_hook (struct interface *ifp)
{
  return 0;
}

/* Called when interface structure deleted. */
static int
ifMgr_interface_delete_hook (struct interface *ifp)
{
  ifp->info = NULL;
  return 0;
}

void
if_refresh (struct interface *ifp)
{
  //if_get_flags (ifp);
}

/* Output prefix string to vty. */
static int
prefix_vty_out (struct vty *vty, struct prefix *p)
{
  char str[INET6_ADDRSTRLEN];

  inet_ntop (p->family, &p->u.prefix, str, sizeof (str));
  vty_out (vty, "%s", str);
  return strlen (str);
}


/* Wrapper hook point for zebra daemon so that ifindex can be set 
 * DEFUN macro not used as extract.pl HAS to ignore this
 * See also interface_cmd in lib/if.c
 */ 
DEFUN_NOSH (zebra_interface,
	    zebra_interface_cmd,
	    "interface IFNAME",
	    "Select an interface to configure\n"
	    "Interface's name\n")
{
  int ret;
  struct interface * ifp;
  
  /* Call lib interface() */
  if ((ret = interface_cmd.func (self, vty, argc, argv)) != CMD_SUCCESS)
    return ret;

  ifp = vty->index;  

  if (ifp->ifindex == IFINDEX_INTERNAL)
    /* Is this really necessary?  Shouldn't status be initialized to 0
       in that case? */
    UNSET_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE);

  return ret;
}

/* Show all or specified interface to vty. */
DEFUN (show_interface, show_interface_cmd,
       "show interface [IFNAME]",  
       SHOW_STR
       "Interface status and configuration\n"
       "Inteface name\n")
{
#if 0
  struct listnode *node;
  struct interface *ifp;
  
#ifdef HAVE_PROC_NET_DEV
  /* If system has interface statistics via proc file system, update
     statistics. */
  ifstat_update_proc ();
#endif /* HAVE_PROC_NET_DEV */
#ifdef HAVE_NET_RT_IFLIST
  ifstat_update_sysctl ();
#endif /* HAVE_NET_RT_IFLIST */

  /* Specified interface print. */
  if (argc != 0)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (ifp == NULL) 
	{
	  vty_out (vty, "%% Can't find interface %s%s", argv[0],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if_dump_vty (vty, ifp);
      return CMD_SUCCESS;
    }

  /* All interface print. */
  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    if_dump_vty (vty, ifp);
#endif
  vty_out (vty, "Fixme: %s UnderDevelopment%s", argv[0], VTY_NEWLINE);
  return CMD_SUCCESS;
}
DEFUN (show_interface_desc,
       show_interface_desc_cmd,
       "show interface description",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface description\n")
{
  struct listnode *node;
  struct interface *ifp;

  vty_out (vty, "Interface       Status  Protocol  Description%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
      int len;

      len = vty_out (vty, "%s", ifp->name);
      vty_out (vty, "%*s", (16 - len), " ");
      
      if (if_is_up(ifp))
	{
	  vty_out (vty, "up      ");
	  if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
	    {
	      if (if_is_running(ifp))
		vty_out (vty, "up        ");
	      else
		vty_out (vty, "down      ");
	    }
	  else
	    {
	      vty_out (vty, "unknown   ");
	    }
	}
      else
	{
	  vty_out (vty, "down    down      ");
	}

      if (ifp->desc)
	vty_out (vty, "%s", ifp->desc);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (multicast,
       multicast_cmd,
       "multicast",
       "Set multicast flag to interface\n")
{
  int ret;
  struct interface *ifp;
#if 0

  ifp = (struct interface *) vty->index;
  if (CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
      ret = if_set_flags (ifp, IFF_MULTICAST);
      if (ret < 0)
	{
	  vty_out (vty, "Can't set multicast flag%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if_refresh (ifp);
    }
#endif
  vty_out (vty, "Fixme: UnderDevelopment%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (no_multicast,
       no_multicast_cmd,
       "no multicast",
       NO_STR
       "Unset multicast flag to interface\n")
{

  return CMD_SUCCESS;
}

DEFUN (linkdetect,
       linkdetect_cmd,
       "link-detect",
       "Enable link detection on interface\n")
{
  struct interface *ifp;
  int if_was_operative;
  
  ifp = (struct interface *) vty->index;
  if_was_operative = if_is_operative(ifp);
  SET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

  /* When linkdetection is enabled, if might come down */
  if (!if_is_operative(ifp) && if_was_operative) if_down(ifp);

  /* FIXME: Will defer status change forwarding if interface
     does not come down! */

  return CMD_SUCCESS;
}


DEFUN (no_linkdetect,
       no_linkdetect_cmd,
       "no link-detect",
       NO_STR
       "Disable link detection on interface\n")
{
  struct interface *ifp;
  int if_was_operative;

  ifp = (struct interface *) vty->index;
  if_was_operative = if_is_operative(ifp);
  UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);
  
  /* Interface may come up after disabling link detection */
  if (if_is_operative(ifp) && !if_was_operative) if_up(ifp);

  /* FIXME: see linkdetect_cmd */

  return CMD_SUCCESS;
}

DEFUN (shutdown_if,
       shutdown_if_cmd,
       "shutdown",
       "Shutdown the selected interface\n")
{
  int ret;
  struct interface *ifp;
#if 0
  ifp = (struct interface *) vty->index;
  ret = if_unset_flags (ifp, IFF_UP);
  if (ret < 0)
    {
      vty_out (vty, "Can't shutdown interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if_refresh (ifp);
#endif
#if 0
extern struct server_t serverd;
  struct stream *s;
  struct listnode *node;
  struct client *client;
  for (ALL_LIST_ELEMENTS_RO (serverd.client_list, node, client)) {
	  s = client->obuf;
	  stream_reset (s);
	  server_create_header (s, 1);
	  server_send_message(client);
  }
#endif
  vty_out (vty, "Fixme: UnderDevelopment%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (no_shutdown_if,
       no_shutdown_if_cmd,
       "no shutdown",
       NO_STR
       "Shutdown the selected interface\n")
{
#if 0
  int ret;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  ret = if_set_flags (ifp, IFF_UP | IFF_RUNNING);
  if (ret < 0)
    {
      vty_out (vty, "Can't up interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if_refresh (ifp);
#endif
  vty_out (vty, "Fixme: UnderDevelopment%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (bandwidth_if,
       bandwidth_if_cmd,
       "bandwidth <1-10000000>",
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")
{
  struct interface *ifp;   
  unsigned int bandwidth;
  
  ifp = (struct interface *) vty->index;
  bandwidth = strtol(argv[0], NULL, 10);

  /* bandwidth range is <1-10000000> */
  if (bandwidth < 1 || bandwidth > 10000000)
    {
      vty_out (vty, "Bandwidth is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  ifp->bandwidth = bandwidth;

  /* force protocols to recalculate routes due to cost change */
//  if (if_is_operative (ifp))
 //   zebra_interface_up_update (ifp);
  
  return CMD_SUCCESS;
}

DEFUN (no_bandwidth_if,
       no_bandwidth_if_cmd,
       "no bandwidth",
       NO_STR
       "Set bandwidth informational parameter\n")
{
  struct interface *ifp;   
  
  ifp = (struct interface *) vty->index;

  ifp->bandwidth = 0;
  
  /* force protocols to recalculate routes due to cost change */
  //if (if_is_operative (ifp))
  //  zebra_interface_up_update (ifp);

  return CMD_SUCCESS;
}

ALIAS (no_bandwidth_if,
       no_bandwidth_if_val_cmd,
       "no bandwidth <1-10000000>",
       NO_STR
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")

static int
ip_address_install (struct vty *vty, struct interface *ifp,
		    const char *addr_str, const char *peer_str,
		    const char *label)
{
  return CMD_SUCCESS;
}

static int
ip_address_uninstall (struct vty *vty, struct interface *ifp,
		      const char *addr_str, const char *peer_str,
		      const char *label)
{
  /* Redistribute this information. */
//  zebra_interface_address_delete_update (ifp, ifc);

  return CMD_SUCCESS;
}

DEFUN (ip_address,
       ip_address_cmd,
       "ip address A.B.C.D/M",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n")
{
  return ip_address_install (vty, vty->index, argv[0], NULL, NULL);
}

DEFUN (no_ip_address,
       no_ip_address_cmd,
       "no ip address A.B.C.D/M",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP Address (e.g. 10.0.0.1/8)")
{
  return ip_address_uninstall (vty, vty->index, argv[0], NULL, NULL);
}

#ifdef HAVE_NETLINK
DEFUN (ip_address_label,
       ip_address_label_cmd,
       "ip address A.B.C.D/M label LINE",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n"
       "Label of this address\n"
       "Label\n")
{
  return ip_address_install (vty, vty->index, argv[0], NULL, argv[1]);
}

DEFUN (no_ip_address_label,
       no_ip_address_label_cmd,
       "no ip address A.B.C.D/M label LINE",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n"
       "Label of this address\n"
       "Label\n")
{
  return ip_address_uninstall (vty, vty->index, argv[0], NULL, argv[1]);
}
#endif /* HAVE_NETLINK */

#ifdef HAVE_IPV6
static int
ipv6_address_install (struct vty *vty, struct interface *ifp,
		      const char *addr_str, const char *peer_str,
		      const char *label, int secondary)
{
//      zebra_interface_address_add_update (ifp, ifc);

  return CMD_SUCCESS;
}

static int
ipv6_address_uninstall (struct vty *vty, struct interface *ifp,
			const char *addr_str, const char *peer_str,
			const char *label, int secondry)
{
  /* Redistribute this information. */
//  zebra_interface_address_delete_update (ifp, ifc);


  return CMD_SUCCESS;
}

DEFUN (ipv6_address,
       ipv6_address_cmd,
       "ipv6 address X:X::X:X/M",
       "Interface IPv6 config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
  return ipv6_address_install (vty, vty->index, argv[0], NULL, NULL, 0);
}

DEFUN (no_ipv6_address,
       no_ipv6_address_cmd,
       "no ipv6 address X:X::X:X/M",
       NO_STR
       "Interface IPv6 config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
  return ipv6_address_uninstall (vty, vty->index, argv[0], NULL, NULL, 0);
}
#endif /* HAVE_IPV6 */

/* Allocate and initialize interface vector. */
void
ifMgr_if_init (void)
{
  /* Default initial size of interface vector. */
  if_add_hook (IF_NEW_HOOK, ifMgr_interface_new_hook);
  if_add_hook (IF_DELETE_HOOK, ifMgr_interface_delete_hook);
  
  /* Install configuration write function. */
  install_node (&interface_node, ifMgr_interface_config_write);

  install_element (VIEW_NODE, &show_interface_cmd);
  install_element (ENABLE_NODE, &show_interface_cmd);
  install_element (ENABLE_NODE, &show_interface_desc_cmd);
  install_element (CONFIG_NODE, &zebra_interface_cmd);
  install_element (CONFIG_NODE, &no_interface_cmd);
  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &multicast_cmd);
  install_element (INTERFACE_NODE, &no_multicast_cmd);
  install_element (INTERFACE_NODE, &linkdetect_cmd);
  install_element (INTERFACE_NODE, &no_linkdetect_cmd);
  install_element (INTERFACE_NODE, &shutdown_if_cmd);
  install_element (INTERFACE_NODE, &no_shutdown_if_cmd);
  install_element (INTERFACE_NODE, &bandwidth_if_cmd);
  install_element (INTERFACE_NODE, &no_bandwidth_if_cmd);
  install_element (INTERFACE_NODE, &no_bandwidth_if_val_cmd);
  install_element (INTERFACE_NODE, &ip_address_cmd);
  install_element (INTERFACE_NODE, &no_ip_address_cmd);
#ifdef HAVE_IPV6
  install_element (INTERFACE_NODE, &ipv6_address_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_address_cmd);
#endif /* HAVE_IPV6 */
#ifdef HAVE_NETLINK
  install_element (INTERFACE_NODE, &ip_address_label_cmd);
  install_element (INTERFACE_NODE, &no_ip_address_label_cmd);
#endif /* HAVE_NETLINK */

}
