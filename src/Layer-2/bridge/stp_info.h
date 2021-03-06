#include "common_types.h"
#include "list.h"

#define BPDU_PROTOCOL_ID        0x00
#define BPDU_VERSION_ID         0x00
#define BPDU_TC_TYPE            0x80
#define BPDU_CONFIG_TYPE        0x00
#define TC_BIT     0x01
#define TC_ACK_BIT 0x80

#define DISABLED 0
#define LISTENING 1
#define LEARNING 2
#define FORWARDING 3
#define BLOCKING 4

#define STP_ENABLED 1
#define STP_DISABLED 0

#define MESSAGE_AGE_INCR 1

/*802.1D STP compatibility Range*/
#define STP_MIN_BRIDGE_PRIORITY 0
#define STP_MAX_BRIDGE_PRIORITY 65535

#define STP_MIN_PORT_PRIORITY 0
#define STP_MAX_PORT_PRIORITY 240

#define STP_MIN_PATH_COST 1
#define STP_MAX_PATH_COST 200000000

#define STP_MIN_HELLO_TIME 1
#define STP_MAX_HELLO_TIME 10

#define STP_MIN_MAX_AGE  6
#define STP_MAX_MAX_AGE  40

#define STP_MIN_FORWARD_DELAY  2
#define STP_MAX_FORWARD_DELAY 30

enum STP_PROTO_SPEC {
	UNKNOWN = 1,
	DEClB100 = 2,
	IEEE8021D = 3
};

#define STP_MAX_MSG    100

/*modify the following macros*/
#define STP_PORT_BITS	10
#define STP_MAX_PORTS	(1 << STP_PORT_BITS)
#define debug_stp(fmt)   if (1) printf("STP: %s", fmt);

#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */

struct stp_instance {
	int64_t     tolpolgy_changes;
	struct list_head next;
	struct list_head port_list;
	int32_t     protocol_spec;
	int32_t     stp_enabled;
	int32_t     priority;
	TIMESTMP    timesinceTC;
	BRIDGEID    designated_root;
	BRIDGEID    bridge_id;
	TIMEOUT     max_age;
	TIMEOUT     hello_time;
	TIMEOUT     forward_delay;
	TIMEOUT     bridge_max_age;
	TIMEOUT     bridge_hello_time;
	TIMEOUT     bridge_forward_delay;
        TIMER_ID    hello_timer;
        TIMER_ID    tcn_timer;
        TIMER_ID    topology_change_timer;
	int32_t     root_path_cost;
	int32_t     hold_time;
	PORT        root_port;
	uint16_t   vlan_id;
        uint8_t     topology_change;
        uint8_t     topology_change_detected;
};

struct stp_port_entry {
        uint64_t    fwdtransitions;
	struct list_head list;
	struct stp_instance *br;
        TIMER_ID    forward_delay_timer;
        TIMER_ID    hold_timer;
        TIMER_ID    message_age_timer;
        PORT        port_no;
	int32_t     designated_age;
        int32_t     priority;
        int32_t     state;
        int32_t     designated_cost;
        int32_t     path_cost;
        BRIDGEID    designated_root;
        BRIDGEID    designated_bridge;
        uint16_t    designated_port;
	uint16_t    port_id;
	uint8_t     topology_change_ack;
        uint8_t	    config_pending;
	uint8_t     is_own_bpdu;
        uint8_t     enabled;
};

struct stp_hdr {
  uint16_t protocol;
  uint8_t  version;
  uint8_t  type;
/*****************************************/
  uint8_t  flags;
  BRIDGEID root_id;
  int32_t  root_path_cost;
  BRIDGEID bridge_id;
  uint16_t port_id;
  uint16_t message_age;
  uint16_t max_age;
  uint16_t hello_time;
  uint16_t  forward_delay;
}STP_HDR_T;



typedef struct stp_bpdu {
/*****************************************
 * Params common for the CONF and TC BPDU*
 * ***************************************/
  MACHDR   mac_hdr;
  LLCHDR   llc_hdr;
  uint16_t protocol;
  uint8_t  version;
  uint8_t  type;
/*****************************************/
  uint8_t  flags;
  BRIDGEID root_id;
  int32_t  root_path_cost;
  BRIDGEID bridge_id;
  uint16_t port_id;
  uint16_t message_age;
  uint16_t max_age;
  uint16_t hello_time;
  uint16_t  forward_delay;
} STP_BPDU_T;

#pragma pack(pop)   /* restore original alignment from stack */
extern bridge_group_t   this_bridge;
extern port_entry_t     this_bridge_ports[];
extern char switch_mac[];
extern struct stp_instance stp_global_instance;


int stp_process_bpdu (STP_BPDU_T *bpdu, uint16_t port);
struct stp_port_entry *stp_get_port(struct stp_instance *br, uint16_t port_no);
int stp_is_root_bridge(const struct stp_instance *br);
void stp_topology_change_detection(struct stp_instance *br);
void stp_config_bpdu_generation(struct stp_instance *br);
void stp_become_designated_port(struct stp_port_entry *p);
void stp_received_config_bpdu(struct stp_port_entry *p, STP_BPDU_T *bpdu);
void stp_received_tcn_bpdu(struct stp_port_entry *p);
void stp_send_tcn_bpdu(struct stp_port_entry *p);
int stp_task (void *arg);
int stp_process_events (int port, uint8_t event, int);
int vlan_get_this_bridge_stp_mode  (int vlanid);
struct stp_port_entry * stp_get_port_entry (uint16_t port);
int stp_is_designated_port(const struct stp_port_entry *p);
void stp_become_root_bridge(struct stp_instance *br);
void stp_transmit_config(struct stp_port_entry *p);
void stp_send_config_bpdu(struct stp_port_entry *p, STP_BPDU_T *bpdu);
int llc_mac_hdr_init (uint8_t *pkt, const uint8_t *daddr, const uint8_t *saddr, int type, int len);
void llc_pdu_header_init(uint8_t *pkt, uint8_t type, uint8_t ssap, uint8_t dsap, uint8_t cr);
void llc_pdu_init_as_ui_cmd(uint8_t *pkt);
void stp_configuration_update(struct stp_instance *br);
void stp_port_state_selection(struct stp_instance *br);
void stp_enable (struct stp_instance *br);
void stp_disable (struct stp_instance *br);
void stp_enable_port(struct stp_port_entry *p);
void stp_disable_port(struct stp_port_entry *p);
int stp_set_bridge_priority (uint16_t newprio, uint16_t vlan_id);
void stp_change_bridge_id(struct stp_instance *br, const char *addr);
int stp_set_bridge_hello_time (int hello , uint16_t vlan_id);
int stp_set_bridge_forward_delay (int fwd_dly , uint16_t vlan_id);
int stp_set_bridge_max_age (int max_age , uint16_t vlan_id);
void stp_set_port_priority (struct stp_port_entry *p, uint8_t newprio);
void stp_set_path_cost(struct stp_port_entry *p, uint32_t path_cost);
int stp_enable_or_disable_port (int port, int state);
void stp_timer_init(struct stp_instance *br);
void stp_port_timer_init(struct stp_port_entry *p);
void stp_transmit_tcn(struct stp_instance *br);
struct stp_port_entry *  stp_get_port_info (struct stp_instance *stp_inst, uint32_t port);
int stp_set_bridge_times (int fdly, int maxage, int htime, uint16_t vlan_id);
