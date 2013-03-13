#include "zebra.h"
#include "libclient.h"

extern int ifmgr_event_callback_handler (int, struct client *, uint16_t);

struct client *if_client;

void ifmgr_client_init (void)
{
  client_set_port (2611);
  if_client = client_new ();
  client_init (if_client);
  if_client->call_back = ifmgr_event_callback_handler;
}
