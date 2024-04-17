#include "inspector.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

int GetFileDescriptor() {
    return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
}