#ifndef DUMP_H
#define DUMP_H

FILE *logfile;

void dump_ether_header(const u_char *pkt_data);
void dump_ipv6_header(const u_char *pkt_data);
void dump_hex_data(const u_char *pkt_data, int size);
void display_ipv6_address(const char *label, struct in6_addr *addr);

#endif