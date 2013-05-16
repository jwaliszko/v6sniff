#ifndef FRAME_H
#define FRAME_H

#define ETHERTYPE_IPV6 0x86dd	/* IPv6 protocol */

typedef struct ether_header
{
	u_int8_t dst[6];
	u_int8_t src[6];
	u_int16_t type;
}__attribute__((__packed__)) ether_header_t;

typedef struct ipv6_header
{
#if defined(WORDS_BIGENDIAN)
	u_int8_t version:4, traffic_class_high:4;
	u_int8_t traffic_class_low:4, flow_label_high:4;
#else
	u_int8_t traffic_class_high :4, version :4;
	u_int8_t flow_label_high :4, traffic_class_low :4;
#endif
	u_int16_t flow_label_low;
	u_int16_t payload_length;
	u_int8_t next_header;
	u_int8_t hop_limit;
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
}__attribute__((__packed__)) ipv6_header_t;

#endif