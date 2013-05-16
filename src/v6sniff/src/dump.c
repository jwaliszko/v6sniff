#include "stdhdr.h"
#include "dump.h"
#include "frame.h"

void dump_ether_header(const u_char *pkt_data)
{
	struct ether_header *eth = (struct ether_header *) pkt_data;

	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet II\n");
	fprintf(logfile, "   |-Destination: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
	fprintf(logfile, "   |-Source: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
	fprintf(logfile, "   |-Type: 0x%x \n", ntohs(eth->type));
	fprintf(logfile, "\n");

	dump_hex_data(pkt_data,sizeof(struct ether_header));
}

void dump_ipv6_header(const u_char *pkt_data)
{
	u_int8_t class;
	u_int32_t flow;

	struct ipv6_header *iph = (struct ipv6_header *) (pkt_data + sizeof(struct ether_header));
	class = iph->traffic_class_high * 16 + iph->traffic_class_low;
	flow = iph->flow_label_high * 65536 + ntohs(iph->flow_label_low);

	fprintf(logfile, "\n");
	fprintf(logfile, "Internet Protocol Version 6\n");
	fprintf(logfile, "   |-Version: %d\n", iph->version);
	fprintf(logfile, "   |-Traffic class: 0x%x\n", class);
	fprintf(logfile, "   |-Flow label: 0x%x\n", flow);
	fprintf(logfile, "   |-Payload length: %d\n", ntohs(iph->payload_length));
	fprintf(logfile, "   |-Next header: 0x%x\n", iph->next_header);
	fprintf(logfile, "   |-Hop limit: %d\n", iph->hop_limit);
	display_ipv6_address("   |-Source: ", &(iph->src_addr));
	display_ipv6_address("   |-Destination: ", &(iph->dst_addr));
	fprintf(logfile, "\n");

	dump_hex_data(pkt_data + sizeof(struct ether_header), sizeof(struct ipv6_header));
}

void dump_hex_data(const u_char *pkt_data, int size)
{
	int i , j;
	for(i=0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(pkt_data[j]>=32 && pkt_data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)pkt_data[j]); //if its a number or alphabet

				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		}

		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02x",(unsigned int)pkt_data[i]);

		if( i==size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++)
			{
			  fprintf(logfile , "   "); //extra spaces
			}

			fprintf(logfile , "         ");

			for(j=i-i%16 ; j<=i ; j++)
			{
				if(pkt_data[j]>=32 && pkt_data[j]<=128)
				{
				  fprintf(logfile , "%c",(unsigned char)pkt_data[j]);
				}
				else
				{
				  fprintf(logfile , ".");
				}
			}

			fprintf(logfile ,  "\n" );
		}
	}
}

void display_ipv6_address(const char *label, struct in6_addr *addr)
{
	int i;
	fprintf(logfile, "%s", label);
	for (i = 0; i < 7; i++)
	{
		fprintf(logfile, "%.1x:", ntohs(addr->_S6_un._S6_u16[i]));
	}
	fprintf(logfile, "%.1x\n", ntohs(addr->_S6_un._S6_u16[7]));
}