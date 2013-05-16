#include "stdhdr.h"
#include "dump.h"
#include "frame.h"

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
u_int16_t ether_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *p);

int ipv6=0,others=0,total=0;

int main(int argc, char *argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
		;

	/* Open the device */
	if ((adhandle = pcap_open(d->name, // name of the device
			65536, // portion of the packet to capture
				   // 65536 guarantees that the whole packet will be captured on all the link layers
			PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
			1000, // read timeout
			NULL, // authentication on the remote machine
			errbuf // error buffer
			)) == NULL)
	{
		fprintf(
				stderr,
				"\nUnable to open the adapter. %s is not supported by WinPcap\n",
				d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	logfile = fopen("dump.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	++total;
	int size = header->len;

	const u_int16_t type = ether_packet(param, header, pkt_data);
	if(ntohs(type) == ETHERTYPE_IPV6)
	{
		++ipv6;
		dump_ether_header(pkt_data);
		dump_ipv6_header(pkt_data);

		fprintf(logfile, "\nPacket dump:\n");
		dump_hex_data(pkt_data, size);
		fprintf(logfile, "\n-----------------------------------------------------------\n");
	}
	else
	{
		++others;
	}

	printf("IPv6: %d, Others: %d, Total: %d\r", ipv6 , others , total);
}

u_int16_t ether_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *p)
{
	struct ether_header *eptr = (struct ether_header*) p;
	assert(pkthdr->caplen <= pkthdr->len);
	assert(pkthdr->caplen >= sizeof(struct ether_header));
	return eptr->type;
}