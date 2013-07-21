#include <stdlib.h>
#include <stdio.h>

//#define WPCAP
#define HAVE_REMOTE

#include <pcap.h>

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header */
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

typedef struct tcp_header { 
	u_short sport; 	// Source port 
	u_short dport; 	// Destination port 
	u_int seqnum; 	// Sequence Number 
	u_int acknum; 	// Acknowledgement number 
	u_char th_off; 	// Header length 
	u_char flags; 	// packet flags 
	u_short win; 	// Window size 
	u_short crc; 	// Header Checksum 
	u_short urgptr; // Urgent pointer...still don't know what this is...
}tcp_header; 

/* TCP header */
/*
typedef struct tcp_header_
{
    unsigned short source_port; // source port
    unsigned short dest_port; // destination port
    unsigned int sequence; // sequence number - 32 bits
    unsigned int acknowledge; // acknowledgement number - 32 bits
 
    unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
    unsigned char reserved_part1:3; //according to rfc
    unsigned char data_offset:4; //The number of 32-bit words in the TCP header. This indicates where the data begins. The length of the TCP header is always a multiple of 32 bits.
 
    unsigned char fin :1; //Finish Flag
    unsigned char syn :1; //Synchronise Flag
    unsigned char rst :1; //Reset Flag
    unsigned char psh :1; //Push Flag
    unsigned char ack :1; //Acknowledgement Flag
    unsigned char urg :1; //Urgent Flag
 
    unsigned char ecn :1; //ECN-Echo Flag
    unsigned char cwr :1; //Congestion Window Reduced Flag
 
    ////////////////////////////////
 
    unsigned short window; // window
    unsigned short checksum; // checksum
    unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;
*/


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
	
    /*
     * unused variables
     */
    (VOID)(param);
    (VOID)(pkt_data);

    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
    
    printf("%s,%.6d len:%u (%u)\n", timestr, header->ts.tv_usec, header->len, header->caplen); 
	
	/* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + 14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    /* print ip addresses and udp ports */
    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
}

int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char device[1024];
u_int netmask;
char packet_filter[] = "ip and udp";
struct bpf_program fcode;

	strcpy(device,"rpcap://\\Device\\NPF_{F89AD090-E142-40F9-943E-82194970D687}");
	//rpcap://\Device\NPF_{F89AD090-E142-40F9-943E-82194970D687}
	
	//if ((fp= pcap_open(device,100 /*snaplen*/,PCAP_OPENFLAG_PROMISCUOUS /*flags*/,20 /*read timeout*/,NULL /* remote authentication */,errbuf)) == NULL)
	if ((fp= pcap_open(device,2000,0,100,NULL,errbuf)) == NULL)
	{
		printf("%s\n", errbuf);
		fprintf(stderr,"\nError opening source: %s\n", errbuf);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(fp) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        return -1;
    }

    netmask=0xffffff; 
		
    //compile the filter
    if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        return -1;
    }
    
    //set the filter
    if (pcap_setfilter(fp, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        return -1;
    }
		
	pcap_loop(fp, 0, packet_handler, NULL);

    return 0;
}