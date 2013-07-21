#include <stdlib.h>
#include <stdio.h>

//#define WPCAP
#define HAVE_REMOTE

#include <pcap.h>

#define LINE_LEN 16

int main(int argc, char **argv)
{
pcap_t *fp;
u_int i=0;
char errbuf[PCAP_ERRBUF_SIZE];
char device[1024];
int res;
struct pcap_pkthdr *header;
const u_char *pkt_data;

	strcpy(device,"rpcap://\\Device\\NPF_{F89AD090-E142-40F9-943E-82194970D687}");
	//rpcap://\Device\NPF_{F89AD090-E142-40F9-943E-82194970D687}
	
	//if ((fp= pcap_open(device,100 /*snaplen*/,PCAP_OPENFLAG_PROMISCUOUS /*flags*/,20 /*read timeout*/,NULL /* remote authentication */,errbuf)) == NULL)
	if ((fp= pcap_open(device,100,0,20,NULL,errbuf)) == NULL)
	{
		printf("%s\n", errbuf);
		fprintf(stderr,"\nError opening source: %s\n", errbuf);
		return -1;
	}
    
	struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* Read the packets */
    while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {

        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* print pkt timestamp and pkt len */
        //printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
        
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
		
		printf("%s:%.6d (%lu)\n", timestr, header->ts.tv_usec, header->len);          
        
		
        /* Print the packet */
        for (i=1; (i < header->caplen + 1 ) ; i++)
        {
            printf("%.2x ", pkt_data[i-1]);
            if ( (i % LINE_LEN) == 0) printf("\n");
        }
        
        printf("\n\n");     
    }

    if(res == -1)
    {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}