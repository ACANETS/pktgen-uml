#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <sys/queue.h>
#include <time.h>
#include <pcap/pcap.h>
#include <assert.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h> 
#include <unistd.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_sched.h>
#include <cmdline_parse.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

#include <rte_port_ethdev.h>
#include <rte_port_ring.h>
#include <rte_pipeline.h>

#ifndef PORT_MASK
#define PORT_MASK                                0x01 //only 1 port, change it for different case
#endif                                                    //which follows the global device[]

#ifdef RTE_MAX_ETHPORTS
#undef RTE_MAX_ETHPORTS
#define RTE_MAX_ETHPORTS                         2 //The maxinumber of NICs on the Dell server
#endif

#ifdef RTE_MAX_LCORE
#undef RTE_MAX_LCORE
#define RTE_MAX_LCORE                            12 //The Dell server has only 12 cores
#endif

#define DEFAULT_PKT_BURST                        64//32//128 //64 //128
#define DEFAULT_TX_DESC                          256 //512 // 
#define MAX_MBUFS_PER_PORT                       (256*1024)//2048//1024//(1024*1024)//1024//256*1024//(2*1024*1024)//128 
#define MBUF_CACHE_SIZE                          0//256 // 
#define DEFAULT_BUFF_SIZE                        2048//512//290//2048//290//2048
#define DEFAULT_PRIV_SIZE                        0
#define MBUF_SIZE                                (DEFAULT_BUFF_SIZE - sizeof(struct rte_mbuf) - DEFAULT_PRIV_SIZE)

#define FCS_SIZE                                 4
#ifndef ETHER_MAX_LEN
#define ETHER_MAX_LEN                            1518
#endif
#define MAX_PKT_SIZE                             (ETHER_MAX_LEN - FCS_SIZE)
//#define PKT_SIZE                                 MBUF_SIZE


#define PKTQ_HWQ_OUT_BURST_SIZE                  DEFAULT_PKT_BURST // burst size of tx queues

#define PAYLOAD_SIZE                             1460//10
//==========================================================================================================
//==============================================================================================================
#include <getopt.h>
char packet_saddr[16];
char packet_saddr_flag = 0;
char packet_daddr[16];
char packet_daddr_flag = 0;
uint16_t packet_sport = 0;
uint16_t packet_dport = 0;
uint16_t packet_psize = PAYLOAD_SIZE;
char* pcap_file_name = NULL;                         // for opening the file
pcap_t *pt[RTE_MAX_LCORE];                           // file handler
uint32_t repeat = -1;                                // how many times the pcap file will be repeated
static uint32_t cur_repeat[RTE_MAX_LCORE];           // track how many times the pcap file has been repeated
static int parse_args(int argc, char **argv)
{
	int opt, ret;
	int option_index;
	static struct option lgopts[] = {
		{"saddr", 1, 0, 0},
		{"daddr", 1, 0, 0},
		{"sport", 1, 0, 0},
		{"dport", 1, 0, 0},
		{"psize", 1, 0, 0},
		{NULL, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "f:R:", lgopts, &option_index)) != EOF) 
	{
		switch (opt) 
		{
		case 'f':
			pcap_file_name = strdup(optarg);
			printf("The input pcap file is %s\n", pcap_file_name);
			break;
		case 'R':
			repeat = atoi(optarg);
			printf("The pcap file will be played %u times \n", repeat);
			break;
		// long options
		case 0:
			if (!strncmp(lgopts[option_index].name, "saddr", sizeof("saddr"))) {
				packet_saddr_flag = 1;
				strncpy(packet_saddr, optarg, strlen(optarg));		
			}
			if (!strncmp(lgopts[option_index].name, "daddr", sizeof("daddr"))) {
				packet_daddr_flag = 1;
				strncpy(packet_daddr, optarg, strlen(optarg));		
			}
			if (!strncmp(lgopts[option_index].name, "sport", sizeof("sport"))) {
				packet_sport = atoi(optarg);		
			}
			if (!strncmp(lgopts[option_index].name, "dport", sizeof("dport"))) {
				packet_dport = atoi(optarg);		
			}
			if (!strncmp(lgopts[option_index].name, "psize", sizeof("psize"))) {
				packet_psize = atoi(optarg);		
			}

			break;

		default:
			return -1;
		}
	}

	ret = optind-1;
	optind = 0; // reset getopt lib 
	return ret;
}
//==============================================================================================================
//for reports
volatile uint32_t report_flag[RTE_MAX_LCORE+1];
volatile int32_t queueid_to_lcoreid[RTE_MAX_LCORE];
volatile uint64_t overall_total_cycle = 0;
volatile uint32_t overall_total_pkts = 0;
//==========================================================================================================
struct rte_mempool* mempool[RTE_MAX_ETHPORTS][RTE_MAX_LCORE];
struct rte_mbuf* app_mtable[RTE_MAX_ETHPORTS][RTE_MAX_LCORE][PKTQ_HWQ_OUT_BURST_SIZE+1];
uint32_t lcoreid_to_queueid[RTE_MAX_ETHPORTS][RTE_MAX_LCORE];
#define APP_THREAD_SENDNUMPKTS_ROUND             (64 *1024 * 1024 / PKTQ_HWQ_OUT_BURST_SIZE)     
//==========================================================================================================
struct app_mempool_params {
	uint32_t pool_size;
	uint32_t priv_size;
	uint32_t data_size;
	uint32_t cache_size;
};
//
static const struct app_mempool_params mempool_params_default = {
	.pool_size = MAX_MBUFS_PER_PORT,
	.priv_size = DEFAULT_PRIV_SIZE,
	.data_size = MBUF_SIZE,
	.cache_size = ((MBUF_CACHE_SIZE > RTE_MEMPOOL_CACHE_MAX_SIZE) ? RTE_MEMPOOL_CACHE_MAX_SIZE : MBUF_CACHE_SIZE),
};
//==========================================================================================================
struct app_link_params {
	uint32_t pmd_id; // Generated based on port mask 
	uint32_t arp_q; // 0 = Disabled (packets go to default queue 0) 
	uint32_t tcp_syn_q; // 0 = Disabled (pkts go to default queue) 
	uint32_t ip_local_q; // 0 = Disabled (pkts go to default queue 0) 
	uint32_t tcp_local_q; // 0 = Disabled (pkts go to default queue 0) 
	uint32_t udp_local_q; // 0 = Disabled (pkts go to default queue 0) 
	uint32_t sctp_local_q; // 0 = Disabled (pkts go to default queue 0) 
	uint32_t promisc;
	uint32_t state; // DOWN = 0, UP = 1 
	uint32_t ip; // 0 = Invalid 
	uint32_t depth; // Valid only when IP is valid 
	uint64_t mac_addr; // Read from HW 
	char pci_bdf[16];

	struct rte_eth_conf conf;
};
//
static const struct app_link_params link_params_default = {
	.pmd_id = 0,
	.arp_q = 0,
	.tcp_syn_q = 0,
	.ip_local_q = 0,
	.tcp_local_q = 0,
	.udp_local_q = 0,
	.sctp_local_q = 0,
	.state = 0,
	.ip = 0,
	.depth = 0,
	.mac_addr = 0,
	.pci_bdf = {0},

	.conf = {
		.link_speeds = 0,
		.rxmode = {
			.mq_mode = ETH_MQ_RX_NONE,

			.header_split   = 0, // Header split 
			.hw_ip_checksum = 0, // IP checksum offload 
			.hw_vlan_filter = 0, // VLAN filtering 
			.hw_vlan_strip  = 0, // VLAN strip 
			.hw_vlan_extend = 0, // Extended VLAN 
			.jumbo_frame    = 0, // Jumbo frame support 
			.hw_strip_crc   = 0, // CRC strip by HW 
			.enable_scatter = 0, // Scattered packets RX handler 

			.max_rx_pkt_len = 9000, // Jumbo frame max packet len 
			.split_hdr_size = 0, // Header split buffer size 
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key = NULL,
				.rss_hf = 0,
			},
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
		.lpbk_mode = 0,
	},
	.promisc = 1,
};
//==========================================================================================================
struct app_pktq_hwq_in_params {
	uint32_t size;
	uint32_t burst;

	struct rte_eth_rxconf conf;
};

static const struct app_pktq_hwq_in_params default_hwq_in_params = {
	.size = 128,
	.burst = 32, //not used

	.conf = {
		.rx_thresh = {
				.pthresh = 8,
				.hthresh = 8,
				.wthresh = 4,
		},
		.rx_free_thresh = 64,
		.rx_drop_en = 0,
		.rx_deferred_start = 0,
	}
};
//==========================================================================================================
struct app_pktq_hwq_out_params {
	uint32_t size;
	uint32_t burst;

	struct rte_eth_txconf conf;
};
//
static const struct app_pktq_hwq_out_params default_hwq_out_params = {
	.size = DEFAULT_TX_DESC,
	.burst = PKTQ_HWQ_OUT_BURST_SIZE,

	.conf = {
		.tx_thresh = {
			.pthresh = 36,
			.hthresh = 0,
			.wthresh = 0,
		},
		.tx_rs_thresh = 0,
		.tx_free_thresh = 0,
		.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
		.tx_deferred_start = 0,
	}
};
//==========================================================================================================
uint32_t total_num_lcores()
{
	uint32_t total = 0;
	uint32_t i;
	for (i = 0; i < RTE_MAX_LCORE; i++)
	{
		if ( rte_lcore_is_enabled(i) )
		{
			total += 1;
		}
	}
	return total;
}
//==========================================================================================================
static void app_init_eal(int argc, char **argv)
{
	int ret;
	ret = rte_eal_init(argc, argv);
	if (ret < 0) { rte_panic("EAL init error\n"); }
	argc -= ret;
	argv += ret;
	ret = parse_args(argc, argv);
	if (ret < 0) { rte_panic("Invalid command line parameters\n"); }
}
//
static void app_init_mempool()
{
	uint32_t i, pmd_id;
	for (pmd_id = 0; pmd_id < RTE_MAX_ETHPORTS; pmd_id++)
	{
		//check if the port is needed
		if ((PORT_MASK & (1LLU << pmd_id)) == 0) {continue;} 
		
		for (i = 0; i < RTE_MAX_LCORE; i++)
		{
			if ( rte_lcore_is_enabled(i) )
			{
				uint32_t sid = rte_lcore_to_socket_id(i);
				char name[128]; sprintf(name, "MEMPOOL_TXQ%u.%u", pmd_id, i);
				mempool[pmd_id][i] = rte_pktmbuf_pool_create(
											name,
											mempool_params_default.pool_size,
											mempool_params_default.cache_size,
											mempool_params_default.priv_size,
											mempool_params_default.data_size,
											sid);

				if (mempool[pmd_id][i] == NULL) { rte_panic("%s init error\n", name); }
			}
		}
	}
}
//
static inline int app_get_cpu_socket_id(uint32_t pmd_id)
{
	int status = rte_eth_dev_socket_id(pmd_id);

	return (status != SOCKET_ID_ANY) ? status : 0; //On the VM, it has only 1 socket
}
//
static void app_init_link()
{
	int status;
	uint32_t pmd_id, pmd_sid, i;
	
	//
	for (pmd_id = 0; pmd_id < RTE_MAX_ETHPORTS; pmd_id++)
	{
		//check if the port is needed
		if ((PORT_MASK & (1LLU << pmd_id)) == 0) {continue;} 
		
		//get pmd_sid
		pmd_sid = app_get_cpu_socket_id(pmd_id);
		
		// LINK
		struct app_link_params link_temp; //create a copy from the initialized static one
		memcpy(&link_temp, &link_params_default, sizeof(struct app_link_params));
		
		status = rte_eth_dev_configure(pmd_id, 1, total_num_lcores(), &link_temp.conf);
		if (status < 0) { printf("Error, can not init dev %u\n", pmd_id); exit(1); }

		rte_eth_macaddr_get(pmd_id, (struct ether_addr *) &link_temp.mac_addr);

		if (link_temp.promisc) { rte_eth_promiscuous_enable(pmd_id); }
			
		//RXQ
		printf("========Setting up the RXQ%d.0==========\n", pmd_id);
		// MEMPOOL FOR RXQ, only 1
		char name[128]; sprintf(name, "MEMPOOL_RXQ%u.0", pmd_id);
		struct rte_mempool * mp;
		mp = rte_pktmbuf_pool_create(
									name,
									mempool_params_default.pool_size,
									mempool_params_default.cache_size,
									mempool_params_default.priv_size,
									mempool_params_default.data_size,
									pmd_sid);
		
		if(mp == NULL) { printf("Error, can not create rxq mempool for dev %u \n", pmd_id); exit(1); }
			
		status = rte_eth_rx_queue_setup(
			                pmd_id,//port id
			                0,//queue id
			                default_hwq_in_params.size,//the number of rx descriptor
			                pmd_sid,//socket id
			                &default_hwq_in_params.conf,//config
			                mp);//mempool	
		if (status < 0) { printf("Error, can not set up rx queue for dev %u \n", pmd_id);  exit(1); }	

		//TXQ 
		uint32_t count = 0;
		for(i = 0; i < RTE_MAX_LCORE; i++) 
		{
			if(rte_lcore_is_enabled(i))
			{			
				printf("========Setting up the TXQ%d.%d==========\n", pmd_id, i);
				//set up the lcoreid_to_queueid
				lcoreid_to_queueid[pmd_id][i] = count;
				count += 1;
				status = rte_eth_tx_queue_setup(
										pmd_id,
										lcoreid_to_queueid[pmd_id][i], //the relative queue id
										default_hwq_out_params.size,//the number of tx descriptor
										pmd_sid,
										&default_hwq_out_params.conf);
				if (status < 0) { printf("Error, can not set up tx queue for dev %u \n", pmd_id);  exit(1); }
			}
		}

		// LINK START
		status = rte_eth_dev_start(pmd_id);
		if (status < 0) { printf("Error, can not start dev %u \n", pmd_id);  exit(1); }
	}
}
//
void open_pcap_file(int lcore_id);
int app_init(int argc, char **argv)
{
	app_init_eal(argc, argv);
	app_init_mempool();
	app_init_link();
	uint32_t i;
	//
	for(i=0; i<RTE_MAX_LCORE; i++) {report_flag[i] = 0;} 
	report_flag[0] = 1;
	//
	int32_t count = 0;
	for(i=0; i<RTE_MAX_LCORE; i++) {queueid_to_lcoreid[i] = -1;}
	for(i=0; i<RTE_MAX_LCORE; i++)
	{
		if(rte_lcore_is_enabled(i))
		{
			queueid_to_lcoreid[count] = i;
			count += 1;
		}
	}
	//
	if(pcap_file_name != NULL)
	{
		for(i=0; i<RTE_MAX_LCORE; i++)
		{
			if(rte_lcore_is_enabled(i))
			{
				open_pcap_file(i);
			}
		}	
	}
	return 0;
}
//==========================================================================================================
//==========================================================================================================
//
int myrand(int lcore_id)
{
	return (rand() * (lcore_id+1) * (lcore_id+1));
}
//
void random_ip_gen(char* src_addr_temp, int lcore_id)
{
	int i;
	int offset = 0;
	for(i=0; i<4; i++)
	{
		offset += sprintf(src_addr_temp+offset, "%d", myrand(lcore_id) & 255);
		if(i != 3) { offset += sprintf(src_addr_temp+offset, "."); }
	}
	src_addr_temp[offset] = '\0';
}
//
struct Pseudo_IP_Header
{
	uint32_t src_addr; //ip
	uint32_t dst_addr; //ip
	unsigned short protocol; //ip
	unsigned short udp_len; //udp
};
struct ether_header {
	unsigned char ether_dhost[6];     
	unsigned char ether_shost[6];     
	unsigned short ether_type;         
};
//
unsigned short Compute_Checksum_UDP(unsigned char* addr, int count, struct Pseudo_IP_Header PIH)
{
	//Compute Internet Checksum for "count" bytes beginning at location "addr".  
	register long sum = 0;
	while( count > 1 )  {sum += * (unsigned short*) addr; addr += 2; count -= 2;}

	//Add left-over byte, if any
	if( count > 0 ) { sum += * (unsigned char *) addr;}
	
	
	//Handle the Pseudo_IP_Header
	addr = (unsigned char*) &PIH;
	count = sizeof(struct Pseudo_IP_Header); // The number of unsigned chars, careful
	while( count !=0 )  {sum += * (unsigned short*) addr; addr += 2; count -= 2;}
	
    // Fold 32-bit sum to 16 bits
	while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
		
	unsigned short checksum = ~sum;
	return checksum;
}
//
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}
//fill the packet with random UDP info
int packet_fillin_random(uint8_t* sendbuf, int lcore_id)
{
	int i;
	//prepare the buffer and the pointer of each header
	int tx_len = 0;
	//memset(sendbuf, 0, MAX_PKT_SIZE);
	struct ether_header * eh = (struct ether_header *) sendbuf;
	struct iphdr * iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
	//fill the mac with random
	for(i=0; i<ETH_ALEN; i++){ eh->ether_shost[i] = myrand(lcore_id) & 255; }
	for(i=0; i<ETH_ALEN; i++){ eh->ether_dhost[i] = myrand(lcore_id) & 255; }
	eh->ether_type = htons(ETH_P_IP);
	
	tx_len += sizeof(struct ether_header);
	//fill the ip with random
	iph->ihl = 5; //with no IP options, ihl*4 is the IP header length
	iph->version = 4;
	iph->tos = 16+8+4+2; // minimize delay, maximize throughput, maximize reliability and minimize monetary cost
	iph->ttl = 64; // hops
	iph->protocol = 17; // UDP
	
	if(packet_saddr_flag == 1)
	{
		const char* src_addr = packet_saddr;
		iph->saddr = inet_addr(src_addr);
	}
	else
	{
		char src_addr_temp[16];
		random_ip_gen(src_addr_temp, lcore_id);
		const char* src_addr = src_addr_temp;
		iph->saddr = inet_addr(src_addr);
	}
	
	if(packet_daddr_flag == 1)
	{
		const char* dst_addr = packet_daddr;
		iph->daddr = inet_addr(dst_addr);
	}
	else
	{
		char dst_addr_temp[16];
		random_ip_gen(dst_addr_temp, lcore_id);
		const char* dst_addr = dst_addr_temp;
		iph->daddr = inet_addr(dst_addr);
	}
	
	tx_len += sizeof(struct iphdr); //with no IP header options
	//fill the udp with random
	if(packet_sport != 0)
	{
		udph->source = htons(packet_sport);
	}
	else
	{
		udph->source = htons(myrand(lcore_id) & 0xffff);
	}
	
	if(packet_dport != 0)
	{
		udph->dest = htons(packet_dport);
	}
	else
	{
		udph->dest = htons(myrand(lcore_id) & 0xffff);
	}
	
	tx_len += sizeof(struct udphdr);
	//fill the payload with charater A
	uint8_t * payload = (uint8_t *)sendbuf + tx_len;
	
	//int payload_size = (myrand(lcore_id) & 1023) + 64;
	//for(i=0; i<payload_size; i++) {payload[i] = 'A';}
	
	int payload_size = packet_psize;
	//memset(payload, 0, payload_size);
	
	tx_len += payload_size;
	//update the UDP header
	udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));
	
	struct Pseudo_IP_Header PIH; memset((unsigned char*)&PIH, 0, sizeof(struct Pseudo_IP_Header));
	PIH.src_addr = iph->saddr;
	PIH.dst_addr = iph->daddr;
	PIH.protocol = htons((unsigned short)iph->protocol);
	PIH.udp_len = udph->len;
	udph->check = Compute_Checksum_UDP((unsigned char*)udph, ntohs(udph->len), PIH);
	
	//update the IP header
	iph->tot_len = htons(tx_len - sizeof(struct ether_header));
	
	iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr)/2);
	
	//return the pktsize
	return tx_len;
}

//open the pcap file
void open_pcap_file(int lcore_id)
{
	if(pcap_file_name != NULL)
	{
		char ebuf[256];
		pt[lcore_id] = pcap_open_offline(pcap_file_name, ebuf);
		if (pt[lcore_id] == NULL)
		{	
			printf("lcore %d: unable to open file: %s\n", lcore_id, pcap_file_name);
			exit(1);			
		}
		printf("lcore %u, the pcap file %s has been successfully opened\n", lcore_id, pcap_file_name);		
	}
}

//Fill in each mempool with real data for the corresponding core with lcore_id
int pktgen_setup_packets(int lcore_id)
{		
	int total_size = 0;
	uint32_t pmd_id;
	for (pmd_id = 0; pmd_id < RTE_MAX_ETHPORTS; pmd_id++)
	{
		//check if the port is needed
		if ((PORT_MASK & (1LLU << pmd_id)) == 0) {continue;} 
		
		struct rte_mempool* mp = mempool[pmd_id][lcore_id];
		struct rte_mbuf *m = NULL;
		struct rte_mbuf *mm = NULL;
		//fill in the complete entire mempool, so the "loop number" is MAX_MBUFS_PER_PORT
		for(; ;)
		{
			m = rte_pktmbuf_alloc(mp);
			if (unlikely(m == NULL) ) {break;}	
			//fill in the buffer with the packet
			uint8_t* buffer = (uint8_t *)(m->buf_addr + m->data_off);
			if(pcap_file_name == NULL)
			{
				int pktSize = packet_fillin_random(buffer, lcore_id);
				total_size += pktSize;
				//update the packet size
				m->pkt_len  = pktSize;
				m->data_len = pktSize;
				
				//chain the rte_mbuf
				m->next = mm;
				mm = m;
			}
			else
			{
				struct pcap_pkthdr h;
				const uint8_t* pkt;
				pkt = pcap_next(pt[lcore_id], &h);
				if(pkt == NULL)
				{
					if(cur_repeat[lcore_id] < repeat)
					{
						printf("lcore %d, pcap file has been played %u times and reopen the pcap file ...\n", lcore_id, (cur_repeat[lcore_id] + 1));
						pcap_close(pt[lcore_id]);
						open_pcap_file(lcore_id);
						cur_repeat[lcore_id] += 1;
					}
					else
					{
						exit(0);
					}
				}
				else
				{
					int copylen = h.caplen;
					if(h.caplen >= 1400) {copylen = 1400;} //some len would exceed 1400
					total_size += copylen;
					m->pkt_len = copylen;
					m->data_len = copylen;
					memcpy(buffer, pkt, copylen);
					
					//chain the rte_mbuf
					m->next = mm;
					mm = m;	
				}
			}
		}//rte_pktmbuf_alloc() loop
		if (mm != NULL) {rte_pktmbuf_free(mm);}
	}//port loop
	//if(pcap_file_name != NULL) { if(pt[lcore_id] != NULL) {pcap_close(pt[lcore_id]);} }
	//total_size is the sum of the sizes of all the packets in the mempool corresponding to each thread, for all the NICs 
	return total_size;
}
//==========================================================================================================
//==========================================================================================================
//
static inline void __pktmbuf_alloc_noreset(struct rte_mbuf *m)
{
	m->next = NULL;
	m->nb_segs = 1;
	m->port = 0xff;

	m->data_off = (RTE_PKTMBUF_HEADROOM <= m->buf_len) ? RTE_PKTMBUF_HEADROOM : m->buf_len;
	rte_mbuf_refcnt_set(m, 1);
}
//
static inline int wr_pktmbuf_alloc_bulk_noreset(struct rte_mempool *mp, struct rte_mbuf *m_list[], unsigned int cnt)
{
	int ret;
	unsigned int i;

	ret = rte_mempool_get_bulk(mp, (void **)m_list, cnt);
	if (ret == 0) {
		for (i = 0; i < cnt; i++)
			__pktmbuf_alloc_noreset(*m_list++);
		ret = cnt;
	}
	else
	{
		printf("rte_mempool_get_bulk return error!!!\n");
		exit(1);
	}
	return ret;
}
//==========================================================================================================
//==========================================================================================================
//Send the packets out for each core with lcore_id
//first, use wr_pktmbuf_alloc_bulk_noreset() to get a bulk of packets from the corresponding mempool
//second, use rte_eth_tx_burst() to send it out
void pktgen_send_pkts(int lcore_id)
{
	uint32_t pmd_id;
	for (pmd_id = 0; pmd_id < RTE_MAX_ETHPORTS; pmd_id++)
	{
		//check if the port is needed
		if ((PORT_MASK & (1LLU << pmd_id)) == 0) {continue;}
		
		struct rte_mempool* mp = mempool[pmd_id][lcore_id];
		struct rte_mbuf *m_table[PKTQ_HWQ_OUT_BURST_SIZE + 1];
		int cnt = wr_pktmbuf_alloc_bulk_noreset(mp, m_table, PKTQ_HWQ_OUT_BURST_SIZE);
		int pos = 0;
		while (cnt) 
		{
			//printf("The cnt is %d\n", cnt);
			int ret = rte_eth_tx_burst(pmd_id, lcoreid_to_queueid[pmd_id][lcore_id], &m_table[pos], cnt);//lcore_id <=> queue id
			pos += ret;
			cnt -= ret;
		}
	}
}
//The app_thread_fps() combine the wr_pktmbuf_alloc_bulk_noreset() and rte_eth_tx_burst() together in each round
int app_thread_fps(void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("Hello from core %u!!!\n", lcore_id);
    
	for(; ;)
	{	
		//printf("lcore %d: Set up packets start......\n", lcore_id);
		uint64_t start = rte_get_tsc_cycles();
		pktgen_setup_packets(lcore_id);
		uint64_t end = rte_get_tsc_cycles();
		//printf("lcore %d: Set up packets done......\n", lcore_id);
		printf("lcore %d:Set Cost %" PRIu64 " cycles, and in %lf sec\n", lcore_id, end-start, ((double)(end-start))/rte_get_tsc_hz());
			
		//printf("lcore %d: Send packets start......\n", lcore_id);
		start = rte_get_tsc_cycles();
		pktgen_send_pkts(lcore_id);
		end = rte_get_tsc_cycles();
		//printf("lcore %d: Send packets done......\n", lcore_id);
		printf("lcore %d:Send Cost %" PRIu64 " cycles, and in %lf sec\n", lcore_id, end-start, ((double)(end-start))/rte_get_tsc_hz());
	}
	return 0;	
}
//==========================================================================================================
//==========================================================================================================
//
int pktgen_get_pkts_modify(int lcore_id)
{
	uint32_t pmd_id;
	for (pmd_id = 0; pmd_id < RTE_MAX_ETHPORTS; pmd_id++)
	{
		//check if the port is needed
		if ((PORT_MASK & (1LLU << pmd_id)) == 0) {continue;}
		
		struct rte_mempool* mp = mempool[pmd_id][lcore_id];
		wr_pktmbuf_alloc_bulk_noreset(mp, app_mtable[pmd_id][lcore_id], PKTQ_HWQ_OUT_BURST_SIZE);
	}
}
//
void pktgen_send_pkts_modify(int lcore_id)
{
	uint32_t pmd_id;
	for (pmd_id = 0; pmd_id < RTE_MAX_ETHPORTS; pmd_id++)
	{
		//check if the port is needed
		if ((PORT_MASK & (1LLU << pmd_id)) == 0) {continue;}
		int pos = 0;
		int cnt = PKTQ_HWQ_OUT_BURST_SIZE;
		while (cnt) 
		{
			int ret = rte_eth_tx_burst(pmd_id, lcoreid_to_queueid[pmd_id][lcore_id], &(app_mtable[pmd_id][lcore_id][pos]), cnt);
			pos += ret;
			cnt -= ret;
			//printf("cnt is %d\n", cnt);
		}
	}
}
//The app_thread_throughput() separate the wr_pktmbuf_alloc_bulk_noreset() from rte_eth_tx_burst() in each round
int app_thread_throughput(void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("Hello from core %u!!!\n", lcore_id);
    	
	//set up packets
	pktgen_setup_packets(lcore_id);
	//pktgen_get_pkts_modify(lcore_id);
	for(; ;)
	{
		int total_time_in_sec = 10;
		uint64_t p_ticks = total_time_in_sec * rte_get_tsc_hz();
		
		
		//call wr_pktmbuf_alloc_bulk_noreset()	
		pktgen_get_pkts_modify(lcore_id);
			
		int rounds = 0;
		uint64_t p_start = rte_get_tsc_cycles();
		while(rte_get_tsc_cycles() - p_start < p_ticks)
		{
			//call rte_eth_tx_burst()
			pktgen_send_pkts_modify(lcore_id);
			rounds += 1;
		}
			
		printf("lcore %d, TX Rate: %lf GBPS \n", lcore_id, 
				(double)8 * rounds * PKTQ_HWQ_OUT_BURST_SIZE * (packet_psize+42) / total_time_in_sec / 1000 /1000 /1000 );
	}
	return 0;	
}
//==========================================================================================================
//==========================================================================================================
int app_thread_pcap(void *arg)
{
    unsigned lcore_id;
    lcore_id = rte_lcore_id();
    printf("Hello from core %u!!!\n", lcore_id);
	if(pcap_file_name == NULL) {printf("Error, please enable the -f option.\n"); exit(1);}

	for(; ;)
	{
		pktgen_setup_packets(lcore_id);
		int rounds = 0;
		while(rounds < (MAX_MBUFS_PER_PORT/PKTQ_HWQ_OUT_BURST_SIZE))
		{
			pktgen_send_pkts(lcore_id);
			rounds += 1;
		}
		printf("lcore %d, sent %u packets \n", lcore_id, rounds * PKTQ_HWQ_OUT_BURST_SIZE);
	}
	return 0;
}

//==========================================================================================================
//==========================================================================================================
int app_thread_sendnumpkts(void* arg)
{
	unsigned lcore_id = rte_lcore_id();
	printf("Hello from core %u!!!\n", lcore_id);
	
	//prepare the packets
	pktgen_setup_packets(lcore_id);
	printf("Core %u: has finished setting up pkts.\n", lcore_id);
	//
	uint64_t start_cycle = rte_get_tsc_cycles();
	int rounds = 0;
	while(rounds < APP_THREAD_SENDNUMPKTS_ROUND)
	{
		//call wr_pktmbuf_alloc_bulk_noreset()	
		pktgen_get_pkts_modify(lcore_id);
		
		//call rte_eth_tx_burst()
		pktgen_send_pkts_modify(lcore_id);
		
		//pktgen_send_pkts(lcore_id);
		rounds += 1;
	}
	uint64_t end_cycle = rte_get_tsc_cycles();
	uint64_t total_cycle = end_cycle - start_cycle;
	uint64_t hz = rte_get_tsc_hz();
	//report
	uint32_t total_pkts = rounds * PKTQ_HWQ_OUT_BURST_SIZE;
	uint32_t pkt_size = (packet_psize+42);
	printf("Core %u: Send %u packets of size %u in time %lf sec\n", lcore_id, total_pkts, pkt_size, (double)total_cycle/hz);
	sleep(30);
	
	//find corresponding queue id "i" for each thread
	uint32_t i;
	uint32_t queue_id;
	for(i=0; i<RTE_MAX_LCORE; i++)
	{
		if(queueid_to_lcoreid[i] == lcore_id)
		{
			queue_id = i;
			break;
		}
	}
	//
	while(report_flag[queue_id] == 0) {}
	if(overall_total_cycle < total_cycle) {overall_total_cycle = total_cycle;}
	overall_total_pkts += total_pkts;
	
	report_flag[queue_id+1] = 1;
	sleep(5);
	//
	if(queue_id == 0)
	{
		double time = (double)overall_total_cycle/hz;
		printf("All the cores have sent totally %u pkts in %lf sec \n", overall_total_pkts, time);
		printf(" %lf PPS, %lf Gbps \n", overall_total_pkts/time, (double)overall_total_pkts*pkt_size*8/time/1024/1024/1024);
	}
	else
	{
		sleep(1);
	}
	
	return 0;
}


//==========================================================================================================
//==========================================================================================================
int main(int argc, char **argv)
{
	srand(time(NULL));
	app_init(argc, argv);
	//rte_eal_mp_remote_launch(app_thread_fps, NULL, CALL_MASTER);
	rte_eal_mp_remote_launch(app_thread_throughput, NULL, CALL_MASTER);
	//rte_eal_mp_remote_launch(app_thread_pcap, NULL, CALL_MASTER);
	//rte_eal_mp_remote_launch(app_thread_sendnumpkts, NULL, CALL_MASTER);
}
