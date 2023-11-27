#include "pcap/PacketAnalyzeCommand.h"
#include <algorithm>

typedef struct {
	uint8_t ether_addr_octet[6];
} ether_addr;

/* Ethernet header */
typedef __declspec(align(2)) struct {
	ether_addr eth_dhost;    /* destination host address */
	ether_addr eth_shost;    /* source host address */
	uint16_t eth_type;                /* IP? ARP? RARP? etc */
} mapper_ethernet_t;

/* IP header */
typedef __declspec(align(4)) struct {
	union {
		uint8_t ip_vhl;
		struct {
			uint8_t ip_ihl : 4;        /* header length */
			uint8_t ip_version : 4;    /* version */
		};
	};
	uint8_t ip_tos;                    /* type of service */
	uint16_t ip_len;                   /* total length */
	uint16_t ip_id;                    /* identification */
	union {
		uint16_t ip_off_all;           /* fragment offset field */
		struct {
			uint16_t ip_offmask : 13;  /* mask for fragmenting bits */
			uint16_t ip_mf : 1;        /* more fragments flag */
			uint16_t ip_df : 1;        /* dont fragment flag */
			uint16_t ip_rf : 1;        /* reserved fragment flag */
		};
	} ip_off;
	uint8_t ip_ttl;                    /* time to live */
	uint8_t ip_protocol;               /* protocol */
	uint16_t ip_sum;                   /* checksum */
	struct in_addr ip_src, ip_dst;     /* source and dest address */
} mapper_ip_t;

typedef __declspec(align(4)) struct {
	uint16_t tcp_sport;                /* source port */
	uint16_t tcp_dport;                /* destination port */
	uint32_t tcp_seq;                   /* sequence number */
	uint32_t tcp_ack;                   /* acknowledgement number */
	uint8_t tcp_offx2;                 /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	union {
		uint8_t all_flags;
		struct {
			uint8_t tcp_fin : 1;       /* FIN */
			uint8_t tcp_syn : 1;       /* SYN */
			uint8_t tcp_rst : 1;       /* RST */
			uint8_t tcp_push : 1;      /* PUSH */
			uint8_t tcp_ack : 1;       /* ACK */
			uint8_t tcp_urg : 1;       /* URG */
			uint8_t tcp_ece : 1;       /* ECE */
			uint8_t tcp_cwr : 1;       /* CWR */
		};
	} tcp_flags;
	uint16_t tcp_window;               /* window */
	uint16_t tcp_sum;                  /* checksum */
	uint16_t tcp_urp;                  /* urgent pointer */
} mapper_tcp_t;

/* UDP header */
typedef __declspec(align(2)) struct {
	uint16_t udp_sport;                /* source port */
	uint16_t udp_dport;                /* destination port */
	uint16_t udp_len;                  /* length */
	uint16_t udp_sum;                  /* checksum */
} mapper_udp_t;

/* ICMP header */
typedef __declspec(align(4)) struct {
	uint8_t icmp_type;                 /* ICMP type */
	uint8_t icmp_code;                 /* ICMP subtype */
	uint16_t icmp_sum;                 /* checksum */
	uint32_t icmp_header;			   /* rest of header */
} mapper_icmp;

typedef __declspec(align(4)) struct {
	mapper_ethernet_t _ethernet;
	mapper_ip_t _ip;
	char _payload[33];
} mapper_t;

uint32_t PacketAnalyzeCommand::execute(void* pdata, size_t dataSize) {
	SNetworkPacket* pnetworkPacket = (SNetworkPacket*)pdata;
	mapper_t results;
	int size_ip;
	char* payload;
	size_t payload_i = 0;

	static const char c_hexChars[] = "0123456789ABCDEF";

	memset(&results, 0, sizeof(mapper_t));
	/* map header to ethernet structure */
	memcpy(&results._ethernet, pdata, sizeof(mapper_ethernet_t) + sizeof(mapper_ip_t));
	/* Ethernet frames are sent through network in Big Endian format */
	results._ethernet.eth_type = _byteswap_ushort(results._ethernet.eth_type);
	results._ip.ip_len = _byteswap_ushort(results._ip.ip_len);
	results._ip.ip_id = _byteswap_ushort(results._ip.ip_id);
	results._ip.ip_off.ip_off_all = _byteswap_ushort(results._ip.ip_off.ip_off_all);
	results._ip.ip_sum = _byteswap_ushort(results._ip.ip_sum);
	/* map header (after applying offset) to ip structure */
	size_ip = results._ip.ip_ihl * 4;
	if (size_ip < 20) {
		//SYSLOG(LOG_ERR, "   * Invalid IP header length: %u bytes", size_ip);
		return 1;
	}
	payload = (char*)((size_t)pdata + sizeof(mapper_ethernet_t) + size_ip);
	for (size_t i = 0; i < min(16, dataSize - sizeof(mapper_ethernet_t) - size_ip); i++) {
		results._payload[payload_i++] = c_hexChars[((payload[i] >> 4) & 0xf)];
		results._payload[payload_i++] = c_hexChars[(payload[i] & 0xf)];
	}
	results._payload[payload_i] = '\0';
	return 0;
}