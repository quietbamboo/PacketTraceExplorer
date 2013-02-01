//
//  def.h
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 11/24/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#ifndef PacketTraceExplorer_def_h
#define PacketTraceExplorer_def_h

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

//0 for running on server for ATT's trace
//1 for running on macbook ATT's sample trace
//2 for running on macbook for yihua's server trace
//3 for yihua's client trace
#define RLOC_ATT_SERVER 0
#define RLOC_ATT_CLIENT 1
#define RLOC_CONTROL_SERVER 2
#define RLOC_CONTROL_CLIENT 3

#define RUNNING_LOCATION RLOC_ATT_SERVER

#define	ETHERTYPE_IP		0x08	/* IP protocol */

typedef	unsigned long long uint64; //should use this instead of u_long

static int ETHER_HDR_LEN; //14 for others; 16 for tcpdump linux cooked header
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define BYTES_PER_32BIT_WORD 4
#define TCP_HDR_LEN 
#define TCP_MAX_PAYLOAD 1358
const double BW_MAX_BITS_PER_SECOND = 30000000.0;

#define LOAD_SAMPLE_PERIOD 100 //load sample rate 1 per 100 seconds

static double TIME_BASE = 1350014400.000000; //Thu Oct 12 2012 00:00:00 GMT-0400 (EDT), GMT-4 is the timezone of Atlanta market in the summer when the data is collected

const int USEC_PER_SEC = 1000000;
const double FLOW_MAX_IDLE_TIME = 3600.0;
const double ONE_MILLION = 1000000.0;
const double GVAL_TIME = 3.0;
const double IDLE_THRESHOLD = 1.0; //seconds
const double DUPACK_SLOWSTART_TIME = 0.1; //seconds

static int SAMPLES = 0;
const int SAMPLE_CYCLE = 500;

typedef struct {
    u_int src_ip;
    u_int dst_ip;
    u_short offset1;
    u_short offset2;
	u_short	ether_type;
} att_ether_hdr;

typedef struct {
	double ts;
	bool isDown;
    
	u_short protocol;
	u_int src_ip;
	u_int dst_ip;
	u_short src_port;
	u_short dst_port;
	u_short tcp_flag;
	u_short len; //with TCP/IP header
	u_short payload_len; //without TCP/IP header
	u_int seq;
	u_int ack;
	u_int win_size;
    
} PACKET_INFO;

#endif
