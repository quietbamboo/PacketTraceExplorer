//
//  bw.h
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 12/1/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#ifndef __PacketTraceExplorer__bw__
#define __PacketTraceExplorer__bw__

#include "util.h"
#include "def.h"

const int SEQ_INDEX_MAX = 2000;
const int ACK_INDEX_MAX = SEQ_INDEX_MAX / 2; //1 ACK 2 Data PKTs

class tcp_flow {
public:
    u_int svr_ip;
    u_int clt_ip;
    u_short svr_port;
    u_short clt_port;
    double gval;
    double actual_ts;
    
    double target;
    double bwstep;
    double last_time;
    double last_throughput;
    
    double start_time;
    double first_byte_time; //first byte from server to client
    double last_byte_time; //last byte from server to client
    double end_time;
    double idle_time;
    double syn_rtt, syn_ack_rtt;
    
    u_short seq_max;
    short si; //circular seq index 0 - 19, point to the current last element
    short sx; // point to the current first index
    u_int *seq_down;//[SEQ_INDEX_MAX]; //circular arrary, seq_down[si] is the last packet
    double *seq_ts;//[SEQ_INDEX_MAX]; //corresponding time
    
    u_short ack_max;
    short ai; //circular ack index 0 - 9
    short ax; // point to the current first index
    u_int *ack_down;//[ACK_INDEX_MAX]; //circular arrary
    double *ack_ts;//[ACK_INDEX_MAX]; //corresponding time
    
    bool has_ts_option_clt;
    bool has_ts_option_svr;
    uint64 total_down_payloads;
    uint64 total_up_payloads;
    uint64 bytes_in_fly;
    uint64 max_bytes_in_fly;
    uint64 packet_count;
    uint64 dup_ack_count;
    uint64 outorder_seq_count;
    double total_bw;
    int sample_count;
    
    double first_bw;
    u_short dup_ack_count_current;
    u_short slow_start_count; // start from 1 initial slow start
    double last_dupack_time;
    u_int bytes_after_dupack;

    tcp_flow();
    tcp_flow(u_int _svr_ip, u_int _clt_ip, u_short _svr_port, u_short _clt_port, double _start_time);
    
    void init(int sm);
    
    //called during init or any abnormal happens
    void reset_seq();
    void reset_ack();
    
    //functions for BW estimation
    void update_seq(u_int seq, u_short payload_len, double ts);
    void update_ack(u_int ack, u_short payload_len, double ts, double _actual_ts);

    //functions for RTT analysis
    void update_seq_x(u_int seq, u_short payload_len, double ts);
    void update_ack_x(u_int ack, u_short payload_len, double _actual_ts);

    //test with start_ai and ai
    bool bw_estimate(short start_ai);
    short find_seq_by_ack(u_int ack, short start, short end);
    short get_si_next(short c);
    short get_si_previous(short c);
    short get_ai_next(short c);
    short get_ai_previous(short c);
    void print(u_short processed_flags);
    ~tcp_flow();
};

#endif /* defined(__PacketTraceExplorer__bw__) */
