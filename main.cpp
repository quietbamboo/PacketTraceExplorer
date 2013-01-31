//
//  main.cpp
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 11/18/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>

#include "data.h"
#include "util.h"

using namespace std;

int main(int argc, const char * argv[]) {
    int xx = -1;
#if BYTE_ORDER == LITTLE_ENDIAN
    xx = 0;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    xx = 1;
#endif
    switch (xx) {
        case 0:
            cout << "BYTE_ORDER LITTLE_ENDIAN" << endl;
            break;
        case 1:
            cout << "BYTE_ORDER BIG_ENDIAN" << endl;
            break;
        default:
            cout << "BYTE_ORDER NOT BIG NOT SMALL" << endl;
            break;
    }
    cout << "Size of tcp_flow " << sizeof(tcp_flow) << endl;
    //test uint64
    cout << "Length of uint64 should be 8: " << sizeof(uint64) << endl;
    
    //test hash_map
    map<u_int, tcp_flow> test_flows;
    map<u_int, tcp_flow>::iterator flow_it;
    bool b1 = (test_flows.size() == 0);
    test_flows[12345];
    bool b2 = (test_flows.size() == 1);
    if (b1 && b2) {
        cout << "MAP TEST PASS" << endl;
    } else {
        cout << "MAP TEST FAIL" << endl;
    }
    cout << "ConvertIPToString called twice " << ConvertIPToString(11) << " => " << ConvertIPToString(22) << endl;
    
    
    /*//init
    init_global();
    
    //one file analysis
    const char *test_file;
    switch (RUNNING_LOCATION) {
        case RLOC_ATT_SERVER:
            test_file = "/home/hjx/sample.pcap";
            break;
        case RLOC_ATT_CLIENT:
            test_file = "/Users/hjx/Documents/trace_explorer/backup/test/sample.pcap";
            //test_file = "/Users/hjx/Documents/trace_explorer/dupack.pcap";
            //test_file = "/Users/hjx/Documents/trace_explorer/t1012.0008.pcap.hdr.pcap";
            //test_file = "/Users/hjx/Documents/trace_explorer/dupack.pcap";
            break;
        case RLOC_CONTROL_SERVER:
            test_file = "/Users/hjx/Documents/trace_explorer/shazam_iphone4.pcap";
            //test_file = "/Users/hjx/Documents/trace_explorer/user_target.pcap";
            //test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/tcpDownlink-new/121226tcpdownnwlte2/121226_042616731_tcp_down_thrpt_nw_lte_server.pcap";
            //test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/tcpDownlink-new/121226tcpdownnwlte2/121226_042616731_tcp_down_thrpt_nw_lte_device_filtered.pcap";
            //test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/tcpDownlink-new/1301nexus/130101_120301140_tcp_down_thrpt_sld_3g_server.pcap";
            //test_file = "/Users/hjx/Documents/trace_explorer/backup/test/server_filtered.pcap";
            //test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/tcpDownlink-new/121219nwtcpdown1/121219152225-downtcpserver.pcap";
            break;
        case RLOC_CONTROL_CLIENT:
            test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/tcpDownlink-new/121226tcpdownnwlte2/121226_042616731_tcp_down_thrpt_nw_lte_device_filtered.pcap";
            //test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/tcpDownlink-new/1301nexus/130101_120301140_tcp_down_thrpt_sld_3g_device.pcap";
            //test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/udpDownlink-new/121219nwudpdown1/121219160150-downudpnwlte.pcap";
            //test_file = "/Users/hjx/Documents/4G/figures/traffic/traces/tcpDownlink-new/121219nwtcpdown1/121219152241-downtcpnwlte.pcap";
            break;
    }
    read_pcap_trace(test_file);
    return 0;//*/
    
    uint64 begin_time = clock();
    
    //string dir = "/q/gp13/dpi/tcprx/VTCLTEHEADER/gstmp/"; //gz dir
    string dir = "/q/gp13/dpi/tcprx/work/raw/";
    string prefix = "t1012.";//
    string suffix = ".pcap.hdr.pcap";
    
    string file, num, cmd;
    for (int i = 0 ; i <= MAX_FILE_ID ; i++) {
    //for (int i = 2338 ; i <= MAX_FILE_ID ; i++) {
        num = NumberToString(i + 10000).substr(1, 4);
        file = prefix + num + suffix;
        
        cout << "===============================================" << endl;
        cout << dir + file << endl;
        cout << "ID " << i << " time " << (float)float((uint64)clock () - begin_time) / CLOCKS_PER_SEC << endl;
        
        /*cmd = string("cp ") + dir + file + ".gz" + string(" ./");
        cout << cmd;
        system(cmd.c_str());
        cout << " time " << float((uint64)clock () - begin_time) / CLOCKS_PER_SEC << endl;
        
        cmd = string("gunzip ./") + file + ".gz";
        cout << cmd;
        system(cmd.c_str());
        cout << " time " << float((uint64)clock () - begin_time) / CLOCKS_PER_SEC << endl;*/
        
        read_pcap_trace((dir + file).c_str());
        cout << "Reading packets done ...  time " << (float)((uint64)clock () - begin_time) / CLOCKS_PER_SEC << endl;
        
        /*cmd = string("rm ./") + file;
        cout << cmd;
        system(cmd.c_str());
        cout << "time " << float((uint64)clock () - begin_time) / CLOCKS_PER_SEC << endl;*/
        
        cout << endl;
    }
    return 0;
}
