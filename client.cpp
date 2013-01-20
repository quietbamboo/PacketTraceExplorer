//
//  client.cpp
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 12/20/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#include "client.h"

client_bw::client_bw(double _current_start, double _step) {
    current_start = _current_start;
    step = _step;
    current_bytes = 0;
}

void client_bw::add_packet(int payload, double ts) {
    if (ts - current_start < step) {
        current_bytes += payload;
    } else {
        //
        double tp = (double)current_bytes * 8.0 / step / 1000000.0;
        cout << "CLIENT_BW time " << (current_start + step) << " " << tp << " Mbps" << endl;
        
        //this packet starts the new sample
        while (ts - current_start >= step) {
            if (tp > 0) {
                tp = 0;
            } else {
                cout << "CLIENT_BW time " << (current_start + step) << " " << tp << " Mbps" << endl;
            }
            current_start += step;
        }
        current_bytes = payload;
    }
}
