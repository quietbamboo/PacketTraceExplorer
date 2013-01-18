//
//  client.h
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 12/20/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#ifndef __PacketTraceExplorer__client__
#define __PacketTraceExplorer__client__

#include "util.h"
#include "def.h"

class client_bw {
    
    double current_start;
    double step;
    int current_bytes;

public:
    client_bw(double _current_start, double _step);
    void add_packet(int payload, double ts);
    
};

#endif /* defined(__PacketTraceExplorer__client__) */
