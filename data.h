//
//  data.h
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 11/18/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#ifndef __PacketTraceExplorer__data__
#define __PacketTraceExplorer__data__

#include <iostream>
#include <cmath>
#include <ext/hash_set>
#include <ext/hash_map>
#include <map>
#include <fstream>

#include "pcap.h" //in the server, pcap is not in system path
#include "util.h"
#include "def.h"
#include "tcp_flow.h"
#include "client.h"
#include "user.h"

int init_global();
int read_pcap_trace(const char * filename);

#endif /* defined(__PacketTraceExplorer__data__) */
