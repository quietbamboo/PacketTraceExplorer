//
//  util.cpp
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 11/24/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#include "util.h"

void MyAssert(bool x, int aid) {
	if (!x)
		cerr << "Assertion failed! ID=" << aid << endl;
}

bool isClient(in_addr addr) {
    if (RUNNING_LOCATION == RLOC_CONTROL_CLIENT || RUNNING_LOCATION == RLOC_CONTROL_SERVER)
        //for Yihua's trace, server trace: client is 198.*; client trace: client is 10.*; and 32.* for 3G trace
        return ((addr.s_addr & 0xFF) == 192 ||
                (addr.s_addr & 0xFF) == 198 ||
                (addr.s_addr & 0xFF) == 10 ||
                (addr.s_addr & 0xFF) == 32) ? true : false;
    else
        return ((addr.s_addr & 0xFF) == 10) ? true : false;
}

const char * ConvertIPToString(unsigned int ip) {
	static char ipstr[17];
	sprintf(ipstr, "%d.%d.%d.%d",
            ip & 0xFF,
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            ip >> 24);
	return ipstr;
}

u_short bswap16(u_short i) {
    return ((i & 0xFF) << 8) + ((i >> 8) & 0xFF);
}

u_int bswap32(u_int i) {
    return ((i & 0xFF) << 24) + ((i & 0xFF00) << 8) + ((i >> 8) & 0xFF00) + ((i >> 24) & 0xFF);
}

//uint64 bswap64(uint64 i) {
//    return ((i & 0xFF) << 56) + ((i & 0xFF00) << 40) + ((i & 0xFF0000) << 24) + ((i & 0xFF000000) << 8) +
//        ((i >> 8) & 0xFF000000) + ((i >> 24) & 0xFF0000) + ((i >> 40) & 0xFF00) + ((i >> 56) & 0xFF);
//}

vector <string> split(const string& str, const string& delimiter) {
    
    if (delimiter.size() == 0) {
        cerr << "delimiter should not be empty" << endl;
        return vector<string>(0);
    }
    
    vector <string> tokens;
    string::size_type lastPos = 0;
    string::size_type pos = str.find(delimiter, lastPos);
    
    while (string::npos != pos) {
        // Found a token, add it to the vector.
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        lastPos = pos + delimiter.size();
        pos = str.find(delimiter, lastPos);
    }
    //add the last, if not the only, token
    tokens.push_back(str.substr(lastPos, str.size() - lastPos));
    return tokens;
}

string compress_user_agent(string ua) {
    string::iterator it, it_tmp;
    for (it = ua.begin() ; it < ua.end() ; ) {
        if ((*it >= 'a' && *it <= 'z') || (*it >= 'A' && *it <= 'Z')) {
            it++;
        } else {
            it_tmp = it;
            it++;
            ua.erase(it_tmp);
            it--;
        }
    }
    return ua;
}

string process_content_type(string str) {
    string::iterator it, it_tmp;
    for (it = str.begin() ; it < str.end() ; ) {
        if (*it >= 'A' && *it <= 'Z') {
            *it = (char)((*it) - 'A' + 'a'); //to lower case
        } else if (*it == ' ') {
            it_tmp = it;
            it++;
            str.erase(it_tmp);
            it--;
        }
        
        if (*it == ';') {
            str.erase(it, str.end());
            break;
        }
        it++;
    }
    return str;
}

