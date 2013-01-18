//
//  util.h
//  PacketTraceExplorer
//
//  Created by Junxian Huang on 11/18/12.
//  Copyright (c) 2012 Junxian Huang. All rights reserved.
//

#ifndef __PacketTraceExplorer__util__
#define __PacketTraceExplorer__util__

#include <iostream>
#include <cmath>
#include <sstream>
#include <vector>

#include "def.h"

#define MAX_FILE_ID 2781

using namespace std;

void MyAssert(bool x, int aid);
bool isClient(in_addr addr);
const char * ConvertIPToString(unsigned int ip);

//Usage: NumberToString (Number);
template <typename T>
string NumberToString (T Number) {
    ostringstream ss;
    ss << Number;
    return ss.str();
}

//Usage: StringToNumber<Type> (String);
template <typename T>
T StringToNumber (const string &Text) {
    istringstream ss(Text);
    T result;
    return ss >> result ? result : 0;
}

u_short bswap16(u_short);
u_int bswap32(u_int);
//uint64 bswap64(uint64);

vector <string> split(const string& str, const string& delimiter = " ");

#endif /* defined(__PacketTraceExplorer__util__) */
