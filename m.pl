use strict;
use warnings;

print("compiling ...\n");
system("rm run.exe");
system("g++ data.cpp main.cpp bw.cpp util.cpp -lz -I /home/hjx/libpcap-1.3.0/ /home/hjx/libpcap-1.3.0/libpcap.so.1.3.0 -o ./run.exe");

