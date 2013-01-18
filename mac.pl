use strict;
use warnings;

#system("gunzip _te_us_.tar.gz");
#system("tar xvf _te_us_.tar");
system("rm PTE.bin");
#system("echo > stdafx.h");
system("g++ data.cpp main.cpp gzstream.C -lpcap -I /Users/hjx/Documents/contest/ -o ./PTE.bin");

#system("./te_us");
