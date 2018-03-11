/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   process.h
 * Author: dkinasu
 *
 * Created on October 23, 2017, 10:54 PM
 */

#ifndef PROCESS_H
#define PROCESS_H

#include "memory.h"
#include "storage.h"
#include "trace.h"
#include "cache.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <iostream>
#include <fstream>
#include <map>

#define BASELINE 0
#define ERASURE  1

// the whole simulator uses us as the unit of time.   1us = 1e-6 s= 1e3 ns
// disk: an average read speed of 128 MB/s and a write speed of 120 MB/s   (4KB read is 40us while 60us to write)
// SSD: an average 550 MB/s read 520 MB/s write   (4KB read is around 8us while 10 us)
// The average encoding/decoding speed could reach 2GB/s-5.8GB/s
#define READ_LATENCY 2000 //60us (SSD Read latency for a 4KB page)   it will becomes 600us  if disk
#define WRITE_LATENCY 4000 //us (SSD Read latency for a 4KB page)   it will becomes  1500us   if disk
#define ACCESS_CACHE 20 // 100us, cache miss time is overshadowed by the serving.   ()  I do not know.
#define ACK_TIME 0 //sending ack back. usually it can be ignored.
// #define DATA_TRANSMISSION (3.2 * K) // us (4KB * K/10Gb/s = 3.2 us)   10Gb/s Ethernet is common   (100-300 us for 4KB transmission over a 100Mbps switch)
#define DATA_TRANSMISSION 2000


// #define DATNETWORK_COST (3.2 * K)// us (4KB * K/10Gb/s = 3.2 us)   10Gb/s Ethernet is common   (100-300 us for 4KB transmission over a 100Mbps switch)

#define RECON_COST (3*K)    //reconstruct the whole file (assuming the encoding rates are)
#define DECODE_COST (1.5*K)  //decoding one chunk (assuming the encoding rates are)
#define SHA1_COST 80//  //us (SSD hash calculation cost for a 4KB page with SHA1
#define ENCODE_COST (2*K) //encoding a page is 0.8us-2us, so encoding a stripe of K is (0.8--2)*K us 
#define PLACEMENT_THRESHOLD   15000000000000 //us Time threshold for wait

#define DUP_TEST   500 //us Time threshold for wait
#define UNIQ_WRITE 1000
#define READ_CACHE 200
#define READ_STORAGE 1500


using namespace std;

struct Result
{
	int policy;
	char *p_name;
	std::map<int, float> value;
	long long total_latency;
};

extern std::vector<struct Result> Final;

struct Result Process(char **files, int trace_start, int trace_end, struct traceline *T_line, int baseline, int policy, int iteratimes, int degraded);
void Write_Process(struct traceline *T_line, int baseline, int policy);
void Read_by_FP(struct traceline *T_line, int baseline);
void Read_by_lpblk(struct traceline *T_line, int ec);
void Read_Table(std::vector<struct Read_request> &Read_trace);
void Delete_Process(struct traceline *T_line, int baseline);
int Request(struct traceline *T_line, int ec);
void Print_Req_Tbl(std::vector<struct Request> &Req_Tbl, int write);
void Output(char * filename);
void Update_R_Request_Time(struct traceline *T_line, int policy);
long long Degraded_read(long long pblk_num);
extern long long last_datablk_by_fp;//record last found fp in read.

void Process_ReadTrace(std::vector<struct Read_request> &Read_trace, std::vector<struct Request> &W_Req_Tbl, int tracetype, struct Result &res, int iteratimes);
void Cal_CDF(float &value);
void CDF_calculation(vector<long long> &array, int write);
float Calculate_G(long long Count_RIO, int policy);

// define 6 situations of write
extern long long w_case_1;
extern long long w_case_2;
extern long long w_case_3;
extern long long w_case_4;
extern long long w_case_5;
extern long long w_case_6;

// define 6 situations of read
extern long long r_case_1;
extern long long r_case_2;
extern long long r_case_3;
extern long long r_case_4;
extern long long r_case_5;
extern long long r_case_6;
extern long long readline_not_by_fp;
extern long long tmp;
extern long long read_blk_num;
//char *hex_to_binary(char *src, size_t src_size);


#endif /* PROCESS_H */

