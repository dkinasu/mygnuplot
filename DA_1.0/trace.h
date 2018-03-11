/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   trace.h
 * Author: dkinasu
 *
 * Created on October 19, 2017, 11:11 AM
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <stdio.h>
#include <cstring>
#include <vector>
#include <cstring>
#include <set>
#include <deque>

// #include "memory.h"
#include "storage.h"

#ifndef TRACE_H
#define TRACE_H

// Predefine
#define SHA1SIZE 64
#define MAX_PATH_SIZE 5120
#define MAX_META_SIZE 100000

// Predefine for the diffrent read trace
#define ALL_REQ_READ 1
#define ALL_REQ_READ_RAN 2
#define RAW_TRACE 3
#define ALL_RANDOM 4
#define ALL_SHORT 5
#define ALL_LONG 6
#define NO_TRACE 0

#define DEGRADE_ALL_REQ_READ 5
#define DEGRADE_ALL_REQ_READ_RAN 6
#define DEGRADE_FIX_SIZE_RANDOM 7
#define DEGRADE_ALL_RANDOM 8

#define WRITE 1
#define READ 0


extern long long Count_WIO;
extern long long Count_RIO;
#define FINGERPRINT_DELETE_NUM 5
#define PAGE_SIZE_WRONG 6 

// Global paras from Trace
// Input paras
extern char ** files;
extern int trace_start; 
extern int trace_end;  
extern int ec_node;
extern int Policy;
//FIU trace
extern int trace;
extern long long max_fp_num;
extern long long max_blk_num;
extern long long cache_size;
extern long long global_time;

extern long long effective_line_count, write_count, read_count, delete_count, other_count;
extern long long total_line, bad_line, empty_line;
extern long long Count_WIO;
extern long long Count_RIO;
extern long long W_Request_lasting_time;
extern long long R_Request_lasting_time;

extern std::vector< long long >R_trace_CDF;//Read_trace profiling
extern std::vector< long long >W_trace_CDF;//Write_trace profiling

//a struct for each line of trace
struct traceline {

	long long trace_num;
	long long Arrive_Time;
	long long Finish_Time;
	long long Request_index;
	long long Address;
	long long pos;
	long long datablk;
	int Hit;

	char *Sha1;
	char *file_path;
	char *RequestID;
	char *Type;

	struct fp_node *fp;
	std::deque<long long> dup;//to contain the request index of the duplicated chunks.
};

extern long long First_Arrive_T;
extern long long Last_address;
extern long long req_serial;
int Split_Trace(char * buffer, struct traceline *T_line);
int TraceLine_Parse(char * buffer, struct traceline *T_line);
int Clear_Traceline(struct traceline *T_line);
void Print_traceline(struct traceline *T_line);

//Generate read_request
struct Read_request {

	long long R_Req_Index;
	long long Arrive_time;
	long long Finish_time;
	long long Lasting_time;

	long long t_straggler;

	float G_value;

	std::vector<long long>datablks;
	std::vector<long long>reponse_times;
};



void Generalize_ReadTrace_ALL(std::vector<struct Read_request> &Read, std::vector<struct Request> &Req_Tbl, int write);
void Generalize_ReadTrace_random(std::vector<struct Read_request> &Read, std::vector<struct Request> &Req_Tbl, int seed);
void Generalize_ReadTrace_All_random(std::vector<struct Read_request> &Read, long long pblk_num, int size, int node_num);
void Generalize_ReadTrace_partial_random(std::vector<struct Read_request> &Read, long long pblk_num, int size, int node_num);
void Generalize_ReadTrace_ALL_SPECIAL(std::vector<struct Read_request> &ReadTrace, std::vector<struct Request> &Req_Tbl, int write, int type);

void Print_ReadTrace(std::vector<struct Read_request> &ReadTrace);
void Calculate_Result(struct Result &t, std::vector<struct Read_request> ReadTrace, int res_type);
void Output_ReadTrace(std::vector<struct Read_request> &ReadTrace, int policy, int trace);

/**/
struct Request
{
	long long R_Req_Index;
	long long W_Req_Index;
	long long Arrive_time;
	long long Finish_time;
	long long Lasting_time;
	float G_value;
	std::vector<long long>reponse_times;
	long long L_time_straggler;

	long long straggler;

	char *RequestID;
	char *Type;
	std::set<int >used_nodes;
	std::set<int >remain;//contain the possible node index
	std::vector<long long>datablks;
};




extern struct Request CurReq;
//extern std::vector<struct Request> R_Req_Tbl;
//extern std::vector<struct Request> W_Req_Tbl;

extern std::vector< std::vector<struct Request> >R_Req_Tbl;
extern std::vector< std::vector<struct Request> >W_Req_Tbl;
extern char *Last_RequestID;

void Init_CurRequest();
void Clear_CurRequest();
void Init_LastReqestID();
void Print_Req_used_nodes(std::vector<struct Request> &Req_Tbl, long long index);
void Print_Req_remain_nodes(std::vector<struct Request> &Req_Tbl, long long index);




//void Output_Result(char *result);
int Argv_Parse(int argc, char ** argv, char *file_prefix, char *file_suffix);

// create a default setting
void Create_Default_Setting(char *** p);

void Output_Result(int policy);
void Output_Data(int policy, int fiu);

extern std::vector<long long>CDF;

#endif /* TRACE_H */

