/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   storage.h
 * Author: dkinasu
 *
 * Created on October 23, 2017, 4:47 PM
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <cstdlib>
#include <cstdio>
#include "memory.h"
#include "uthash.h"
#include "process.h"

#include <vector>
#include <map>
#include <algorithm>
#include <deque>

#define PBLK_SIZE 20971520
#define MAX_BLK_NUM 10000000 //400GB
#define NODE_NUM 6
#define K 4
#define M 2
#define B_RR 0
#define RANDOM 1
#define DA 2
#define QUEUE_NUM 1

typedef std::vector<int> IVec;
typedef std::vector<long> LVec;


// /*get the fp_node of the pblk*/
// #define pblk_get_addr(pblk_list, pblock)	\
// 					(struct fp_node *)((pblk_list)[(pblock)]->fp_node)
// set the fp_node of the pblk
// #define pblk_set_addr(pblk_list, pblock, node)	\
// 					(((pblk_list)[(pblock)])->fp = (void *)node)				


struct Node
{
	int num;
	long long Last_Busy_Time;
	long long pblk_used;
	long long Physical_Address;//ÏÂÒ»¸ö¸ÃÍ¨µÀ¿ÉÓÃµÄµØÖ·±àºÅ
	int failed;
	long long dup_count; //how many duplicates it saves
	long long speclative_read_access;
	long long write_access;
	long long read_access;
	long long total_access_count;
	long long parity_num;
	float network;
	std::vector<long long>queques;
};

extern struct Node **Cluster;
extern int CurNode;

extern long long sys_last_busy_time;



void Init_Cluster(int node_num);
void Print_Cluster_Time();
void Reset_time();
void Recover_Cluster();
int Create_Node_Failure(int seed);
extern long long degraded_read;
void Print_map(std::map<long long, int> &A);


/* define physical block_node struct */
struct pblk_node
{
	int ref_count;
	struct fp_node* fp;
	
	int node_num;
	long long stripe_num;
	int corrupted;
	long long pblk_num;
	int parity;
	int dummy;
	long long data_blk_num;
};

extern std::vector<struct pblk_node*> global_storage;
extern std::map<long long, long long> blk_mapping;

void Print_Blk_Mapping();
void Reset_blk_maping();

extern long long datablk_serial;
extern long long pblk_serial;
extern long long pblk_used;
extern long long dummy_pblk;
extern std::deque<long long> assign_set;

long long Allocate_a_pblk();

int Pblk_is_free(unsigned pblk_nr);
long long Mark_pblk_free(unsigned pblk_nr);

void Print_pblk(int pblk_num);

void Increase_pblk_ref_count(unsigned pblk_nr);
void Decrease_pblk_ref_count(unsigned pblk_nr);
void BA_RR(long long sp, int stride, int policy);
void RA(long long sp, int policy);
void DA_RR(long long sp, int stride, int policy);
void DA_RR_new(long long sp, int stride, int policy);
void DA_NO_RR(long long sp, int stride, int policy);
void DA_sra_b(long long sp, int stride, int policy);
void DA_access_b(long long sp, int stride, int policy);
void DA_lbt_b(long long sp, int stride, int policy);
void DA_lbt_mix(long long sp, int stride, int policy);
void P_balance(long long sp, int stride, int policy);

int sort_SOE();
int Min_Node(std::set<int> t);
int Min_Node_access(std::set<int> t1, std::set<int> t2);
int Min_Node_lbt(std::set<int> t1, std::set<int> t2);
int Min_Node_mix(std::set<int> t1, std::set<int> t2);
int Min_Node_speculative_access(std::set<int> t1, std::set<int> t2);

extern std::set<int>nodeset;
extern std::set<long long> dummyset;

void EC_Para(int node);
extern int ec_k;
extern int ec_m;

extern struct cluster_node *node;

struct SOE
{
	std::vector<struct traceline > data_pblk;
	// long *data_pblk;
	int full;
};

extern struct SOE soe; 

void Init_SOE(int k);
void Push_SOE(struct traceline p);
int Is_SOE_full(int k);
void Reset_SOE(int k);
void Print_SOE();
void Finish_time_SOE(int sp, int policy);
void Update_SOE_Time(long long &last);
int Search_fp_in_SOE(struct traceline *T_line);

struct stripe
{
	long long stripe_num;
	int length;
	std::vector <long long>data;
	std::vector <long long>parity;
	int corrupted;
	int used;
};

// int Is_stripe_free(int n);
void Init_a_stripe(struct stripe &s, int k, int m);
void Encode_a_stripe(int stripe_num, int m);
// long Assign_parity(int k);
long long Placement(struct SOE soe, int policy);
void Print_stripe(long stripe_num);
void Reset_stripe_tbl();
void Print_stripe_tbl();
// void Init_stripe_tbl(int max_stripe_num);

extern long long max_stripe_num;
extern long long stripe_num;
extern long long used_stripe_num;
extern std::vector<struct stripe> stripe_tbl;

void Init(int node_num, int cache_size_N);
void Reset_other();
void Reset_all(int node_num, int cache_size_N);
#endif /* STORAGE_H */



