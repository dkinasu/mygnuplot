
#include "trace.h"
#include "process.h"
#include "memory.h"
#include "storage.h"
#include "cache.h"

#define SHA1_COST 80


#define MAXTRACELINE_W 1000//traceÖÐµÄÐ´tracelineÊýÄ¿ 52026 write_2 16 new 88261
#define MAXTRACELINE_TEST 6000

#define MAX_ADDR 2000000
#define CHANNEL_NUM 12

#define THRESHOLD 2000 // µ¥Î»us, ¼´1000us=1ms





// trace.h
char **files;/* file_path for all the tracefiles*/
int trace_start;
int trace_end; 
int ec_node = NODE_NUM;
long long max_fp_num;
long long max_blk_num = 200000;
long long cache_size = 0;
long long First_Arrive_T = 0;
//FIU trace
int trace = 1;
int Policy = 1;

std::vector<long long>CDF;

std::vector< long long >R_trace_CDF;//Read_trace profiling
std::vector< long long >W_trace_CDF;//Write_trace profiling

struct traceline T_line;
long long Last_address = 0;
long long req_serial = 0;
char **default_argv = NULL;
char *file_prefix = NULL;
char *file_suffix = NULL;

long long total_line, bad_line, empty_line;
long long effective_line_count, write_count, read_count, delete_count, other_count;

struct Request CurReq;
//std::vector<struct Request> R_Req_Tbl(0);
//std::vector<struct Request> W_Req_Tbl(0);

std::vector< vector<struct Request> >R_Req_Tbl;
std::vector< vector<struct Request> >W_Req_Tbl;

char *Last_RequestID;

long long Count_WIO = 0;
long long Count_RIO = 0;
long long W_Request_lasting_time = 0;
long long R_Request_lasting_time = 0;





// stroage.h
//struct Node *Cluster[K+M];
struct Node **Cluster;
long long degraded_read = 0;

long long sys_last_busy_time = 0;
long long global_time = 0;
int CurNode = -1;

long long pblk_used = 0;
long long pblk_serial = 0;
long long dummy_pblk = 0;
std::vector<struct pblk_node*> global_storage(0);
std::map<long long, long long> blk_mapping;
long long datablk_serial = 0;
std::set<long long> dummyset;
std::set<int>nodeset;


struct SOE soe; 

std::deque<long long> assign_set(0);

long long max_stripe_num;
long long stripe_num = 0;
long long used_stripe_num = 0;
std::vector<struct stripe> stripe_tbl(0);

int ec_k = K;
int ec_m = M;



// memory.h
struct fp_node * fp_store = NULL; /* hashtable for fp_store */
unsigned fp_count;
//struct list_head lru_fp_list;
long long total_fp_hit = 0;


int fp_search_count;

int fp_hit;

long long fp_in_N_cache_count = 0;
long long fp_in_F_cache_count = 0;


// cache.h 
std::list< struct fp_node *> N_cache(0);
std::list< struct fp_node *> F_cache(0);

long long N_cache_size = 0;
long long F_cache_size = 0;
long long N_cache_hit = 0;
long long F_cache_hit = 0;
long long N_cache_miss = 0;
long long F_cache_miss = 0;


// process.h 
// define 6 situations of write
long long w_case_1 = 0;
long long w_case_2 = 0;
long long w_case_3 = 0;
long long w_case_4 = 0;
long long w_case_5 = 0;
long long w_case_6 = 0;

// // define 6 situations of read
long long r_case_1 = 0;
long long r_case_2 = 0;
long long r_case_3 = 0;
long long r_case_4 = 0;
long long r_case_5 = 0;
long long r_case_6 = 0;
long long readline_not_by_fp = 0;


long long tmp = 0;
long long read_blk_num = 0;
long long last_datablk_by_fp = -1;//record last found fp in read. -1 means starting.

std::vector<struct Result> Final;


