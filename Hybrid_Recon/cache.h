

#ifndef CACHE_H
#define CACHE_H

#include <cstdlib>
#include <cstdio>
#include "storage.h"
#include "memory.h"
// #include "para.h"


// #include "uthash.h"

#include <vector>
#include <map>
#include <algorithm>
#include <list>

#define CACHE_SIZE 2000000 /*unit is pages*/
#define N_CACHE 0
#define F_CACHE 1
#define BOTH_CACHE 2



extern std::list< struct fp_node *> N_cache;
extern std::list< struct fp_node *> F_cache;
extern long long N_cache_size;
extern long long F_cache_size;
extern long long N_cache_hit;
extern long long F_cache_hit;
extern long long N_cache_miss;
extern long long F_cache_miss;

int Set_cache_size(int cache_num, long long size);
int Insert_cache(int cache_num, struct fp_node *fp);
void Evict_cache(int cache_num);
int Hit_cache(int cache_num, struct fp_node *fp);
int LRU_Ajust(std::list< struct fp_node *> &cache, struct fp_node *fp);
int Cache_full(int cache_num);
int Routine_N_cache(struct fp_node *fp);
void Reset_cache(int cache_num);

void Print_cache(std::list< struct fp_node *> &cache);

// define a list to be the N_cache

// extern long page_count_in_cache = 0;
// extern unsigned cache_hit = 0;
// extern unsigned cache_miss = 0;
// extern long cache_evict = 0;




#endif 
