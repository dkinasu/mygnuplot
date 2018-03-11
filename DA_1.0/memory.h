
#ifndef MEMORY_H
#define MEMORY_H

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "trace.h"
#include "rbtree.h"
#include "lish.h"
#include <list>
#include "uthash.h"
#include <algorithm>
#include "cache.h"
//#include "storage.h"
//#include "process.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>


#define DATA_SIZE 4096 /*1 page = 4KB*/




/* define fp_node struct and all the related operation */
struct fp_node{	
	// bool identity;
  	int hit; //hit means another hit excluding itself
  	int in_N_cache; /*whether it is in the cache*/
	int in_F_cache; /*whether it is in the cache*/
	char *fingerprint; //make it as the key/
	struct pblk_node *p;
	long long Request_index; // the request index of the first occurence of the fp in a traceline
	// unsigned pblk_nr; /*physical block number*/
	//char status;
	UT_hash_handle hh; /* makes this structure hashable */
};

extern struct fp_node *fp_store; /* hashtable for fp_store */
extern unsigned fp_count;


extern long long total_fp_hit;

extern int fp_search_count;

extern int fp_hit;

extern long long fp_in_N_cache_count;
extern long long fp_in_F_cache_count;

void Decrease_fp(struct page_node *p);

struct fp_node *Init_fp_node(struct traceline *T_line);
void Add_fp(struct fp_node *s);
struct fp_node * Find_fp(char * fp);
void Del_fp_from_fp_store(struct fp_node* s);//delele fp from fp store and free the space
void Print_fps();
void Count_fp();
void Reset_fp_store();

int fp_is_in_N_cache(struct fp_node *fp);
int fp_is_in_F_cache(struct fp_node *fp);

int Mark_fp_in_N_cache(struct fp_node *fp);
int Mark_fp_in_F_cache(struct fp_node *fp);
int Mark_fp_not_in_N_cache(struct fp_node *fp);
int Mark_fp_not_in_F_cache(struct fp_node *fp);



/* define logic address struct for a file and all the related operation */
struct laddr_node{
  	struct rb_node node;
	char *file_path;//using file_path
  	struct rb_root *page_tree; /* each laddr_node has a rb_page_tree*/
};

//search a file in a rb_tree
struct laddr_node *Init_laddr_node(char *file_path);
struct laddr_node *Find_filepath(struct rb_root *root, char *file_path);
void Add_laddr_node(struct rb_root *root, struct laddr_node *laddr_node);
void Del_laddr_node(struct rb_root *root, struct laddr_node *delete_node);
void Del_file(struct rb_root *root, char *file_path);


//laddr_tree is for searching the file
extern struct rb_root laddr_tree;


/* define page_node struct struct for a page */
struct page_node{
  	struct rb_node node;
  	// struct list_head lru_list;
	long int pos;//the ith numbered page in a file
	struct fp_node *fp;
  	// unsigned pblk_nr; /*corresponding pblk number*/
};

// //
struct page_node *Init_page_node(long long pos, struct fp_node *fp);
struct page_node *Find_page(struct rb_root *root, long int pos);
void Add_page_node(struct rb_root *root, struct page_node *page_node);
void Del_page_node(struct rb_root *root, struct page_node *delete_node);

void Destroy_page_tree(struct rb_root *root);


// //add the fp into the list head with lru policy
// void Page_lru_add(struct page_node *p);
// void Page_lru_del(struct page_node *p);
// void Print_lru_cache();
// int Is_cache_full();
// void Page_lru_evict(int n);/*evict n lru pages out*/

// struct page_node * Find_LRUed_page(); /*this function returns the least used page*/
// struct page_node * Find_page_node_lru(long unsigned pblk_nr); /*this function is not working*/
// int Check_page_node_lru(struct page_node *p);

// void Page_lru_accessed_adjust(long unsigned pblk_nr);


// extern struct list_head lru_page_list;

















#endif /* MEMORY_H */


