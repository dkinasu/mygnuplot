/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "memory.h"

void delete_all()
{
	  struct fp_node *current_user, *tmp;

	  HASH_ITER(hh, fp_store, current_user, tmp)
	  {
	    HASH_DEL(fp_store,current_user);  /* delete; users advances to next */
	    free(current_user);            /* optional- if you want to free  */
	  }
}


void Reset_fp_store()
{
	delete_all();
	fp_store = NULL; /* hashtable for fp_store */

	fp_count = 0;
	total_fp_hit = 0;
	fp_search_count = 0;
	fp_hit = 0;

	fp_in_N_cache_count = 0;
	fp_in_F_cache_count = 0;
}


/*operation for the fp_node*/

struct fp_node *Init_fp_node(struct traceline *T_line)
{
	struct fp_node *new_node = NULL;
	new_node = (struct fp_node*)malloc(sizeof(struct fp_node)); 
	
	if (!new_node)
		return NULL;

	char *fingerprint = T_line->Sha1;

	if (fingerprint != NULL)
	{
		new_node->fingerprint = strdup(fingerprint);
		//printf("Init in the struct_lenth: %lu, original_lenth %lu\n", strlen(new_node->fingerprint), strlen(fingerprint));
		//rb_init_node(&new_node->node);
		// new_node->identity = true;
		new_node->hit = 0;
		new_node->p = NULL;
		new_node->in_N_cache = 0; /*whether it is in the cache*/
		new_node->in_F_cache = 0;
		new_node->Request_index = T_line->Request_index;
		return new_node;
	} else 
	{
		printf("fingerprint doesn't exist!");
		return NULL;
	}
}


int fp_is_in_N_cache(struct fp_node *fp)
{
	std::list< struct fp_node *>::iterator li;

	li = std::find(N_cache.begin(), N_cache.end(), fp);
	return (li != N_cache.end());
}

int fp_is_in_F_cache(struct fp_node *fp)
{
	std::list< struct fp_node *>::iterator li;

	li = std::find(F_cache.begin(), F_cache.end(), fp);
	return (li != F_cache.end());
}

int Mark_fp_in_N_cache(struct fp_node *fp)
{
	fp->in_N_cache = 1;
	fp_in_N_cache_count++;

	return fp_in_N_cache_count;
}

int Mark_fp_in_F_cache(struct fp_node *fp)
{
	fp->in_F_cache = 1;
	fp_in_F_cache_count++;

	return fp_in_F_cache_count;
}

int Mark_fp_not_in_N_cache(struct fp_node *fp)
{
	fp->in_N_cache = 0;
	fp_in_N_cache_count--;

	return fp_in_N_cache_count;
}

int Mark_fp_not_in_F_cache(struct fp_node *fp)
{
	fp->in_F_cache = 0;
	fp_in_F_cache_count--;

	return fp_in_F_cache_count;
}


void Count_fp()
{
	unsigned int num_fp = 0;
	num_fp = HASH_COUNT(fp_store);
	printf("there are %u fps in Hashtable\n", num_fp); 
}

void Add_fp(struct fp_node *s)
{
		//printf("Before: added len: %u      %lu\n",(unsigned)uthash_strlen(s->fingerprint), strlen(s->fingerprint));
		HASH_ADD_STR(fp_store, fingerprint ,s);
		//printf("After:  added len: %u      %lu\n",(unsigned)uthash_strlen(s->fingerprint), strlen(s->fingerprint));
}


struct fp_node * Find_fp(char * fp)
{
	
	//printf("Finding fp [%d] %s\n", line_count, fp);
	struct fp_node *s;
	
    HASH_FIND_STR(fp_store, fp, s);  
    
    return s;
}


void Del_fp_from_fp_store(struct fp_node* s)
{
	if(Find_fp(s->fingerprint) != NULL)
	{
		HASH_DEL(fp_store, s);
	}
	
	if(s != NULL)
		free(s);
}


void Print_fps()
{
	
	struct fp_node *s;
	int i = 0;

	printf("\n----------------------\n");
    for(s = fp_store; s != NULL; s = (struct fp_node *) s->hh.next) 
    {
    	i++;
    	//char dst[HASHVALSIZE];
    	//binary_to_hex(dst, s->fingerprint, SHA1SIZE);
    	//dst[HASHVALSIZE] = '\0';
    	//printf("[%d]: %s\n", i, dst);
    	printf("[%5d]: %s\n", i, s->fingerprint);
        //printf("Fingerprint is %s:  pblk_nr%u\n", s->fingerprint, s->pblk_nr);
    }
    printf("----------------------\n");
    /*
	struct fp_node *cur_fp, *tmp;
	int i = 0;

  	HASH_ITER(hh, fp_store, cur_fp, tmp) 
  	{
  		i++;
  		printf("[%d]: %s\n", i, cur_fp->fingerprint);
  	}
	*/
}


// /*
// //add the fp into the list head with lru policy
// static inline void fp_lru_add(struct list_head *lru_list, struct in_mem_pos *fp)
// {
// 	list_add(&fp->lru_list, lru_list);
// 	//fp_lru_print(lru_list);
// }*/



// /*search a file in a rb_tree*/
struct laddr_node *Init_laddr_node(char *file_path)
{
	struct laddr_node *new_node = NULL;

	struct rb_root *page_tree;

	new_node = (struct laddr_node *) malloc(sizeof(struct laddr_node));

	if (!new_node)
	{
		return NULL;
	}

	/*Initialiation*/
	new_node->file_path = (char *) malloc(strlen(file_path) + 1);
	memcpy(new_node->file_path, file_path, strlen(file_path));
	new_node->file_path[strlen(file_path)] = '\0';

	/*new_node itself is a rb_node to be inserted in the laddr_tree*/	
	rb_init_node(&new_node->node);
	page_tree = (struct rb_root*) malloc(sizeof(struct rb_root));
	page_tree->rb_node = NULL;
	new_node->page_tree = page_tree;

	return new_node;
}

struct laddr_node *Find_filepath(struct rb_root *root, char *file_path)
{
	struct rb_node *new_node = root->rb_node;

	int result;
	/*iterate the rb_tree*/
	while(new_node)
	{
		//container is just like convert new_node->node into struct ladd_node *
		struct laddr_node *tmp = container_of(new_node, struct laddr_node, node);

		if (strlen(file_path) < strlen(tmp->file_path))
		{
			result = -1;
		}
		else if (strlen(file_path) > strlen(tmp->file_path))
			result = 1;
		else
			result = memcmp(file_path, tmp->file_path, strlen(tmp->file_path));

		if(result < 0)
			new_node = new_node->rb_left;
		else if (result > 0)
			new_node = new_node->rb_right;
		else
		{
			assert((result == 0) && (strlen(file_path) == strlen(tmp->file_path)));
	  		return tmp;
		}

	}

	return NULL;
}

// /*insert the node into the ladd_tree. */
void Add_laddr_node(struct rb_root *root, struct laddr_node *laddr_node)
{
	struct rb_node **new_node = &(root->rb_node), *parent = NULL;

	int result;

	while (*new_node) 
  	{
  		
  		struct laddr_node *tmp = container_of(*new_node, struct laddr_node, node);
		parent = *new_node;

		if ((strlen(laddr_node->file_path) < strlen(tmp->file_path)))
  			result = -1;
  		else if ((strlen(laddr_node->file_path) > strlen(tmp->file_path)))
  			result = 1;
  		else
  			result = memcmp(laddr_node->file_path, tmp->file_path, strlen(tmp->file_path));
		
		if (result < 0)
			new_node = &((*new_node)->rb_left);
		else if (result > 0)
			new_node = &((*new_node)->rb_right);
  		else 
  		{
	  		assert(0);
  		}
  	}

  	rb_link_node(&laddr_node->node, parent, new_node);
  	rb_insert_color(&laddr_node->node, root);

}

// void Del_laddr_node(struct rb_root *root, struct laddr_node *delete_node)
// {

// 	unsigned pblk_nr;

	
// 	free(delete_node->file_path);
// 	delete_node->file_path = NULL;

// 	Destroy_page_tree(delete_node->page_tree);
	
// 	rb_erase(&delete_node->node, root);

		
// 	free(delete_node);
// 	delete_node = NULL;

// }

// void Del_file(struct rb_root *root, char *file_path)
// {
// 	//printf("Start deleting a file\n");
// 	//Del_laddr_node(root, delete_node);
// 	//printf("Finish deleting a file\n");


// 	struct laddr_node *delete_node;
	
// 	delete_node = Find_filepath(root, file_path);
	
// 	if(delete_node != NULL)
// 	{
// 		Del_laddr_node(root, delete_node);
// 	}
// 	return;

// 	printf("Finish deleting a file\n");

// }

void Decrease_fp(struct page_node *p)
{
	if(p->fp->hit == 0)
	{
		//delete this from fp store
		struct fp_node* tmp = p->fp;
		p->fp = NULL;
		Del_fp_from_fp_store(tmp);//delele fp from fp store and free the space of s

	}
	else if(p->fp->hit > 0)
	{
		p->fp->hit--;
	}
	else
	{
		printf("[Error]: the fp hit is negetive!\n");
	}
}




struct page_node *Init_page_node(long long pos, struct fp_node *fp)
{
	struct page_node * new_node = NULL;
	new_node = (struct page_node *)malloc(sizeof(struct page_node));

	if(!new_node)
		return NULL;

	// new_node->lru_list.next = &(new_node->lru_list);
	// new_node->lru_list.prev = &(new_node->lru_list);

	new_node->pos = pos;
	new_node->fp = fp;
	// new_node->pblk_nr = pblk_nr;

	rb_init_node(&new_node->node);
	//printf("line[%d] New page_node->pblk_nr = %u, pos = %ld\n", line_count, new_node->pblk_nr, new_node->pos);
	return new_node;
}

struct page_node *Find_page(struct rb_root *root, long int pos)
{
	struct rb_node *node = root->rb_node;
  	
  	while (node) 
  	{
  		struct page_node *tmp = container_of(node, struct page_node, node);
		
		if (pos < tmp->pos)
			node = node->rb_left;
		else if (pos > tmp->pos)
			node = node->rb_right;
  		else
	  		return tmp;
  	}
  	return NULL;

}

void Add_page_node(struct rb_root *root, struct page_node *page_node)
{
	struct rb_node **tmp = &(root->rb_node), *parent = NULL;
	int x = 1;

  	while (*tmp) 
  	{
  		struct page_node *this_node = container_of(*tmp, struct page_node, node);
		
		parent = *tmp;
		
		if (page_node->pos < this_node->pos)
			tmp = &((*tmp)->rb_left);
		else if (page_node->pos > this_node->pos)
			tmp = &((*tmp)->rb_right);
  		else 
  		{
	  		assert(x == 0);
  		}
  	}

  	rb_link_node(&page_node->node, parent, tmp);
  	rb_insert_color(&page_node->node, root);


}


// void Del_page_node(struct rb_root *root, struct page_node *delete_node)
// {

// 	rb_erase(&delete_node->node, root);
// 	/*destruct the page_node from the list*/
// 	if (Check_page_node_lru(delete_node))
// 	{
// 		Page_lru_del(delete_node);
// 		/* code */
// 	}
	
// 	//Decrease_pblk_ref_count(delete_node->pblk_nr);
// 	free(delete_node);	
// 	delete_node = NULL;

// }


// // //Destroying the rb_page tree and its pblk.
// void Destroy_page_tree(struct rb_root *root)
// {
// 	struct page_node *page_node;
// 	struct rb_node *node;

// 	node = rb_first(root);
// 	page_node = rb_entry(node, struct page_node, node);

// 	while (page_node) 
// 	{
// 		node = rb_next(&page_node->node);
		
// 		Del_page_node(root, page_node);
// 		/*
// 		rb_erase(&page_node->node, root);
// 		if(Pblk_is_in_mem(page_node->pblk_nr))
// 		{
// 				Page_lru_del(page_node);
// 				storage[page_node->pblk_nr]->in_mem = 0;
// 		}
// 		Decrease_pblk_ref_count(page_node->pblk_nr);

// 		free(page_node);
	
// 		if (!node) 
// 		{
// 			page_node = NULL;
// 			break;
// 		}
// 		*/
		
// 		page_node = rb_entry(node, struct page_node, node);
// 	}
// }


// //add a page node to the data LRU list
// void Page_lru_add(struct page_node *p)
// {	
// 	list_add(&p->lru_list, &lru_page_list);
// 	//Mark_pblk_in_mem(p->pblk_nr);
// 	page_count_in_cache++;
// 	//printf("line[%d] Adding page_node to LRU: pblk_nr = %u pos = %ld\n", line_count, p->pblk_nr, p->pos);
// 	//printf("Finish Adding new page into LRU\n");
// }

// void Page_lru_del(struct page_node *p)
// {
// 	list_del(&p->lru_list);
// 	//storage[p->pblk_nr]->in_mem = 0;
// 	page_count_in_cache--;
// 	//printf("Deleting page_node from LRU: pblk_nr = %u pos = %ld\n", p->pblk_nr, p->pos);
// 	//printf("Finish Deleting page from LRU\n");
// }




// int Is_cache_full()
// {
// 	//printf("page_count_in_cache: %ld cache_size: %ld\n", page_count_in_cache, cache_size);
// 	return (page_count_in_cache >= cache_size);
// }


// /*trying to find a page with given pblk_nr in the LRU*/
// struct page_node * Find_page_node_lru(long unsigned pblk_nr)
// {
	
// 	int counter = 0;
	
// 	struct page_node *tmp;
	
// 	struct list_head *p, *q;

// 	assert(!list_empty(&lru_page_list));

// 	//printf("Iterating LRU lists\n");
	
// 	list_for_each_safe(p, q, &lru_page_list) 
// 	{
		
// 		counter++;
// 		//printf("Counter = %d\n", counter);

// 		tmp = list_entry(p, struct page_node, lru_list);
		
// 		//printf("tmp->pos: %ld\n", tmp->pos);
		
// 		if (tmp->pblk_nr == pblk_nr)
// 		{
// 			//printf("Cache hit! tmp->pblk_nr: %u pblk_nr: %lu\n", tmp->pblk_nr, pblk_nr);
// 			return tmp;
// 		}
		
// 	}

// 	//printf("[%d] [Not Found!] End searching LRU\n", counter);

// 	return NULL;
// }

// /*check if a page is inside or not*/
// int Check_page_node_lru(struct page_node *pn)
// {
	
// 	int counter = 0;
	
// 	struct page_node *tmp;
	
// 	struct list_head *p, *q;

// 	assert(!list_empty(&lru_page_list));

// 	//printf("iterating LRU lists\n");
	
// 	list_for_each_safe(p, q, &lru_page_list) 
// 	{
		
// 		counter++;
// 		//printf("Counter = %d\n", counter);

// 		tmp = list_entry(p, struct page_node, lru_list);
		
// 		//printf("tmp->pos: %ld\n", tmp->pos);
		
// 		if (tmp == pn)
// 		{
// 			//printf("Check Page in LRU: YES!\n");
// 			return 1;
// 		}
		
// 	}

// 	//printf("[%d] Check page in LRU: NO\n", counter);

// 	return 0;
// }



// void Page_lru_accessed_adjust(long unsigned pblk_nr)
// {

// 	//if (Pblk_is_in_mem(pblk_nr))
// 	{
// 		struct page_node *p = Find_page_node_lru(pblk_nr);
// 		Page_lru_del(p);
// 		Page_lru_add(p);
// 	}
	
// 	//printf("Finishing Adjusting LRU\n");
// }

// struct page_node * Find_LRUed_page()
// {
// 	struct page_node *tmp;
// 	struct list_head *p;

// 	int counter = 0;

// 	if(list_empty(&lru_page_list))
// 	{
// 		printf("Cache is empty\n");
// 		return NULL;
// 	}
// 	else
// 	{
// 		//printf("Head->next: %p head->prev: %p\n", (&lru_page_list)->next, (&lru_page_list)->prev);
// 		//tmp = list_entry(&lru_page_list, struct page_node, lru_list);
// 		//printf("[%d]tmp->pos: %ld\n",counter, tmp->pos);

// 		list_for_each(p, &lru_page_list)
// 		{
			
// 			counter++;
// 			tmp = list_entry(p, struct page_node, lru_list);

// 			//printf("[%d]tmp->pblk_nr: %u pos: %ld\n",counter, tmp->pblk_nr, tmp->pos);
			
// 			if (counter >= 15)
// 			{
// 				break;
// 				/* code */
// 			}
// 		}
// 	}

// 	//printf("The LRUed page->pblk_nr:%u pos: %ld\n", tmp->pblk_nr, tmp->pos);
// 	return tmp;
// }

// void Print_lru_cache()
// {
// 	struct page_node *tmp;
// 	struct list_head *p;

// 	int counter = 0;
	
// 	printf("---------Printing LRU(rightmost)---------\n");

// 	if(list_empty(&lru_page_list))
// 	{
// 		printf("Cache is empty\n");
// 	}
// 	else
// 	{
// 		list_for_each(p, &lru_page_list)
// 		{
// 			counter++;
// 			tmp = list_entry(p, struct page_node, lru_list);
// 			printf("%*s pblk_nr: %u  pos:%ld\n", counter, " ", tmp->pblk_nr, tmp->pos);	
// 		}
// 	}
	
// 	printf("-----------------------------------\n");

// }

// void Page_lru_evict(int n)
// {
// 	int min = (n <= page_count_in_cache?n:page_count_in_cache);
// 	//printf("n = %d page_count_in_cache = %ld min = %d\n", n, page_count_in_cache, min);

// 	for (int i = 0; i < min; ++i)
// 	{
// 		struct page_node *p = Find_LRUed_page();

// 		if(p != NULL)
// 		{
// 			//cache_miss++;
// 			cache_evict++;
// 			Page_lru_del(p);
// 		}
		
// 	}
// 	return ;
// }
