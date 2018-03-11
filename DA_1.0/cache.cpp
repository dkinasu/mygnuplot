#include "cache.h"



int Set_cache_size(int cache_num, long long size)
{
	if (size <= 0)
	{
		N_cache_size = -1;
	}
	else
	{
		if(cache_num == 0)
		{		 
			 N_cache_size = size;
		}
		else if(cache_num == 1)
		{
			
			F_cache_size = size;
		}
		else if(cache_num == 2)
		{
			N_cache_size = size;
			F_cache_size = size;
		}
	}
	
	return 0;

}

int Insert_cache(int cache_num, struct fp_node *fp)
{

	std::list< struct fp_node *> *cache = NULL; 
	if(cache_num == 0)
	{
		cache = &N_cache;
		Mark_fp_in_N_cache(fp);
	}
	else if(cache_num == 1)
	{
		cache = &F_cache;
		Mark_fp_in_F_cache(fp);
	}

	cache->push_front(fp);

	return 0;
}

void Evict_cache(int cache_num)
{

	std::list< struct fp_node *> *cache = NULL; 
	std::list< struct fp_node *>::iterator li;

	struct fp_node *p = NULL;

	
	if(cache_num == 0)
	{
		cache = &N_cache;
		p = cache->back();
		Mark_fp_not_in_N_cache(p);
	}
	else if(cache_num == 1)
	{
		cache = &F_cache;
		p = cache->back();
		Mark_fp_not_in_F_cache(p);
	}

	return cache->pop_back();
}

int Hit_cache(int cache_num, struct fp_node *fp)
{
	int N_hit = 0;
	int F_hit = 0;

	// printf("inside Hit_cache: p->pblk_nr: %u\n", p->pblk_nr);
	N_hit = fp_is_in_N_cache(fp);
	// printf("inside Hit_cache\n");

	F_hit = fp_is_in_F_cache(fp);
	
	if(cache_num == 0)
	{		 
		 return N_hit;
	}
	else if(cache_num == 1)
	{
		
		return F_hit;
	}
	else if(cache_num == 2)
	{
		return F_hit || N_hit;
	}

	return -1;

}

int LRU_Ajust(std::list< struct fp_node *> &cache, struct fp_node *fp)
{

	std::list< struct fp_node *>::iterator findIter = std::find(cache.begin(), cache.end(), fp);

	if(findIter == cache.end())
	{
		printf("Not in the cache!\n");
	}
	else
	{
		cache.erase(findIter);	
		cache.push_front(fp);
	}

	return 0;

}


int Cache_full(int cache_num)
{
	if(cache_num == 0)
	{		 
		 return (N_cache.size() >= N_cache_size);
	}
	else if(cache_num == 1)
	{
		
		return (F_cache.size() >= F_cache_size);
	}
	else if(cache_num == 2)
	{
		return -1;
		//return F_hit || N_hit;
	}

	return 0;
}

void Print_cache(std::list< struct fp_node *> &cache)
{
	std::list< struct fp_node *>::iterator li;
	
	for (li = cache.begin(); li != cache.end(); ++li)
	{
		printf("%s \n", (*li)->fingerprint);
		// Print_pblk((*li)->pblk_num);
	}
	printf("\n");
}


int Routine_N_cache(struct fp_node *fp)
{
	if (N_cache_size <= 0)
	{
//		printf("No cache! [Miss]\n");
		return 0;
	}
	else
	{
		if(Hit_cache(N_CACHE, fp) == 1)
		{
			printf("line[%lld]: cache [Hit]\n", total_line);
			// printf("Before LRU_Ajust\n");
			LRU_Ajust(N_cache, fp);
			return 1;
		}
		else//cache miss
		{
			printf("line[%lld]: cache [Miss]\n", total_line);
			if(Cache_full(N_CACHE))//cache full
			{
				printf("N_cache is full![Eviciting]\n");
				Evict_cache(N_CACHE);
				Insert_cache(N_CACHE, fp);
			}
			else//cache not full
			{
				// printf("[not Full] Insert a new page\n");
				Insert_cache(N_CACHE, fp);
			}

			return 0;
		}

	}
	
}

void Reset_cache(int cache_num)
{
	if(cache_num == 0)
	{		 
		N_cache.clear();
		N_cache_size = 0;
		N_cache_hit = 0;
		N_cache_miss = 0;
		// N_cache.swap(std::list< struct fp_node *>(N_cache));
	}
	else if(cache_num == 1)
	{
		F_cache.clear();
		F_cache_size = 0;
		F_cache_hit = 0;
		F_cache_miss = 0;
	}
	else if(cache_num == 2)
	{
			 
		N_cache.clear();
		N_cache_size = 0;
		N_cache_hit = 0;
		N_cache_miss = 0;

		F_cache.clear();
		F_cache_size = 0;
		F_cache_hit = 0;
		F_cache_miss = 0;

		//return F_hit || N_hit;
	}




}
