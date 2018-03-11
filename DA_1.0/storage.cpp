/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "storage.h"

void Init_Cluster(int node_num)
{
	Cluster = (struct Node **)malloc(sizeof(struct Node *)*node_num);

//	printf("sizeof Cluster: %ld node_num is %d\n", sizeof(Cluster), node_num);

	for (int i = 0; i < node_num; ++i)
	{
		Cluster[i] = new Node;

		if(Cluster[i] != NULL)
		{
			Cluster[i]->num = 0; 
			Cluster[i]->Last_Busy_Time = 0;
			Cluster[i]->pblk_used = 0;
			Cluster[i]->Physical_Address = i * MAX_BLK_NUM;//ÏÂÒ»¸ö¸ÃÍ¨µÀ¿ÉÓÃµÄµØÖ·±àºÅ
			Cluster[i]->failed = 0;
			Cluster[i]->dup_count = 0;
			Cluster[i]->total_access_count = 0;
			Cluster[i]->speclative_read_access = 0;
			Cluster[i]->write_access = 0;
			Cluster[i]->read_access = 0;
			Cluster[i]->parity_num = 0;
			Cluster[i]->network = 0;
			Cluster[i]->queques.resize(QUEUE_NUM, 0);
		}		
	}

	if(pblk_serial != 0)
		pblk_serial = 0;

	if(pblk_used != 0)
		pblk_used = 0;

	for(int i = 0; i < node_num; i++)
	{
		nodeset.insert(i);
	}
}


void Destroy_Cluster()
{
	if(Cluster != NULL)
	{
		for (int i = 0; i < ec_node; ++i)
		{
			if(Cluster[i] !=  NULL)
				free(Cluster[i]);
		}
		free(Cluster);
	}
}


long long Allocate_a_pblk()
{
	if(pblk_used < MAX_BLK_NUM * ec_node -1)
	{
		if(pblk_serial == MAX_BLK_NUM * ec_node -1)
		{
			pblk_serial = 0;
		}

		struct pblk_node* p = new pblk_node;

		if(p == NULL)
		{
			printf("Allocation Failed!\n");
		}

		p->ref_count = 1;
		p->node_num = pblk_serial % ec_node;
		p->parity = 0;
		p->dummy = 0;
		p->fp = NULL;

		p->stripe_num = -1;
		p->corrupted = 0;
		p->pblk_num = pblk_serial;
		p->data_blk_num = -1;

		global_storage.push_back(p);

		
		pblk_used++;
		
		pblk_serial++;
		// printf("%lld \n", pblk_serial);
		//used_pblk.push_back(pblk_serial);
		
		return pblk_serial-1;
			
	}
	else
	{
		printf("Storage full: No space!\n");
		return -1;

	}
}


void Destroy_storage()
{

//	printf("sizeof Storage: %ld\n", global_storage.size());
	for (int i = 0; i < global_storage.size(); ++i)
	{
		if(global_storage[i] != NULL)
		{
//			if(global_storage[i]->fp != NULL)
//			{
////				printf("[fp NOT NULL]!\n");
////				free(global_storage[i]->fp);
//			}
//			else
//			{
////				printf("[fp is NULL] Why!\n");
//			}
			free(global_storage[i]);
		}
	}

	global_storage.clear();
	pblk_used = 0;
	pblk_serial = 0;
	dummy_pblk = 0;

}

void Reset_other()
{
	total_line = 0;
	bad_line = 0;
	empty_line = 0;

	effective_line_count = 0;
	write_count = 0;
	read_count = 0;
	delete_count = 0;
	other_count = 0;

	Clear_CurRequest();
	Init_LastReqestID();
//	R_Req_Tbl.clear();
//	W_Req_Tbl.clear();

	Count_WIO = 0;
	Count_RIO = 0;
	W_Request_lasting_time = 0;
	R_Request_lasting_time = 0;
}




void Increase_pblk_ref_count(unsigned pblk_nr)
{
	global_storage[pblk_nr]->ref_count++;
}






// void Destroy_storage(int max_pblk_num)
// {

// }


int Pblk_is_free(unsigned pblk_nr)
{
	return (global_storage[pblk_nr]->ref_count == 0);
}


long long Mark_pblk_free(unsigned pblk_nr)
{
	global_storage[pblk_nr]->ref_count = 0;
	global_storage[pblk_nr]->fp = NULL;
	// global_storage[pblk_nr]->in_N_cache = 0;
	// global_storage[pblk_nr]->in_F_cache = 0;
	
	pblk_used--;
	
	return pblk_used;
}





void Print_pblk(int pblk_num)
{
	printf("1");
	if(global_storage[pblk_num] == NULL)
	{
		printf("pblk[%d] does not exist!\n", pblk_num);
	}
	else
	{
		struct fp_node* fp;
		int corrupted;
		int parity;
		printf("[num: %d], [node_num: %d], [str_num: %lld], [ref: %d], \
			[corrupted: %d], [parity: %d], [fp: %s]", \
			pblk_num, global_storage[pblk_num]->node_num, global_storage[pblk_num]->stripe_num, global_storage[pblk_num]->ref_count, \
			global_storage[pblk_num]->corrupted, global_storage[pblk_num]->parity, global_storage[pblk_num]->fp->fingerprint);
	}
	
}


void Finish_time_SOE(int sp, int policy)
{
	int temp;
	int blk_in_stripe = 0;
	int queue = - 1;
	//change the time of parity nodes.
	for (int i = 0; i < ec_m; ++i)
	{
		temp = global_storage[stripe_tbl[sp].parity[i]]->node_num;

		Cluster[temp]->write_access++;

		queue = (Cluster[temp]->write_access - 1) % QUEUE_NUM;

		if (sys_last_busy_time >= Cluster[temp]->queques[queue])
		{
			Cluster[temp]->queques[queue] = sys_last_busy_time + DATA_TRANSMISSION + WRITE_LATENCY;
		}
		else
		{
			blk_in_stripe++;
			// printf("Blocking!!!![%d]\n", blk_in_stripe);
			Cluster[temp]->queques[queue] += WRITE_LATENCY + DATA_TRANSMISSION;
		}
	}


	//change the time of data nodes.
	for (int i = 0; i < soe.data_pblk.size(); ++i)
	{
		temp = global_storage[soe.data_pblk[i].fp->p->pblk_num]->node_num;

		Cluster[temp]->write_access++;

		queue = (Cluster[temp]->write_access - 1) % QUEUE_NUM;

		// printf("Cluster[%d]->Last_Busy_Time: %lld sys_last_busy_time:%lld\n", temp, Cluster[temp]->Last_Busy_Time, sys_last_busy_time);

		if (sys_last_busy_time >= Cluster[temp]->queques[queue])
		{
			Cluster[temp]->queques[queue] = sys_last_busy_time + WRITE_LATENCY + DATA_TRANSMISSION;
		}
		else
		{
			blk_in_stripe++;
			// printf("Blocking!!!![%d]\n", blk_in_stripe);
			Cluster[temp]->queques[queue] += WRITE_LATENCY + DATA_TRANSMISSION;
		}

		//This is right
		if (W_Req_Tbl[policy][soe.data_pblk[i].Request_index].Finish_time < soe.data_pblk[i].Finish_Time)
		{
			// printf("1\n");
			if (soe.data_pblk[i].Arrive_Time > W_Req_Tbl[policy][soe.data_pblk[i].Request_index].Finish_time)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].Request_index].Lasting_time += soe.data_pblk[i].Finish_Time - soe.data_pblk[i].Arrive_Time;
			}
			else
			{
				// printf("2\n");
				W_Req_Tbl[policy][soe.data_pblk[i].Request_index].Lasting_time += soe.data_pblk[i].Finish_Time - W_Req_Tbl[policy][soe.data_pblk[i].Request_index].Finish_time;
			}

			// printf("3\n");
			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].Finish_time = soe.data_pblk[i].Finish_Time;
			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].straggler = soe.data_pblk[i].trace_num;
		}
	}

	// Print_Cluster_Time();
}

// /* delete a pblk node by decreasing its ref_count*/
// void Decrease_pblk_ref_count(unsigned pblk_nr)
// {
// 	if (storage[pblk_nr]->ref_count == 0)
// 	{
// 		printf("Error: This pblk[%d] is not allocated\n", pblk_nr);
// 	}
// 	else
// 	{
// 		storage[pblk_nr]->ref_count--;

// 		if(storage[pblk_nr]->ref_count == 0)
// 		{
// 			LVec::iterator it = std::find(used_pblk.begin(), used_pblk.end(), pblk_nr);
			
// 			if(it != used_pblk.end())
// 			{
// 				used_pblk.erase(it);
// 			}

// 			/*1. mark this pblk unused 2. release fp_node */
// 			if (Pblk_is_in_mem(pblk_nr))
// 			{
// 				//Page_lru_del()
// 				storage[pblk_nr]->in_mem = 0;
// 			}
		
// 			Del_fp(storage[pblk_nr]->fp);
			
// 			Mark_pblk_free(pblk_nr);
// 		}
// 	}
	
// 	return;

// }




// void Init_stripe_tbl(int max_stripe_num)
// {
// 	// stripe_tbl = (struct stripe *)malloc(max_stripe_num * sizeof(struct stripe));

// 	// if(stripe_tbl == NULL)
// 	// {
// 	// 	printf("Stripe_tbl Init [Failed]\n");
// 	// }

// 	// for (int i = 0; i < max_stripe_num; ++i)
// 	// {
// 	// 	stripe_tbl[i].stripe_num = i;
// 	// 	stripe_tbl[i].length = 0;
// 	// 	stripe_tbl[i].data = NULL;
// 	// 	stripe_tbl[i].parity = NULL;

// 	// 	stripe_tbl[i].corrupted = 0;
// 	// 	stripe_tbl[i].used = 0;
// 	// }

// }

// /*Init a pblk_node*/
// long Find_a_free_stripe()
// {
// 	//printf("Finding a free stripe!\n");
// 	if(used_stripe_num < max_stripe_num -1)
// 	{
// 		for (int i = 0; i < max_stripe_num; ++i)
// 		{
// 			if(Is_stripe_free(i))
// 			{			
// 				return i;
// 			}
// 		}
				
// 	}
// 	else
// 	{
// 		printf("Stripes full: No!\n");
// 		return -1;
// 	}
// }




// int Is_stripe_free(int n)
// {
// 	//printf("Is a stripe free\n");
// 	if (stripe_tbl[n].used == 0)
// 	{
// 		//printf("Yes!Free\n");
// 		return 1;
// 	}
// 	else
// 		return 0;
// }


void Init_a_stripe(struct stripe &s, int k, int m)
{
	// printf("Init a Stripe\n");
	s.stripe_num = stripe_num;
	s.length = k+m;
	s.data.resize(k, -1);
	s.parity.resize(m, -1);
	s.used = 1;
	s.corrupted = 0;

	stripe_tbl.push_back(s);
	used_stripe_num++;
	stripe_num++;
}

// /*return new stripe_num*/
long long Placement(struct SOE soe, int policy)
{
	struct stripe s;

	Init_a_stripe(s, ec_k, ec_m);

	assign_set.clear();

	dummyset.clear();

//	printf("sizeof Global_storage: %ld\n", global_storage.size());

	for (int i = 0; i < (ec_k + ec_m); ++i)
	{
		assign_set.push_back(Allocate_a_pblk());
//		printf("%lld ", assign_set[i]);
	}
	
//	printf(" Starting Placement policy\n");

	if(policy == 0)
	{
		BA_RR(s.stripe_num, 1, policy);
	}
	else if(policy == 1)
	{
		RA(s.stripe_num, policy);
	}
	else if(policy == 2)
	{
		DA_RR(s.stripe_num, ec_m, policy);
	}
	else if(policy == 3)
	{
		DA_NO_RR(s.stripe_num, ec_m, policy);
	}
	else if(policy == 4)
	{
		DA_access_b(s.stripe_num, ec_m, policy);
	}
	else if(policy == 5)
	{
		DA_lbt_b(s.stripe_num, ec_m, policy);
	}
	else if(policy == 6)
	{
		DA_lbt_mix(s.stripe_num, ec_m, policy);
	}
	else if(policy == 7)
	{
		DA_sra_b(s.stripe_num, ec_m, policy);
	}
	else if(policy == 8)
	{
		P_balance(s.stripe_num, ec_m, policy);
	}
	else
	{
		printf("Error!Policy Num [out of range]\n");
	}

	std::set<long long>::iterator di;

	vector<long long>dummy_tmp;

	for(di = dummyset.begin(); di != dummyset.end(); di++)
	{
		dummy_tmp.push_back(*di);
		global_storage[*di]->dummy = 1;
	}

	for (int i = 0; i < ec_k; ++i)
	{

		if (i > soe.data_pblk.size() - 1)
		{
			stripe_tbl[s.stripe_num].data[i] = dummy_tmp[i - soe.data_pblk.size()];
//			global_storage[dummyset[]] = -1;
			dummy_pblk++;
		}
		else
		{
			if(soe.data_pblk[i].fp->p == NULL)
			{
//				printf("soe.data_pblk[%d].fp->p is NULL\n", i);
			}
			else
			{
				blk_mapping[soe.data_pblk[i].datablk] = soe.data_pblk[i].fp->p->pblk_num;
				soe.data_pblk[i].fp->p->data_blk_num = soe.data_pblk[i].datablk;

				W_Req_Tbl[policy][soe.data_pblk[i].Request_index].datablks.push_back(soe.data_pblk[i].fp->p->data_blk_num);
//
				for(int j = 0; j < soe.data_pblk[i].dup.size(); j++)
				{
					W_Req_Tbl[policy][soe.data_pblk[i].dup[j]].datablks.push_back(soe.data_pblk[i].fp->p->data_blk_num);
				}
			}


			stripe_tbl[s.stripe_num].data[i] = soe.data_pblk[i].fp->p->pblk_num;
			
			global_storage[soe.data_pblk[i].fp->p->pblk_num]->stripe_num = s.stripe_num;
			
		}
		
//		 printf("stripe_tbl[%lld].data[%d] = %lld\n", s.stripe_num, i, stripe_tbl[s.stripe_num].data[i]);
			
	}


//	printf("Start encoding a stripe\n");
	Encode_a_stripe(s.stripe_num, ec_m);
//	Print_stripe(s.stripe_num);

	return s.stripe_num;
}

void Print_Blk_Mapping()
{

	std::map<long long, long long>::iterator mi;
	printf("-----------------------BLK Mapping--------------------\n");

	for(mi = blk_mapping.begin(); mi != blk_mapping.end(); mi++)
	{
		printf("Data[%10lld]--->Pblk[%10lld]--->Node[%5d]\n", mi->first, mi->second, global_storage[mi->second]->node_num);

	}

	printf("------------------------------------------------------\n");
}


bool fpcmp (struct traceline &i,struct traceline &j) { return (i.fp->hit<j.fp->hit); }


int sort_SOE()
{
	std:sort(soe.data_pblk.begin(), soe.data_pblk.end(), fpcmp);
	return 0;
}

//last_busy_time
int Min_Node(std::set<int> t)
{
	std::set<int>::iterator si;
	int index = *(t.begin());
//	long long min = Cluster[index]->Last_Busy_Time;
	long long min = Cluster[index]->total_access_count;

	for(si = t.begin(); si != t.end(); si++)
	{
//		if(min > Cluster[*si]->Last_Busy_Time && si != t.begin())
		if(min > Cluster[*si]->total_access_count && si != t.begin())
		{
			index = *si;
//			min = Cluster[*si]->Last_Busy_Time;
			min = Cluster[*si]->total_access_count;
		}

	}
	return index;
}


//total_access
int Min_Node_access(std::set<int> t1, std::set<int> t2)
{
	std::vector<int> tmp(ec_node);
	std::vector<int>::iterator it;

	it = std::set_intersection (t1.begin(), t1.end(), t2.begin(), t2.end(), tmp.begin());

	tmp.resize(it-tmp.begin());

//	for(it = tmp.begin(); it != tmp.end(); it++)
//	{
//		printf("%d ", (*it));
//	}
//
//	printf("\n");

	if(tmp.size() == 0)
	{
		return -1;
	}

	std::vector<int>::iterator s1;

	int index = *(tmp.begin());
	long long min = Cluster[index]->total_access_count;

	for(s1 = tmp.begin(); s1 != tmp.end(); s1++)
	{

		if(min > Cluster[*s1]->total_access_count && s1 != tmp.begin())
		{
			index = *s1;
			min = Cluster[*s1]->total_access_count;
		}

	}

	return index;
}

//total_access
int Min_Node_speculative_access(std::set<int> t1, std::set<int> t2)
{
	std::vector<int> tmp(ec_node);
	std::vector<int>::iterator it;

	it = std::set_intersection (t1.begin(), t1.end(), t2.begin(), t2.end(), tmp.begin());

	tmp.resize(it-tmp.begin());

	//	for(it = tmp.begin(); it != tmp.end(); it++)
	//	{
	//		printf("%d ", (*it));
	//	}
	//
	//	printf("\n");

	if(tmp.size() == 0)
	{
		printf("[No Node available!]\n");
		return -1;
	}

	std::vector<int>::iterator s1;

	int index = *(tmp.begin());
	long long min = Cluster[index]->speclative_read_access;

	for(s1 = tmp.begin(); s1 != tmp.end(); s1++)
	{
		if(s1 != tmp.begin() && min > Cluster[*s1]->speclative_read_access)
		{
			index = *s1;
			min = Cluster[*s1]->speclative_read_access;
		}

	}

	return index;
}


//last_busy_time
int Min_Node_lbt(std::set<int> t1, std::set<int> t2)
{

	std::vector<int> tmp(ec_node);
	std::vector<int>::iterator it;

	it = std::set_intersection (t1.begin(), t1.end(), t2.begin(), t2.end(), tmp.begin());

	tmp.resize(it-tmp.begin());

	//	for(it = tmp.begin(); it != tmp.end(); it++)
	//	{
	//		printf("%d ", (*it));
	//	}

	//	printf("\n");

	if(tmp.size() == 0)
	{
		printf("[No Node available!]\n");
		return -1;
	}

	std::vector<int>::iterator s1;

	int index = *(tmp.begin());
	long long min = Cluster[index]->Last_Busy_Time;

	for(s1 = tmp.begin(); s1 != tmp.end(); s1++)
	{
		if(s1 != tmp.begin() && min > Cluster[*s1]->Last_Busy_Time)
		{
			index = *s1;
			min = Cluster[*s1]->Last_Busy_Time;
		}

	}

	return index;

}


//pblk_used + speclative_read_access
int Min_Node_mix(std::set<int> t1, std::set<int> t2)
{
	std::vector<int> tmp(ec_node);
	std::vector<int>::iterator it;

	it = std::set_intersection (t1.begin(), t1.end(), t2.begin(), t2.end(), tmp.begin());

	tmp.resize(it-tmp.begin());

	//	for(it = tmp.begin(); it != tmp.end(); it++)
	//	{
	//		printf("%d ", (*it));
	//	}

	//	printf("\n");

	if(tmp.size() == 0)
	{
		printf("[No Node available!]\n");
		return -1;
	}

	std::vector<int>::iterator s1;

	int index = *(tmp.begin());
	long long min = Cluster[index]->write_access + Cluster[index]->speclative_read_access;

	for(s1 = tmp.begin(); s1 != tmp.end(); s1++)
	{
		if(s1 != tmp.begin() && min > (Cluster[*s1]->write_access + Cluster[*s1]->speclative_read_access))
		{
			index = *s1;
			min = Cluster[*s1]->write_access + Cluster[*s1]->speclative_read_access;;
		}

	}

	return index;

}






void BA_RR(long long sp, int stride, int policy)
{
//	printf("sp = %lld stride = %d, sp * stride % (ec_node)= %lld \n", sp, stride, sp * stride % (ec_node));
	for (int i = 0; i < (sp * stride) % (ec_node); ++i)
	{
		int j = assign_set.back();
		assign_set.pop_back();
		assign_set.push_front(j);
	}

	std::deque<long long> temp(0);

	for (int i = 0; i < ec_k; ++i)
	{
		int ii = assign_set.front();
		assign_set.pop_front();
		temp.push_back(ii);
	}

	for (int i = 0; i < sp % ec_node; ++i)
	{
		int j = temp.front();
		temp.pop_front();
		temp.push_back(j);
	}


	for (int i = 0; i < ec_k; ++i)
	{
		if(i > soe.data_pblk.size()-1)
		{
//			global_storage[temp[i]]->dummy = 1;
			dummyset.insert(temp[i]);
		}
		else
		{
			soe.data_pblk[i].fp->p = global_storage[temp[i]];
			global_storage[temp[i]]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;
		}
		
	}

}


void RA(long long sp, int policy)
{
	
	//real random

	// printf("time(NULL) %lld\n", (long long)time(NULL) + sp);
//	srand(time(NULL) + sp);
	srand(sp);
	// std::set<int> index(0);

	for (int i = 0; i < ec_k; ++i)
	{
		
		int temp = rand()% (ec_k + ec_m - i);
		// while(index.find())
		// int temp = rand()% (K + M);
		// index.insert(temp);

		// printf("Temp[%d]: assign_set[temp] = %lld\n", temp, assign_set[temp]%8);
		
		if(i > soe.data_pblk.size()-1)
		{
//			global_storage[assign_set[temp]]->dummy = 1;
			dummyset.insert(assign_set[temp]);
		}
		else
		{
			soe.data_pblk[i].fp->p = global_storage[assign_set[temp]];
			global_storage[assign_set[temp]]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

			// printf("soe.data_pblk[%d].fp->p->pblk_num = %u\n", i, soe.data_pblk[i].fp->p->pblk_num);
			// printf("soe.data_pblk[%d].fp->p->pblk_num = %u\n", 0, soe.data_pblk[0].fp->p->pblk_num);
		}
		
		
		assign_set.erase(assign_set.begin()+temp);
		
	}

}

void DA_RR(long long sp, int stride, int policy)
{
	std::deque<long long> tmp(0);

	std::set<int>::iterator si;
	int found = 0;

	map <long long, int> temp_map;
	map <long long, int>::iterator mi;

//	printf("sp = %lld stride = %d, sp * stride % (ec_node)= %lld \n", sp, stride, sp * stride % (ec_node));

	for (int i = 0; i < sp * stride % (ec_node); ++i)
	{
		int j = assign_set.back();
		assign_set.pop_back();
		assign_set.push_front(j);
	}


	for (int i = 0; i < ec_k; ++i)
	{

		long long t = assign_set.front();
		// printf("size of %ld\n", assign_set.size());
		tmp.push_back(t);
		// printf("2t\n");
		assign_set.pop_front();
//		printf("tmp[%d]: %lld\n", i, tmp[i] % (ec_k+ec_m));

		if(i > soe.data_pblk.size()-1)
		{
			dummyset.insert(tmp[i]);
			//global_storage[tmp[i]]->dummy = 1;
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
			//inital placement
//			printf("Inital Assigning: soe[%d] = %lld \n", i, tmp[i] % ec_node);

			soe.data_pblk[i].fp->p = global_storage[tmp[i]];


			if(soe.data_pblk[i].fp->p == NULL)
				printf("soe.data_pblk[i].fp->p is NULL!\n");
		}

		temp_map[tmp[i]] = i;

	}

//	printf("\n");
//
//	Print_map(temp_map);

	//assignment
//	printf("DA_Placment\n");
	for (int i = 0; i < ec_k; ++i)
	{
		int index = i;
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);
//			Print_Req_used_nodes(W_Req_Tbl[policy], soe.data_pblk[i].Request_index);

			found =  0;

			if(soe.data_pblk[i].fp->p == NULL)
			{
				printf("soe.data_pblk[i].fp->p is NULL!\n");
				continue;
			}


			for (int j = 0; j < tmp.size(); ++j)
			{

				si = W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.find(int(tmp[j] % ec_node));

				if(si == W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.end())
				{
					found = 1;

					if(soe.data_pblk[i].fp->p == NULL)
					{
						printf("soe.data_pblk[i].fp->p is NULL!\n");
					}

					if(tmp[j] != soe.data_pblk[i].fp->p->pblk_num)
					{
//						printf("Exchange Assigning: soe[%d] = %lld \n", i, tmp[j]);

						if(dummyset.find(tmp[j]) != dummyset.end())
						{
							dummyset.erase(tmp[j]);
							dummyset.insert(soe.data_pblk[i].fp->p->pblk_num);
						}


						struct pblk_node* t = soe.data_pblk[i].fp->p;
						soe.data_pblk[i].fp->p = global_storage[tmp[j]];



						//original correct placement.
						for(int jj = 0; jj < soe.data_pblk.size(); jj++)
						{
							if(jj == i)
							{
								continue;
							}

							if(soe.data_pblk[jj].fp->p->pblk_num == tmp[j])
							{
								soe.data_pblk[jj].fp->p = t;
						//				cout << "jj= " << jj << "  temp_map[tmp[j]] =" << temp_map[tmp[j]] << endl;

								break;
							}
						}

					}
					else//find initial
					{
							;					;
					}

					tmp.erase(tmp.begin() + j);
					break;
				}
				else
				{
//					index = j;
					;
				}


			}

			if(found == 0)
			{
				tmp.erase(tmp.begin() + index -i);
			}

//			printf("Final Assigning: soe[%d] = %d \n", i, soe.data_pblk[i].fp->p->node_num);


//						mi = temp_map.find(tmp[j]);
//
//						if(mi != temp_map.end())
//						{
//							soe.data_pblk[temp_map[tmp[j]]].fp->p = t;
////							printf("i = %d tmp[j] = %lld, temp_map[tmp[j]] = %d\n", i, tmp[j], temp_map[tmp[j]]);
//							int tk = temp_map[tmp[j]];
//							temp_map[t->pblk_num] = -1;
//							temp_map[tmp[j]] = i;
//							temp_map[t->pblk_num] = tk;
//							temp_map.erase(tmp[j]);
//
//						}
//						else
//						{
//							Print_map(temp_map);
//							printf("Key %lld not found in the map!\n", tmp[j]);
//						}

//						Print_map(temp_map);
//


//
//
//					}


			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.insert(soe.data_pblk[i].fp->p->node_num);

			if(W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.size() == ec_k)
					W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.clear();

			for (int m = 0; m < soe.data_pblk[i].dup.size(); ++m)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.insert(soe.data_pblk[i].fp->p->node_num);

				if(W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.size() == ec_k)
					W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.clear();
			}

//			temp_map.clear();

		}
		
	}

//	printf("Assign Over!\n");

}


void DA_RR_new(long long sp, int stride, int policy)
{
	std::deque<long long> tmp(0);

	std::set<int>::iterator si;

	map <long long, int> temp_map;
	map <long long, int>::iterator mi;

//	printf("sp = %lld stride = %d, size of assign_set: %ld \n", sp, stride, assign_set.size());

	for (int i = 0; i < sp * stride % (ec_node / stride); ++i)
	{
		int j = assign_set.back();
		assign_set.pop_back();
		assign_set.push_front(j);
	}

	for (int i = 0; i < ec_k; ++i)
	{


		long long t = assign_set.front();
		// printf("size of %ld\n", assign_set.size());
		tmp.push_back(t);
		// printf("2t\n");
		assign_set.pop_front();
//		printf("tmp[%d]: %lld\n", i, tmp[i] % (ec_k+ec_m));

		if(i > soe.data_pblk.size()-1)
		{
			dummyset.insert(tmp[i]);
			//global_storage[tmp[i]]->dummy = 1;
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
			//inital placement

			soe.data_pblk[i].fp->p = global_storage[tmp[i]];

			if(soe.data_pblk[i].fp->p == NULL)
				printf("soe.data_pblk[i].fp->p is NULL!\n");
		}

		temp_map[tmp[i]] = i;
	}

//	printf("\n");
//
//	Print_map(temp_map);

	//assignment
//	printf("DA_Placment\n");
	for (int i = 0; i < ec_k; ++i)
	{
//		int index = i;
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);

//			Print_Req_used_nodes(W_Req_Tbl, soe.data_pblk[i].Request_index);

			for (int j = 0; j < tmp.size(); ++j)
			{
				si = W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.find(int(tmp[j] % ec_node));

				if(si == W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.end())
				{
					if(soe.data_pblk[i].fp->p == NULL)
					{
						;
//						printf("soe.data_pblk[i].fp->p is NULL!\n");
					}

					if(tmp[j] != soe.data_pblk[i].fp->p->pblk_num)
					{
//						printf("Exchange Assigning: soe[%d] = %lld \n", i, tmp[j]);

						if(dummyset.find(tmp[j]) != dummyset.end())
						{
							dummyset.erase(tmp[j]);
							dummyset.insert(soe.data_pblk[i].fp->p->pblk_num);
						}

						struct pblk_node* t = soe.data_pblk[i].fp->p;
						soe.data_pblk[i].fp->p = global_storage[tmp[j]];


//						mi = temp_map.find(tmp[j]);
//
//						if(mi != temp_map.end())
//						{
//							soe.data_pblk[temp_map[tmp[j]]].fp->p = t;
////							printf("i = %d tmp[j] = %lld, temp_map[tmp[j]] = %d\n", i, tmp[j], temp_map[tmp[j]]);
//							int tk = temp_map[tmp[j]];
//							temp_map[t->pblk_num] = -1;
//							temp_map[tmp[j]] = i;
//							temp_map[t->pblk_num] = tk;
//							temp_map.erase(tmp[j]);
//
//						}
//						else
//						{
//							Print_map(temp_map);
//							printf("Key %lld not found in the map!\n", tmp[j]);
//						}

//						Print_map(temp_map);
//

//						original correct placement.
						for(int jj = 0; jj < soe.data_pblk.size() && (jj != i); jj++)
						{
							if(soe.data_pblk[jj].fp->p->pblk_num == tmp[j])
							{
								soe.data_pblk[jj].fp->p = t;
//								cout << "jj= " << jj << "  temp_map[tmp[j]] =" << temp_map[tmp[j]] << endl;

								break;
							}
						}


					}
					else//find initial
					{
						;
					}

//					index = j;
					tmp.erase(tmp.begin() + j);
					break;
				}
			}

//			tmp.erase(tmp.begin() + index -1);
			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.insert(soe.data_pblk[i].fp->p->node_num);

			if(W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.size() == ec_k)
					W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.clear();

			for (int m = 0; m < soe.data_pblk[i].dup.size(); ++m)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.insert(soe.data_pblk[i].fp->p->node_num);

				if(W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.size() == ec_k)
					W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.clear();
			}

//			temp_map.clear();

		}

	}

//	printf("Assign Over!\n");

}




void Print_map(map<long long, int> &A)
{
	map<long long, int>::iterator mi;

	for(mi = A.begin(); mi != A.end(); mi++)
	{
		printf("map[%5lld]  == %d\n", mi->first, mi->second);
	}

}
void DA_NO_RR(long long sp, int stride, int policy)
{
	std::deque<long long> tmp(0);

	std::deque<long long>::iterator di;

	std::set<int>::iterator si;

	map <long long, int> temp_map;
	map <long long, int>::iterator mi;
	int found = 0;

//	printf("sp = %lld stride = %d, size of assign_set: %ld \n", sp, stride, assign_set.size());

	for (int i = 0; i < assign_set.size(); ++i)
	{
		tmp.push_back(assign_set[i]);
	}

	srand(time(NULL) + sp);

	for (int i = 0; i < ec_k; ++i)
	{

//		int temp = rand()% (ec_k + ec_m - i);
		int temp = rand()% assign_set.size();
//		printf("temp = %d\n", temp);

		if(i > soe.data_pblk.size()-1)
		{
			dummyset.insert(assign_set[temp]);
		}
		else
		{
//			printf("Inital Assigning: soe[%d] = %lld  Node_num = %d\n", i, global_storage[assign_set[temp]]->pblk_num, global_storage[assign_set[temp]]->node_num);
			soe.data_pblk[i].fp->p = global_storage[assign_set[temp]];
		}

		temp_map[assign_set[temp]] = i;
		assign_set.erase(assign_set.begin()+temp);
//		for(int j = 0; j < assign_set.size(); j++)
//		{
//			printf("%lld ", assign_set[j]);
//		}
//
//		printf("\n");

	}

	assign_set.clear();

	//assignment
//	printf("DA_Placment\n");
	for (int i = 0; i < ec_k; ++i)
	{
		int index = i;
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);
//			Print_Req_used_nodes(W_Req_Tbl[policy], soe.data_pblk[i].Request_index);


			found =  0;

			if(soe.data_pblk[i].fp->p == NULL)
			{
				printf("soe.data_pblk[i].fp->p is NULL!\n");
				continue;
			}

			for (int j = 0; j < tmp.size(); ++j)
			{

				si = W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.find(int(tmp[j] % ec_node));

				if(si == W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.end())
				{
					found = 1;

					if(soe.data_pblk[i].fp->p == NULL)
					{
						printf("soe.data_pblk[i].fp->p is NULL!\n");
					}

					if(tmp[j] != soe.data_pblk[i].fp->p->pblk_num)
					{
//						printf("Exchange Assigning: soe[%d] = %lld \n", i, tmp[j]);

						if(dummyset.find(tmp[j]) != dummyset.end())
						{
							dummyset.erase(tmp[j]);
							dummyset.insert(soe.data_pblk[i].fp->p->pblk_num);
						}


						struct pblk_node* t = soe.data_pblk[i].fp->p;
						soe.data_pblk[i].fp->p = global_storage[tmp[j]];



						//original correct placement.
						for(int jj = 0; jj < soe.data_pblk.size(); jj++)
						{
							if(jj == i)
							{
								continue;
							}

							if(soe.data_pblk[jj].fp->p->pblk_num == tmp[j])
							{
								soe.data_pblk[jj].fp->p = t;
						//				cout << "jj= " << jj << "  temp_map[tmp[j]] =" << temp_map[tmp[j]] << endl;

								break;
							}
						}

					}
					else//find initial
					{
							;					;
					}

					tmp.erase(tmp.begin() + j);
					break;
				}
				else
				{
//					index = j;
					;
				}


			}

			if(found == 0)
			{
				tmp.erase(tmp.begin() + index -i);
			}

//			printf("Final Assigning: soe[%d] = %d\n", i, soe.data_pblk[i].fp->p->node_num);

			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.insert(soe.data_pblk[i].fp->p->node_num);

			if(W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.size() == ec_k)
					W_Req_Tbl[policy][soe.data_pblk[i].Request_index].used_nodes.clear();

			for (int m = 0; m < soe.data_pblk[i].dup.size(); ++m)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.insert(soe.data_pblk[i].fp->p->node_num);

				if(W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.size() == ec_k)
					W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].used_nodes.clear();
			}

		}

//		printf("Cycle %dth!\n", i);
	}

//	printf("tmp.size: %ld \n", tmp.size());
	for (int i = 0; i < tmp.size(); ++i)
	{
		assign_set.push_back(tmp[i]);
//		printf("tmp[%d]: %lld\n", i, tmp[i] % (ec_k+ec_m));
//		printf("assign_set[%d] = %lld\n", i, assign_set[i]);
	}
//	printf("Assign Over!\n");

}


void DA_access_b(long long sp, int stride, int policy)
{

	std::set<int> Tmp;
	std::set<int>::iterator Ti;

	std::deque<long long>::iterator di;

	std::set<long long>::iterator si;

	for (int i = 0; i < assign_set.size(); ++i)
	{
		Tmp.insert((int) assign_set[i]%ec_node);
	}


	 sort_SOE();
//	 printf("SOE has been sorted!\n");
//	 Print_SOE();

	//Initialization
	srand(time(NULL) + sp);
//	srand(sp);
	for (int i = 0; i < ec_k; ++i)
	{
		int temp = rand()% (ec_k + ec_m - i);

		// printf("Temp[%d]: assign_set[temp] = %lld\n", temp, assign_set[temp]%8);

		if(i > soe.data_pblk.size()-1)
		{
			dummyset.insert(assign_set[temp]);
		}
		else
		{
//			printf("Inital Assigning: soe[%d]: A_T: %lld  = %lld \n", i, soe.data_pblk[i].Arrive_Time ,assign_set[temp] % (ec_k+ec_m));
			soe.data_pblk[i].fp->p = global_storage[assign_set[temp]];
		}

		assign_set.erase(assign_set.begin()+temp);
	}

	assign_set.clear();
//	printf("Finish initial placement!\n");

	//assignment
	for (int i = 0; i < ec_k; ++i)
	{
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);

//			Print_Req_remain_nodes(W_Req_Tbl, soe.data_pblk[i].Request_index);

//			printf("Available nodes: ");
//			for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
//			{
//				printf("%d ", *Ti);
//			}
//			printf("\n");

//			Print_Cluster_Time();

			int min_node = Min_Node_access(W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain, Tmp);

			if(min_node == -1)
			{
				//could not find right now.
//				printf("Could not find the node[]!!!\n");
				min_node = soe.data_pblk[i].fp->p->node_num;
			}
			else
			{

//				printf("Found Node! [%d] min_node= %d\n", i, min_node);

				if(soe.data_pblk[i].fp->p->node_num != min_node)
				{
					struct pblk_node* t = soe.data_pblk[i].fp->p;

					if(dummyset.find(min_node + sp*ec_node) != dummyset.end())
					{
						dummyset.erase(min_node + sp*ec_node);
						dummyset.insert(soe.data_pblk[i].fp->p->pblk_num);
					}

	//				printf("[%d] Final Assigning: soe[%d]: A_T: %lld  node = %d   pblk = %lld \n", i, i, soe.data_pblk[i].Arrive_Time, min_node,  min_node + sp*ec_node);
					soe.data_pblk[i].fp->p = global_storage[min_node + sp*ec_node];

					for(int jj = i+1; jj < soe.data_pblk.size(); jj++)
					{
						if(soe.data_pblk[jj].fp->p->node_num == min_node)
						{
	//						printf("Exchange with soe[%d] \n", jj);
							soe.data_pblk[jj].fp->p = t;
							break;
						}
					}

				}

			}


			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain.erase(min_node);
			Tmp.erase(min_node);


			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

			for (int m = 0; m < soe.data_pblk[i].dup.size(); ++m)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].remain.erase(soe.data_pblk[i].fp->p->node_num);
			}

		}

	}

//	printf("Tmp.size: %ld \n", Tmp.size());
	for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
	{
		assign_set.push_back(*Ti + sp *ec_node);
	}

//	printf("Assign Over!\n");

}

void DA_sra_b(long long sp, int stride, int policy)
{

	std::set<int> Tmp;
	std::set<int>::iterator Ti;

	std::deque<long long>::iterator di;

	std::set<long long>::iterator si;

	for (int i = 0; i < assign_set.size(); ++i)
	{
		Tmp.insert((int) assign_set[i]%ec_node);
	}

	 sort_SOE();

	//Initialization
	srand(time(NULL) + sp);
//	srand(sp);
	for (int i = 0; i < ec_k; ++i)
	{
		int temp = rand()% (ec_k + ec_m - i);

		// printf("Temp[%d]: assign_set[temp] = %lld\n", temp, assign_set[temp]%8);

		if(i > soe.data_pblk.size()-1)
		{
				dummyset.insert(assign_set[temp]);
		}
		else
		{
//			printf("Inital Assigning: soe[%d]: A_T: %lld  = %lld \n", i, soe.data_pblk[i].Arrive_Time ,assign_set[temp] % (ec_k+ec_m));
			soe.data_pblk[i].fp->p = global_storage[assign_set[temp]];
		}

		assign_set.erase(assign_set.begin()+temp);
	}

	assign_set.clear();
//	printf("Finish initial placement!\n");

	//assignment
	for (int i = 0; i < ec_k; ++i)
	{
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);

//			Print_Req_remain_nodes(W_Req_Tbl, soe.data_pblk[i].Request_index);

//			printf("Available nodes: ");
//			for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
//			{
//				printf("%d ", *Ti);
//			}
//			printf("\n");

//			Print_Cluster_Time();

			int min_node = Min_Node_speculative_access(W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain, Tmp);
//			printf("[%d] min_node= %d\n", i, min_node);

			if(min_node == -1)
			{
				//could not find right now.
				printf("Could not find the node[]!!!\n");
				min_node = soe.data_pblk[i].fp->p->node_num;
			}
			else
			{

				if(soe.data_pblk[i].fp->p->node_num != min_node)
				{
					struct pblk_node* t = soe.data_pblk[i].fp->p;

					if(dummyset.find(min_node + sp*ec_node) != dummyset.end())
					{
						dummyset.erase(min_node + sp*ec_node);
						dummyset.insert(soe.data_pblk[i].fp->p->pblk_num);
					}

	//				printf("[%d] Final Assigning: soe[%d]: A_T: %lld  node = %d   pblk = %lld \n", i, i, soe.data_pblk[i].Arrive_Time, min_node,  min_node + sp*ec_node);
					soe.data_pblk[i].fp->p = global_storage[min_node + sp*ec_node];

					for(int jj = i+1; jj < soe.data_pblk.size(); jj++)
					{
						if(soe.data_pblk[jj].fp->p->node_num == min_node)
						{
	//						printf("Exchange with soe[%d] \n", jj);
							soe.data_pblk[jj].fp->p = t;
							break;
						}
					}

				}
			}

			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain.erase(min_node);
			Tmp.erase(min_node);


			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

			for (int m = 0; m < soe.data_pblk[i].dup.size(); ++m)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].remain.erase(soe.data_pblk[i].fp->p->node_num);
			}

		}

	}

//	printf("Tmp.size: %ld \n", Tmp.size());
	for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
	{
		assign_set.push_back(*Ti + sp *ec_node);
	}

//	Print_Cluster_Time();
//	printf("Assign Over!\n");

}

















void DA_lbt_b(long long sp, int stride, int policy)
{

	std::set<int> Tmp;
	std::set<int>::iterator Ti;

	std::deque<long long>::iterator di;

	std::set<long long>::iterator si;

	for (int i = 0; i < assign_set.size(); ++i)
	{
		Tmp.insert((int) assign_set[i]%ec_node);
	}

	 sort_SOE();
//	 printf("SOE has been sorted!\n");
//	 Print_SOE();

	//Initialization
	srand(time(NULL) + sp);
//	srand(sp);
	for (int i = 0; i < ec_k; ++i)
	{
		int temp = rand()% (ec_k + ec_m - i);

		// printf("Temp[%d]: assign_set[temp] = %lld\n", temp, assign_set[temp]%8);

		if(i > soe.data_pblk.size()-1)
		{
				dummyset.insert(assign_set[temp]);
		}
		else
		{
//			printf("Inital Assigning: soe[%d]: A_T: %lld  = %lld \n", i, soe.data_pblk[i].Arrive_Time ,assign_set[temp] % (ec_k+ec_m));
			soe.data_pblk[i].fp->p = global_storage[assign_set[temp]];
		}

		assign_set.erase(assign_set.begin()+temp);
	}

	assign_set.clear();
//	printf("Finish initial placement!\n");

	//assignment
	for (int i = 0; i < ec_k; ++i)
	{
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);

//			Print_Req_remain_nodes(W_Req_Tbl, soe.data_pblk[i].Request_index);

//			printf("Available nodes: ");
//			for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
//			{
//				printf("%d ", *Ti);
//			}
//			printf("\n");

//			Print_Cluster_Time();

			int min_node = Min_Node_lbt(W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain, Tmp);
//			printf("[%d] min_node= %d\n", i, min_node);

			if(min_node == -1)
			{
				//could not find right now.
//				printf("Could not find the node[]!!!\n");
				min_node = soe.data_pblk[i].fp->p->node_num;
			}
			else
			{

				if(soe.data_pblk[i].fp->p->node_num != min_node)
				{
					struct pblk_node* t = soe.data_pblk[i].fp->p;

					if(dummyset.find(min_node + sp*ec_node) != dummyset.end())
					{
						dummyset.erase(min_node + sp*ec_node);
						dummyset.insert(soe.data_pblk[i].fp->p->pblk_num);
					}



	//				printf("[%d] Final Assigning: soe[%d]: A_T: %lld  node = %d   pblk = %lld \n", i, i, soe.data_pblk[i].Arrive_Time, min_node,  min_node + sp*ec_node);
					soe.data_pblk[i].fp->p = global_storage[min_node + sp*ec_node];

					for(int jj = i+1; jj < soe.data_pblk.size(); jj++)
					{
						if(soe.data_pblk[jj].fp->p->node_num == min_node)
						{
	//						printf("Exchange with soe[%d] \n", jj);
							soe.data_pblk[jj].fp->p = t;
							break;
						}
					}

				}

			}

			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain.erase(min_node);
			Tmp.erase(min_node);


			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;


			for (int m = 0; m < soe.data_pblk[i].dup.size(); ++m)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].remain.erase(soe.data_pblk[i].fp->p->node_num);
			}

		}

	}

//	printf("Tmp.size: %ld \n", Tmp.size());
	for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
	{
		assign_set.push_back(*Ti + sp *ec_node);
	}

//	printf("Assign Over!\n");
}


void DA_lbt_mix(long long sp, int stride, int policy)
{

	std::set<int> Tmp;
	std::set<int>::iterator Ti;

	std::deque<long long>::iterator di;

	std::set<long long>::iterator si;

	for (int i = 0; i < assign_set.size(); ++i)
	{
		Tmp.insert((int) assign_set[i]%ec_node);
	}

	sort_SOE();
//	printf("SOE has been sorted!\n");
//	Print_SOE();

	//Initialization
	srand(time(NULL) + sp);
//	srand(sp);
	for (int i = 0; i < ec_k; ++i)
	{
		int temp = rand()% (ec_k + ec_m - i);

		// printf("Temp[%d]: assign_set[temp] = %lld\n", temp, assign_set[temp]%8);

		if(i > soe.data_pblk.size()-1)
		{
				dummyset.insert(assign_set[temp]);
		}
		else
		{
//			printf("Inital Assigning: soe[%d]: A_T: %lld  = %lld \n", i, soe.data_pblk[i].Arrive_Time ,assign_set[temp] % (ec_k+ec_m));
			soe.data_pblk[i].fp->p = global_storage[assign_set[temp]];
		}

		assign_set.erase(assign_set.begin()+temp);
	}

	assign_set.clear();
//	printf("Finish initial placement!\n");

	//assignment
	for (int i = 0; i < ec_k; ++i)
	{
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);
//
//			Print_Req_remain_nodes(W_Req_Tbl, soe.data_pblk[i].Request_index);
//
//			printf("Available nodes: ");
//			for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
//			{
//				printf("%d ", *Ti);
//			}
//			printf("\n");
//
//			Print_Cluster_Time();

			int min_node = Min_Node_mix(W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain, Tmp);
//			printf("[%d] min_node= %d\n", i, min_node);

			if(min_node == -1)
			{
				//could not find right now.
//				printf("Could not find the node[]!!!\n");
				min_node = soe.data_pblk[i].fp->p->node_num;
			}
			else
			{
				if(soe.data_pblk[i].fp->p->node_num != min_node)
				{
					struct pblk_node* t = soe.data_pblk[i].fp->p;

					if(dummyset.find(min_node + sp*ec_node) != dummyset.end())
					{
						dummyset.erase(min_node + sp*ec_node);
						dummyset.insert(soe.data_pblk[i].fp->p->pblk_num);
					}

	//				printf("[%d] Final Assigning: soe[%d]: A_T: %lld  node = %d   pblk = %lld \n", i, i, soe.data_pblk[i].Arrive_Time, min_node,  min_node + sp*ec_node);
					soe.data_pblk[i].fp->p = global_storage[min_node + sp*ec_node];

					for(int jj = i+1; jj < soe.data_pblk.size(); jj++)
					{
						if(soe.data_pblk[jj].fp->p->node_num == min_node)
						{
	//						printf("Exchange with soe[%d] \n", jj);
							soe.data_pblk[jj].fp->p = t;
							break;
						}
					}

				}
			}

			W_Req_Tbl[policy][soe.data_pblk[i].Request_index].remain.erase(min_node);
			Tmp.erase(min_node);


			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

			for (int m = 0; m < soe.data_pblk[i].dup.size(); ++m)
			{
				W_Req_Tbl[policy][soe.data_pblk[i].dup[m]].remain.erase(soe.data_pblk[i].fp->p->node_num);
			}

		}

	}

//	printf("Tmp.size: %ld \n", Tmp.size());
	for(Ti = Tmp.begin(); Ti != Tmp.end(); Ti++)
	{
		assign_set.push_back(*Ti + sp *ec_node);
	}

//	printf("Assign Over!\n");
}





void P_balance(long long sp, int stride, int policy)
{
//	printf("Inside P_balance!\n");

	std::deque<long long> tmp(0);

	std::deque<long long>::iterator di;

	std::set<long long>::iterator si;

	for (int i = 0; i < assign_set.size(); ++i)
	{
		tmp.push_back(assign_set[i]);
	}

	assign_set.clear();

//	sort_SOE();
//	printf("SOE has been sorted!\n");
//	Print_SOE();

	//assignment
	for (int i = 0; i < ec_k; ++i)
	{
		if(i > soe.data_pblk.size()-1)
		{
			// printf("i >>>>>> %d\n", i);;
		}
		else
		{
//			printf("i= %d  requestID %s  ", i, soe.data_pblk[i].RequestID);
//
//			Print_Cluster_Time();
			int min_node = Min_Node(nodeset);

//			printf("[%d] min_node= %d\n", i, min_node);

			di = std::find(tmp.begin(), tmp.end(), min_node + sp*ec_node);

			soe.data_pblk[i].fp->p = global_storage[min_node + sp*ec_node];

			nodeset.erase(min_node);

			tmp.erase(di);

			global_storage[soe.data_pblk[i].fp->p->pblk_num]->fp = soe.data_pblk[i].fp;

			Cluster[soe.data_pblk[i].fp->p->node_num]->dup_count += soe.data_pblk[i].fp->hit;
			Cluster[soe.data_pblk[i].fp->p->node_num]->pblk_used++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->write_access++;
			Cluster[soe.data_pblk[i].fp->p->node_num]->speclative_read_access += soe.data_pblk[i].fp->hit + 1;
			Cluster[soe.data_pblk[i].fp->p->node_num]->total_access_count++;

		}

	}

	if(tmp.size() > ec_m)
		printf("[Dummy block!]tmp.size: %ld \n", tmp.size());

	for (int i = 0; i < tmp.size(); ++i)
	{
		if(i < ec_m)
			assign_set.push_back(tmp[i]);
		else
			dummyset.insert(tmp[i]);
//		printf("tmp[%d]: %lld\n", i, tmp[i] % (ec_k+ec_m));
//		printf("assign_set[%d] = %lld\n", i, assign_set[i]);
	}


	nodeset.clear();
	for(int i = 0; i < ec_node; i++)
	{
		nodeset.insert(i);
	}

	//printf("Assign Over!\n");

}




void Print_Cluster_Time()
{
	printf("Last_busy_time of each node\n");
	for (int i = 0; i < ec_node; ++i)
	{
		printf("Cluster[%2d] dup: %3lld [LST: %5lld] [pblk_Used: %4lld Parity: %4lld] [T_A: %4lld] [W_A: %4lld] [R_A: %4lld] [SRA: %4lld]\n", i, Cluster[i]->dup_count, Cluster[i]->Last_Busy_Time, Cluster[i]->pblk_used, Cluster[i]->parity_num, Cluster[i]->total_access_count, Cluster[i]->write_access, Cluster[i]->read_access, Cluster[i]->speclative_read_access);
	}

	printf("\n");
}

int Search_fp_in_SOE(struct traceline *T_line)
{
	for (int i = 0; i < soe.data_pblk.size(); ++i)
	{
		if(strcmp(soe.data_pblk[i].Sha1, T_line->fp->fingerprint) == 0)
		{
			soe.data_pblk[i].dup.push_back(T_line->Request_index);
			return i;
		}
	}

	return 0;
}

void EC_Para(int node)
{
	if(node <= NODE_NUM)
	{

	}
	else
	{
		switch (node)
		{
			case 8 :
			{
				ec_k = 4;
				break;
			}
			case 9 :
			{
				ec_k = 6;
				break;
			}
			case 10 :
			{
				ec_k = 6;
				break;
			}
			case 12 :
			{
				ec_k = 8;
				break;
			}
			case 14 :
			{
				ec_k = 10;
				break;
			}

			default:
				ec_k = ec_node / 3 * 2;
		}

		ec_m = node - ec_k;
	}

	printf("Node Num: %d [K, M] = [ %2d, %2d]\n", node, ec_k, ec_m);
}


void Reset_time()
{
	sys_last_busy_time = 0;

	for(int i = 0; i < ec_node; i++)
	{
		Cluster[i]->Last_Busy_Time = 0;
		std::fill(Cluster[i]->queques.begin(), Cluster[i]->queques.end(), 0);
	}

//	printf("Time has been reset now!\n");
}


// /*produce the parity and */
void Encode_a_stripe(int s, int m)
{
	for (int i = 0; i < m; ++i)
	{
		stripe_tbl[s].parity[i] = assign_set[i];// using pblk_num instead of data_num
//		printf("Parity[%d] = %lld[N: %d] ", i,  stripe_tbl[s].parity[i], global_storage[stripe_tbl[s].parity[i]]->node_num);

		global_storage[stripe_tbl[s].parity[i]]->parity = 1;
		global_storage[stripe_tbl[s].parity[i]]->stripe_num = s;
		Cluster[global_storage[stripe_tbl[s].parity[i]]->node_num]->pblk_used++;
		Cluster[global_storage[stripe_tbl[s].parity[i]]->node_num]->write_access++;
		Cluster[global_storage[stripe_tbl[s].parity[i]]->node_num]->total_access_count++;
		Cluster[global_storage[stripe_tbl[s].parity[i]]->node_num]->parity_num++;
	}
//	printf("\n");

//	Print_stripe(s);
}

int Create_Node_Failure(int seed)
{

	Recover_Cluster();

	srand(time(NULL) + seed);
//	srand(time(0)+seed);


	int F_Node = rand() % ec_node;

	Cluster[F_Node]->failed = 1;

//	printf("Node[%2d] Failed!\n", F_Node);

	return F_Node;
}


void Recover_Cluster()
{
	for(int i = 0; i < ec_node; i++)
	{
		if(Cluster[i]->failed == 1)
		{
			Cluster[i]->failed = 0;
//			printf("Node[%2d] is recovered!\n", i);
		}

	}
}

// void Diff_EC(int group_num, int base_k, int base_m)
// {
// 	std::vector < LVec > m;
// 	m.resize(group_num);

// 	std::vector< long > div;
// 	div.resize(group_num-1);

// 	int d; 
// 	// d = Threshold(max_pblk_num);
	
// 	d = 2;

// 	for(int i = 0; i < used_pblk.size(); i++)
// 	{
// 		if(storage[used_pblk[i]]->ref_count >= d)
// 			m[0].push_back(used_pblk[i]);
// 		else
// 			m[1].push_back(used_pblk[i]);
// 	}	

// 	for(int j = 0; j < group_num; j++)
// 	{
// 		if(j == 0)
// 			//Print_vec(m[j]);

// 		printf("m[%d]: %lu\n", j, m[j].size());
		
// 		//printf("\nBatch[%d]: Encoding\n", j);
// 		Encode(&m[j], base_k + (d/2)*j, base_m - j*d/2);
// 	}

// }

// void Print_vec(LVec &p)
// {
// 	for(int j = 0; j < p.size(); j++)
// 	{
// 		if(j % 20 == 0)
// 			printf("\n");

// 		printf(" %ld", p[j]);		
// 	}
// 	printf("\n");
// }


// void Encode(LVec *p, int k, int m)
// {
// 	int counter = 0;
// 	int num = p->size() / k;
	
// 	Init_SOE(k);

// 	// printf("0 \n");
// 	for(int i = 0; i < p->size(); i++)
// 	{
// 		//printf("Starting iterating\n");
// 		Push_SOE(p->at(i));
		
// 		if(Is_SOE_full(k))
// 		{
// 			//printf("Full!\n");
// 			counter++;
// 			long sp = Placement(soe, k, m);
// 			//printf("Finish placement!\n");
// 			//Print_stripe(sp, k, m);
// 			Reset_SOE(k);
// 		}
// 		else if( (counter == num) && (i == p->size()-1) )
// 		{
// 			//printf("1\n");
// 			while(!Is_SOE_full(k))
// 				Push_SOE(-1);
// 			//printf("2\n");
// 			long sp = Placement(soe, k, m);
// 			Print_stripe(sp, k, m);
// 			Reset_SOE(k);
// 		}
			
// 	}

// }


// long Assign_parity()
// {
// 	if(pblk_used < MAX_BLK_NUM -1)
// 	{
// 		for (int i = pblk_serial; i < MAX_BLK_NUM; ++i)
// 		{
// 			if(Pblk_is_free(i))
// 			{
// 				storage[i]->ref_count = 1;
// 				storage[i]->node_num = i % N_num;
// 				storage[i]->parity = 1;

// 				storage[i]->fp = NULL;
// 				storage[i]->in_mem = 0; /*whether it is in the cache*/
// 				storage[i]->stripe_num = -1;
// 				storage[i]->corrupted = 0;
// 				storage[i]->pblk_num = i;

// 				pblk_used++;
// 				pblk_serial++;
				
// 				return i;
// 			}
// 		}
				
// 	}
// 	else
// 	{
// 		printf("Storage full: No space!\n");
// 		return -1;

// 	}
// }


void Init_SOE(int k)
{
	soe.data_pblk.resize(0);
	soe.full = 0;
}


void Push_SOE(struct traceline p)
{
	soe.data_pblk.push_back(p);
	soe.full++;
	//Print_SOE();
}

int Is_SOE_full(int k)
{
	return (soe.full == k);
}

void Reset_SOE(int k)
{
	
	soe.data_pblk.clear();
//	printf("SOE has been reset!\n");
	soe.full = 0;
	// printf("Finish resetting SOE\n");
}

void Print_SOE()
{
	printf("Inside SOE is:\n");
	
	for (int i = 0; i < soe.full; ++i)
	{
//		Print_traceline(&soe.data_pblk[i]);
//		printf("soe.data_pblk[%d]: A_T: %lld hit: %d\n", i, soe.data_pblk[i].Arrive_Time , soe.data_pblk[i].fp->hit);

		printf("RID: %s [dataNum: %3lld] P_num[%5lld]  Node_num[%3d]\n", soe.data_pblk[i].RequestID, soe.data_pblk[i].datablk, soe.data_pblk[i].fp->p->pblk_num, soe.data_pblk[i].fp->p->node_num);
	}
	printf("\n");
}

void Print_stripe(long stripe_num)
{
	printf("Stripe[%4ld]  ", stripe_num);

	printf("Data[");

	for (int i = 0; i < stripe_tbl[stripe_num].data.size(); ++i)
	{
		if(global_storage[stripe_tbl[stripe_num].data[i]]->dummy == 1)
			printf(" %6d: %2d", -1, global_storage[stripe_tbl[stripe_num].data[i]]->node_num);
		else
//			printf(" %5d", global_storage[stripe_tbl[stripe_num].data[i]]->node_num);
//			printf(" %5lld[D: %5lld N:%2d] ", global_storage[stripe_tbl[stripe_num].data[i]]->pblk_num, global_storage[stripe_tbl[stripe_num].data[i]]->data_blk_num, global_storage[stripe_tbl[stripe_num].data[i]]->node_num);
			printf(" %6lld: %2d ", global_storage[stripe_tbl[stripe_num].data[i]]->data_blk_num, global_storage[stripe_tbl[stripe_num].data[i]]->node_num);
	}
	printf("]  ");

	printf("Parity[");

	for (int i = 0; i < stripe_tbl[stripe_num].parity.size(); ++i)
	{
		// printf(" %5lld", stripe_tbl[stripe_num].parity[i]);
//		printf(" %4d", global_storage[stripe_tbl[stripe_num].parity[i]]->node_num);
//		printf(" %4lld[D: %5s N:%2d]", global_storage[stripe_tbl[stripe_num].parity[i]]->pblk_num, "X", global_storage[stripe_tbl[stripe_num].data[i]]->node_num);
		printf(" %6lld: %2d", stripe_tbl[stripe_num].parity[i], global_storage[stripe_tbl[stripe_num].parity[i]]->node_num);
	}
	printf("]");

	printf("\n");
}


void Print_stripe_tbl()
{
	for(long long i = 0; i < stripe_tbl.size(); i++)
		Print_stripe(i);
}
// void Create_ref_statistics(std::map<long, long> &ref_statis)
// {
// 	for(int i = 0; i < used_pblk.size(); i++)
// 	{
// 		if(storage[used_pblk[i]]->ref_count > 0)
// 		{
// 			if(ref_statis.find(storage[used_pblk[i]]->ref_count) == ref_statis.end())
// 				ref_statis[storage[used_pblk[i]]->ref_count] = 1;
// 			else
// 				ref_statis[storage[used_pblk[i]]->ref_count]++;
// 		}
// 	}	

// 	std::map<long, long>::iterator mit;
// 	for(mit = ref_statis.begin(); mit != ref_statis.end(); mit++)
// 	{
// 		printf("[%ld  %ld] ", mit->first, mit->second);
// 	}

// 	printf("\n");
// }

// int Threshold(int max_pblk_num)
// {
// 	//std::vector<int> i;
// 	IVec *p;
// 	std::map <int, IVec *> ref_tbl;
// 	std::map <int, IVec *>::iterator mi;

// 	for(int i = 0; i < max_pblk_num; i++)
// 	{
// 		if(storage[i]->ref_count >= 1)
// 		{
// 			if(ref_tbl.find(storage[i]->ref_count) == ref_tbl.end())	
// 			{				
// 				ref_tbl[storage[pblk_serial]->ref_count] = (IVec *)malloc(sizeof(IVec));
// 			}
			
// 			printf("pblk_nr: %d ref: %d\n", i, storage[i]->ref_count);
// 			ref_tbl[storage[pblk_serial]->ref_count]->push_back(i);
// 		}
// 	}

// 	for(mi = ref_tbl.begin(); mi != ref_tbl.end(); mi++)
// 	{
// 		printf(" %d: %lu\n", mi->first, mi->second->size());
// 		//free(mi->second);
// 	}

// }

void Reset_stripe_tbl()
{
	stripe_tbl.clear();
	used_stripe_num = 0;
	stripe_num = 0;
}

void Init(int node_num, int cache_size_N)
{
	Init_Cluster(node_num);
    Init_CurRequest();
    Init_LastReqestID();
    Set_cache_size(N_CACHE, cache_size_N);
    blk_mapping.clear();
    CDF.resize(6, 0);
}

void Reset_blk_maping()
{
	datablk_serial = 0;
	blk_mapping.clear();
}


void Reset_all(int node_num, int cache_size_N)
{
	Destroy_Cluster();
	Init_Cluster(node_num);

	Reset_SOE(ec_k);
	Reset_time();
	Reset_other();

	//stripe
	Reset_stripe_tbl();

	//cache
	Reset_cache(N_CACHE);

//	global_storage
	Destroy_storage();

	//reset fp_store
	Reset_fp_store();

	Reset_blk_maping();
	CDF.clear();


}

