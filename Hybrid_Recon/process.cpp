/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "process.h"


 void binary_to_hex(char *dst, char *src, size_t src_size)
 {
 	int x;

 	for (x = 0; x < src_size; x++)
 		sprintf(&dst[x * 2], "%.2x", (unsigned char)src[x]);
 	return;
 }


char *hex_to_binary(char *src, size_t src_size)
{
	int x;

	char *result = (char *)malloc((src_size + 1) / 2);
	for (x = 0; x < src_size; x++){
		char c = src[x];
		unsigned int bin = (c > '9') ?
		   (tolower(c) - 'a' + 10) : (c - '0');
		if (x % 2 == 0) {
			result[x / 2] = bin << 4;
		} else {
			result[x / 2] |= bin;
		}
	}
	return result;
}


void Print_set(set<int> &f)
{
	set<int>::iterator fi;

	printf("Free_H_nodes: ");
	for(fi=f.begin(); fi != f.end(); fi++)
	{
		printf(" %2d ", *fi);
	}
	printf("\n");
}


float Sum(std::vector<struct Read_request> ReadTrace)
{
	float t = 0;
	for(int i = 0; i < ReadTrace.size(); i++)
	{
		if(ReadTrace[i].G_value != -1)
			t += ReadTrace[i].G_value;
	}
	return t/ReadTrace.size();
}

void Write_Process_no_cal(struct traceline *T_line, int ec, int policy)
{
	int unique = 0;
	long long last_trace_time = 0;


	struct fp_node *fp = NULL;

	sys_last_busy_time += SHA1_COST;

	fp = Find_fp(T_line->Sha1);
	fp_search_count++;

	if (fp != NULL) //duplicates
	{
		w_case_3++;
//		printf("FP hit![%lld]!\n", w_case_3);
		total_fp_hit++;
		fp->hit++;

		unique = 0;


		T_line->Finish_Time = sys_last_busy_time + ACK_TIME;

		if(T_line->Finish_Time > W_Req_Tbl[policy][T_line->Request_index].Finish_time)
		{
			W_Req_Tbl[policy][T_line->Request_index].Finish_time = T_line->Finish_Time;
			W_Req_Tbl[policy][T_line->Request_index].Lasting_time = W_Req_Tbl[policy][T_line->Request_index].Finish_time - W_Req_Tbl[policy][T_line->Request_index].Arrive_time;
			W_Req_Tbl[policy][T_line->Request_index].straggler = T_line->trace_num;
		}


		T_line->fp = fp;

		if (T_line->fp->p == NULL)
		{
			Search_fp_in_SOE(T_line);
		}
		else
		{
			Cluster[T_line->fp->p->node_num]->dup_count++;
			Cluster[T_line->fp->p->node_num]->speclative_read_access += 1;

			for(int w = 0; w < QUEUE_NUM; w++)
			{
				std::set<int>::iterator it;
				it = W_Req_Tbl[policy][T_line->Request_index].remain.find(T_line->fp->p->node_num + w*ec_node);

				if(it != W_Req_Tbl[policy][T_line->Request_index].remain.end())
				{
					W_Req_Tbl[policy][T_line->Request_index].remain.erase(it);
					break;
				}
			}

			W_Req_Tbl[policy][T_line->Request_index].datablks.push_back(T_line->fp->p->data_blk_num);

			W_Req_Tbl[policy][T_line->Request_index].used_nodes.insert(T_line->fp->p->node_num);
			if(W_Req_Tbl[policy][T_line->Request_index].used_nodes.size() == ec_k)
				W_Req_Tbl[policy][T_line->Request_index].used_nodes.clear();
		}

	}
	else// new fp
	{
//		printf("FP [MISS]!\n");
		unique = 1;
		T_line->datablk = datablk_serial;
		datablk_serial++;
		fp = Init_fp_node(T_line);
		Add_fp(fp);
		T_line->fp = fp;
	}

	//check cache.

	sys_last_busy_time += ACCESS_CACHE;

	if(Routine_N_cache(T_line->fp))
	{
		N_cache_hit++;
		printf("line[%4lld]: cache hit[%lld]\n", total_line, N_cache_hit);
		// printf("line:[%lld] RequestID: %s duplicated! Last_time[%lld]\n", total_line, T_line->RequestID,  T_line->Finish_Time - T_line->Arrive_Time);
	}
	else
	{
		N_cache_miss++;
//		printf("line[%4lld]: cache miss[%4lld]\n", total_line, N_cache_miss);

		if (ec == 1)
		{
			if(unique == 1)//new pblk
			{

				if (soe.full == 0)
				{
					tmp = T_line->Arrive_Time;
				}

				T_line->Finish_Time = sys_last_busy_time + ACK_TIME;

				if(T_line->Finish_Time > W_Req_Tbl[policy][T_line->Request_index].Finish_time)
				{
					W_Req_Tbl[policy][T_line->Request_index].Finish_time = T_line->Finish_Time;
					W_Req_Tbl[policy][T_line->Request_index].Lasting_time = W_Req_Tbl[policy][T_line->Request_index].Finish_time - W_Req_Tbl[policy][T_line->Request_index].Arrive_time;
					W_Req_Tbl[policy][T_line->Request_index].straggler = T_line->trace_num;
				}

				//remove timeover restriction
				if(T_line->Arrive_Time > (tmp + PLACEMENT_THRESHOLD))
				{
					;
				}

//				printf("Push SOE\n");
				Push_SOE(*T_line);
				unique = 0;

			}


			if (Is_SOE_full(ec_k))//encoding
			{
//				printf("SOE is full! Starting Placement.\n");
			    sys_last_busy_time += ENCODE_COST;

			   	int s_p = Placement(soe, policy);
//			   	Finish_time_SOE(s_p, policy);
//			   	Print_SOE();
			   	Reset_SOE(ec_k);
			}



		}
		else if(ec == 0)//no Erasure coding
		{

		}

	}


}



// Process Write Request: 6 cases
void Write_Process(struct traceline *T_line, int ec, int policy)
{
	int unique = 0;
	long long last_trace_time = 0;


	struct fp_node *fp = NULL;

	sys_last_busy_time += SHA1_COST;

	fp = Find_fp(T_line->Sha1);
	fp_search_count++;

	if (fp != NULL) //duplicates
	{
		w_case_3++;
//		printf("FP hit![%lld]!\n", w_case_3);
		total_fp_hit++;
		fp->hit++;

		unique = 0;


		T_line->Finish_Time = sys_last_busy_time + ACK_TIME;

		if(T_line->Finish_Time > W_Req_Tbl[policy][T_line->Request_index].Finish_time)
		{
			W_Req_Tbl[policy][T_line->Request_index].Finish_time = T_line->Finish_Time;
			W_Req_Tbl[policy][T_line->Request_index].Lasting_time = W_Req_Tbl[policy][T_line->Request_index].Finish_time - W_Req_Tbl[policy][T_line->Request_index].Arrive_time;
			W_Req_Tbl[policy][T_line->Request_index].straggler = T_line->trace_num;
		}


		T_line->fp = fp;

		if (T_line->fp->p == NULL)
		{
			Search_fp_in_SOE(T_line);
		}
		else
		{
			Cluster[T_line->fp->p->node_num]->dup_count++;
			Cluster[T_line->fp->p->node_num]->speclative_read_access += 1;

			for(int w = 0; w < QUEUE_NUM; w++)
			{
				std::set<int>::iterator it;
				it = W_Req_Tbl[policy][T_line->Request_index].remain.find(T_line->fp->p->node_num + w*ec_node);

				if(it != W_Req_Tbl[policy][T_line->Request_index].remain.end())
				{
					W_Req_Tbl[policy][T_line->Request_index].remain.erase(it);
					break;
				}
			}

			W_Req_Tbl[policy][T_line->Request_index].datablks.push_back(T_line->fp->p->data_blk_num);

			W_Req_Tbl[policy][T_line->Request_index].used_nodes.insert(T_line->fp->p->node_num);
			if(W_Req_Tbl[policy][T_line->Request_index].used_nodes.size() == ec_k)
				W_Req_Tbl[policy][T_line->Request_index].used_nodes.clear();
		}

	}
	else// new fp
	{
//		printf("FP [MISS]!\n");
		unique = 1;
		T_line->datablk = datablk_serial;
		datablk_serial++;
		fp = Init_fp_node(T_line);
		Add_fp(fp);
		T_line->fp = fp;
	}

	//check cache.

	sys_last_busy_time += ACCESS_CACHE;
	
	if(Routine_N_cache(T_line->fp))
	{
		N_cache_hit++;
		printf("line[%4lld]: cache hit[%lld]\n", total_line, N_cache_hit);
		// printf("line:[%lld] RequestID: %s duplicated! Last_time[%lld]\n", total_line, T_line->RequestID,  T_line->Finish_Time - T_line->Arrive_Time);
	}
	else
	{
		N_cache_miss++;
//		printf("line[%4lld]: cache miss[%4lld]\n", total_line, N_cache_miss);
		
		if (ec == 1)
		{
			if(unique == 1)//new pblk
			{

				if (soe.full == 0)
				{
					tmp = T_line->Arrive_Time;
				}
				
				T_line->Finish_Time = sys_last_busy_time + ACK_TIME;

				if(T_line->Finish_Time > W_Req_Tbl[policy][T_line->Request_index].Finish_time)
				{
					W_Req_Tbl[policy][T_line->Request_index].Finish_time = T_line->Finish_Time;
					W_Req_Tbl[policy][T_line->Request_index].Lasting_time = W_Req_Tbl[policy][T_line->Request_index].Finish_time - W_Req_Tbl[policy][T_line->Request_index].Arrive_time;
					W_Req_Tbl[policy][T_line->Request_index].straggler = T_line->trace_num;
				}

				//remove timeover restriction
				if(T_line->Arrive_Time > (tmp + PLACEMENT_THRESHOLD))
				{
					;
				}

//				printf("Push SOE\n");
				Push_SOE(*T_line);
				unique = 0;

			}


			if (Is_SOE_full(ec_k))//encoding
			{
//				printf("SOE is full! Starting Placement.\n");
			    sys_last_busy_time += ENCODE_COST;
			    
			   	int s_p = Placement(soe, policy);
			   	Finish_time_SOE(s_p, policy);
//			   	Print_SOE();
			   	Reset_SOE(ec_k);
			}

			 
			
		}
		else if(ec == 0)//no Erasure coding
		{

//			//regardless of duplicates or not, go the the node and write.
//			CurNode = global_storage[T_line->fp->p->pblk_num]->node_num;
//
//			if (unique == 1)//new pblk
//			{
//				if (sys_last_busy_time >= Cluster[CurNode]->Last_Busy_Time)
//				{
//						Cluster[CurNode]->Last_Busy_Time = sys_last_busy_time + WRITE_LATENCY + DATA_TRANSMISSION;
//				}
//				else
//				{
//						Cluster[CurNode]->Last_Busy_Time += WRITE_LATENCY + DATA_TRANSMISSION;
//				}
//
//				T_line->Finish_Time = Cluster[CurNode]->Last_Busy_Time;
//			}
//			else//duplicates & cache miss: write into cache instead of swap.
//			{
//				//get into cache.
//				T_line->Finish_Time = sys_last_busy_time;
//			}
		}

	}

	

	// printf("-----------------------------------------------------------\n");	

}

void Update_R_Request_Time(struct traceline *T_line, int policy)
{

	// printf("Update_R_Request_Time!\n");
	// printf("T_line->Arrive_Time: %lld   Req_Tbl[T_line->Request_index].Arrive_time: %lld\n", T_line->Arrive_Time, Req_Tbl[T_line->Request_index].Arrive_time);
	if (R_Req_Tbl[policy][T_line->Request_index].Arrive_time > T_line->Arrive_Time)
	{
		printf("[Error]:R_Request[%lld].Arrive_Time Wrong!\n", T_line->Request_index);
		R_Req_Tbl[policy][T_line->Request_index].Arrive_time = T_line->Arrive_Time;
	}
	

	if (R_Req_Tbl[policy][T_line->Request_index].Finish_time < T_line->Finish_Time)
	{
		R_Req_Tbl[policy][T_line->Request_index].Finish_time = T_line->Finish_Time;
		R_Req_Tbl[policy][T_line->Request_index].Lasting_time = R_Req_Tbl[policy][T_line->Request_index].Finish_time - R_Req_Tbl[policy][T_line->Request_index].Arrive_time;

		if(R_Req_Tbl[policy][T_line->Request_index].straggler < (T_line->Finish_Time - T_line->Arrive_Time))
		{
		    R_Req_Tbl[policy][T_line->Request_index].straggler = T_line->Finish_Time - T_line->Arrive_Time;
		}
	}
	
	R_Req_Tbl[policy][T_line->Request_index].reponse_times.push_back(T_line->Finish_Time - T_line->Arrive_Time);


//	R_Req_Tbl[policy][T_line->Request_index].G_value = 1 - ((float) R_Req_Tbl[policy][T_line->Request_index].Lasting_time / R_Req_Tbl[policy][T_line->Request_index].datablks.size() / R_Req_Tbl[policy][T_line->Request_index].straggler);

//	printf("R_Req_Tbl[%5lld]: straggler= %5lld   G_value: %5.2f\n", T_line->Request_index, R_Req_Tbl[T_line->Request_index].straggler, R_Req_Tbl[T_line->Request_index].G_value);


}

float Calculate_G(long long Count_RIO, int policy)
{
	std::map<int, int>result;

//	if(Count_RIO -1 >= 0)
	{
		int n_node;
		int max = -1;

		for(int j = 0; j < R_Req_Tbl[policy][Count_RIO-1].datablks.size(); j++)
		{
			n_node = global_storage[blk_mapping[R_Req_Tbl[policy][Count_RIO-1].datablks[j]]]->node_num;
			result[n_node]++;
			if(max < result[n_node])
				max = result[n_node];
		}

		float ave = (float) 1 / max;
		//printf("R_Lasting_time:%lld t_straggler=%lld\n", R_Req_Tbl[policy][Count_RIO-1].Lasting_time, R_Req_Tbl[policy][Count_RIO-1].straggler);
		R_Req_Tbl[policy][Count_RIO-1].G_value = 1 - ave;
	}

	return R_Req_Tbl[policy][Count_RIO-1].G_value;
}


void Cal_total_latency()
{
	long long max = -1;
	long long sum_access = 0;
	long long ave_access = 0;
	long long max_access = -1;
	float G_access = 0;

	for(int i = 0; i < ec_node; i++)
	{
		sum_access += Cluster[i]->read_access;

		if(max_access < Cluster[i]->read_access)
			max_access = Cluster[i]->read_access;

		if(max < Cluster[i]->Last_Busy_Time)
			max = Cluster[i]->Last_Busy_Time;
	}

	ave_access = (float)sum_access / ec_node;

	G_access = 1 - (float)ave_access/max_access;

//	printf("ave: %lld, max: %lld", ave_access, max_access);
	total_access.push_back(G_access);

	total_latency.push_back(max);
}

void Cal_CDF(float& value)
{
	CDF[5]++; //100%

	//CDF
	if(value <= 0.8) //80%
	{
		CDF[4]++;
	}

	if(value <= 0.6) //60%
	{
		CDF[3]++;
	}

	if(value <= 0.4) //40%
	{
		CDF[2]++;
	}

	if(value <= 0.2)//20%
	{
		CDF[1]++;
	}

	if(value == 0) //0
	{
		CDF[0]++;
	}

}

void CDF_calculation(vector<long long> &array, int write)
{
	std::vector<struct Request>tmp;
	int value = -1;

	if(write == 1)
	{
		tmp = W_Req_Tbl[0];
	}
	else
	{
		tmp = R_Req_Tbl[0];
	}


	for(int i = 0; i < tmp.size(); i++)
	{
		value = tmp[i].datablks.size();

		array[5]++; //100%

		//CDF
		if(value <= 4 * ec_node) //4 * ec_node%
		{
			array[4]++;
		}

		if(value <= 2* ec_node) //2 * ec_node%
		{
			array[3]++;
		}

		if(value <= ec_node) //1 * ec_node%
		{
			array[2]++;
		}

		if(value <= ec_node / 2)// 1/2 * ec_node%
		{
			array[1]++;
		}

		if(value == 0) //0
		{
			array[0]++;
		}
	}

}

float Calculate_distance_access()
{
	float result = 0;
	float average = -1;
	long long sum = 0;
	long long max = -1;

	for(int i = 0; i < ec_node; i++)
	{
		sum += Cluster[i]->read_access;
		if(max < Cluster[i]->read_access)
		{
			max = Cluster[i]->read_access;
		}
	}

	average = (float) sum / ec_node;

	result = 1 - average/max;

	return result;

}


float Calculate_distance_lbt()
{
	float result = 0;
	float average = -1;
	long long sum = 0;
	long long max = -1;

	for(int i = 0; i < ec_node; i++)
	{
//		if(Cluster[i]->Last_Busy_Time == 0)
//		{
//			printf("[%lld] [%d] Time == 0!\n", total_line, i);
//		}
		sum += Cluster[i]->Last_Busy_Time;

		if(max < Cluster[i]->Last_Busy_Time)
			max = Cluster[i]->Last_Busy_Time;
	}

	average = (float) sum / ec_node;

	/*square of the difference*/
//	sum = 0;
//
//	for(int i = 0; i < ec_node; i++)
//	{
//		sum += (Cluster[i]->Last_Busy_Time - average)* (Cluster[i]->Last_Busy_Time - average);
//	}
//
//	result = (float) sum / ec_node;


	/*1-average/max*/
	result = 1 - average/max;

	return result;

}


//Process a Read request
void Read_by_FP(struct traceline *T_line, int policy, int recon)
{

	struct fp_node *fp = NULL;
	int CurNode = -1;
	int queue = -1;
	long long datapblk_num = -1;
	long long pblk_num = -1;

	// printf("-------------------------line[%lld] Read----------------------\n", total_line);

	fp = Find_fp(T_line->Sha1);


	if (fp != NULL) //Read hit
	{
		T_line->fp = fp;

		datapblk_num = fp->p->data_blk_num;
		pblk_num = fp->p->pblk_num;


	}
	else //not found fp. therefore using last_datablk_by_fp.
	{
		readline_not_by_fp++;//read_not_by_fp

		if(datablk_serial == 0)
			return ;

		datapblk_num = (last_datablk_by_fp + 1) % datablk_serial;

		pblk_num = blk_mapping[datapblk_num];

		T_line->fp = global_storage[pblk_num]->fp;

	}

	//update last_datablk_by_fp
	if(last_datablk_by_fp != datapblk_num)
		last_datablk_by_fp = datapblk_num;


	R_Req_Tbl[policy][T_line->Request_index].datablks.push_back(datapblk_num);
	R_Req_Tbl[policy][T_line->Request_index].arrive_times.insert(std::make_pair(datapblk_num, T_line->Arrive_Time));

	if(recon == 1)
	{
		return ;
	}

	CurNode = global_storage[pblk_num]->node_num;

//	printf("RID: %s [dataNum: %3lld] P_num[%5lld]  Node_num[%3d]\n", T_line->RequestID, datapblk_num, pblk_num, CurNode);


	//check cache
	//sys_last_busy_time += ACCESS_CACHE;

	if(Routine_N_cache(T_line->fp))//N_cache hit
	{
		r_case_2++;
		N_cache_hit++;

		T_line->Finish_Time = sys_last_busy_time;
	}
	else//N_cache miss
	{
		r_case_4++;
		N_cache_miss++;

		if(recon == 1)
		{
			printf("using Recon!\n");
		}

		else
		{
//			printf("Using normal!\n");

			//starting access nodes
			if(Cluster[CurNode]->failed != 1 && global_storage[pblk_num]->corrupted != 1)
			{

				Cluster[CurNode]->total_access_count++;
				Cluster[CurNode]->read_access++;

				queue = (Cluster[CurNode]->read_access - 1) % QUEUE_NUM;

//				if (sys_last_busy_time > Cluster[CurNode]->queques[queue])
				if (sys_last_busy_time > Cluster[CurNode]->Last_Busy_Time)
				{
						Cluster[CurNode]->Last_Busy_Time = sys_last_busy_time + READ_LATENCY + DATA_TRANSMISSION;
				}
				else
				{
				//		printf("Blocked[Node Busy]!\n");
						read_blk_num++;
						Cluster[CurNode]->Last_Busy_Time += READ_LATENCY + DATA_TRANSMISSION;
				}

	//			printf("%5lld\n", Cluster[CurNode]->Last_Busy_Time);
			//	sys_last_busy_time = Cluster[CurNode]->Last_Busy_Time + ACCESS_CACHE + SHA1_COST; // the metadata needs to get the read data and compute the sha1 and write into cache.

				if(T_line->Finish_Time < Cluster[CurNode]->Last_Busy_Time + ACK_TIME)
					T_line->Finish_Time = Cluster[CurNode]->Last_Busy_Time + ACK_TIME;

		//			Print_Cluster_Time();
			}
			else
			{
		//		printf("Access [blk: %5lld] in Node[%2d]: Failure!\n", pblk_num, CurNode);
				long long t = Degraded_read(pblk_num);

				if(T_line->Finish_Time < t)
					T_line->Finish_Time = t;
			}
		}

		Update_R_Request_Time(T_line, policy);
	}



}

//Process a Read request by mapping blk to eliminate missing read.
void Read_by_lpblk(struct traceline *T_line, int policy)
{
	int CurNode = 0;

	int queue = -1;
	// printf("-------------------------line[%lld] Read----------------------\n", total_line);

	long long datapblk_num = (T_line->Address / 8 + 1) % (datablk_serial) ;

	long long pblk_num = blk_mapping[datapblk_num];

	R_Req_Tbl[policy][T_line->Request_index].datablks.push_back(datapblk_num);

	CurNode = global_storage[pblk_num]->node_num;

	printf("RID: %s [dataNum: %3lld] P_num[%5lld]  Node_num[%3d]\n", T_line->RequestID, datapblk_num, pblk_num, CurNode);

	//check cache
//	sys_last_busy_time += ACCESS_CACHE;


	if(Routine_N_cache(T_line->fp))//N_cache hit
	{
		r_case_2++;
		N_cache_hit++;

		T_line->Finish_Time = sys_last_busy_time;
	}
	else//N_cache miss
	{
		r_case_4++;
		N_cache_miss++;

		//starting access nodes

		if(Cluster[CurNode]->failed != 1 && global_storage[pblk_num]->corrupted != 1)
		{

			Cluster[CurNode]->total_access_count++;
			Cluster[CurNode]->read_access++;

			queue = (Cluster[CurNode]->read_access - 1) % QUEUE_NUM;
//			printf("ACCESS Node[%3d]: %5lld --> ", CurNode, Cluster[CurNode]->Last_Busy_Time);


			if (sys_last_busy_time > Cluster[CurNode]->queques[queue])
			{
				Cluster[CurNode]->queques[queue] = sys_last_busy_time + READ_LATENCY + DATA_TRANSMISSION;
				//there we assume client first go to check the MDS and then cache miss and then go to Cluster.
			}
			else
			{
			//	printf("Blocked[Node Busy]!\n");
				read_blk_num++;
				Cluster[CurNode]->queques[queue] += READ_LATENCY + DATA_TRANSMISSION;
			}

//			printf("%5lld\n", Cluster[CurNode]->Last_Busy_Time);
	//		sys_last_busy_time = Cluster[CurNode]->Last_Busy_Time + ACCESS_CACHE + SHA1_COST; // the metadata needs to get the read data and compute the sha1 and write into cache.

			if(T_line->Finish_Time < Cluster[CurNode]->queques[queue] + ACK_TIME)
				T_line->Finish_Time = Cluster[CurNode]->queques[queue] + ACK_TIME;

//			Print_Cluster_Time();
		}
		else
		{
//			printf("Access [blk: %5lld] in Node[%2d]: Failure!\n", pblk_num, CurNode);
			long long t = Degraded_read(pblk_num);

			if(T_line->Finish_Time < t)
				T_line->Finish_Time = t;
		}

		Update_R_Request_Time(T_line, policy);
	}

}



long long Degraded_read(long long pblk_num)
{
	long long stripe_num;

	int Cur_node = -1;

	long long last_finish_time = -1;

	vector<long long>tmp;

	degraded_read++;

	stripe_num = global_storage[pblk_num]->stripe_num;

	for(int i = 0; i < stripe_tbl[stripe_num].data.size() ; i++)
	{
		tmp.push_back(stripe_tbl[stripe_num].data[i]);
	}

	for(int i = 0; i < stripe_tbl[stripe_num].parity.size() ; i++)
	{
			tmp.push_back(stripe_tbl[stripe_num].parity[i]);
	}

	std::random_shuffle(tmp.begin(), tmp.end());

	tmp.resize(ec_k);

//	printf("Helper p_block[Node]:  ");
//	for(int i = 0; i < tmp.size() ; i++)
//	{
//		printf(" %5lld [%2lld] ", tmp[i], tmp[i] % ec_node);
//	}
//	printf("\n");

	for(int i = 0; i < tmp.size() ; i++)
	{
		Cur_node = tmp[i] % ec_node;
		int queue = -1 ;


		if(Cluster[Cur_node]->failed != 1 && global_storage[tmp[i]]->corrupted != 1)
		{
			Cluster[Cur_node]->total_access_count++;
			Cluster[Cur_node]->read_access++;

			queue = (Cluster[CurNode]->read_access - 1) % QUEUE_NUM;
//			printf("ACCESS Node[%d]: %5lld --> ", Cur_node, Cluster[Cur_node]->Last_Busy_Time);

			if (sys_last_busy_time > Cluster[Cur_node]->Last_Busy_Time)
			{
				Cluster[Cur_node]->Last_Busy_Time = sys_last_busy_time + READ_LATENCY + DATA_TRANSMISSION;
			}
			else
			{
			//	printf("Blocked[Node Busy]!\n");
				read_blk_num++;
				Cluster[Cur_node]->Last_Busy_Time += READ_LATENCY + DATA_TRANSMISSION;
			}

//			printf("%5lld\n", Cluster[Cur_node]->Last_Busy_Time);
			//sys_last_busy_time = Cluster[CurNode]->Last_Busy_Time + ACCESS_CACHE + SHA1_COST; // the metadata needs to get the read data and compute the sha1 and write into cache.

			if(last_finish_time < Cluster[Cur_node]->Last_Busy_Time + ACK_TIME)
			{
				last_finish_time = Cluster[Cur_node]->Last_Busy_Time + ACK_TIME;
			}
		}
		else //Degraded read
		{
			last_finish_time = Degraded_read(tmp[i]);
		}


	}

	return last_finish_time;
}



void Read_Table(std::vector<struct Read_request> &Read_trace, int raw)
{

	long long last_finish_time = 0;
	long long pblk_num = 0;
	int queue = -1;

	for(int i = 0; i < Read_trace.size(); i++)
	{
		last_finish_time = 0;

		if(raw != 1)
		{
			Reset_time();
		}

		for(int j = 0; j < Read_trace[i].datablks.size(); j++)
		{

			pblk_num = blk_mapping[Read_trace[i].datablks[j]];

			if(Routine_N_cache(global_storage[pblk_num]->fp))//N_cache hit
			{

				N_cache_hit++;

				last_finish_time = sys_last_busy_time;
			}
			else//N_cache miss
			{

				N_cache_miss++;

				//starting access nodes
				CurNode = global_storage[pblk_num]->node_num;

				//The node is okay
				if(Cluster[CurNode]->failed != 1 && global_storage[pblk_num]->corrupted != 1)
				{
					Cluster[CurNode]->total_access_count++;
					Cluster[CurNode]->read_access++;

					queue = (Cluster[CurNode]->read_access-1) % QUEUE_NUM;

//					if(raw == 1)
//					{
//						printf("ACCESS Node[%d]: %5lld --> ", CurNode, Cluster[CurNode]->Last_Busy_Time);
//					}

					if (sys_last_busy_time > Cluster[CurNode]->queques[queue])
					{
						Cluster[CurNode]->queques[queue] = sys_last_busy_time + READ_LATENCY + DATA_TRANSMISSION;
					}
					else
					{
	//					printf("Blocked[Node Busy]!\n");
						read_blk_num++;
						Cluster[CurNode]->queques[queue] += READ_LATENCY + DATA_TRANSMISSION;
					}

	//				printf("%5lld\n", Cluster[CurNode]->Last_Busy_Time);
					//sys_last_busy_time = Cluster[CurNode]->Last_Busy_Time + ACCESS_CACHE + SHA1_COST; // the metadata needs to get the read data and compute the sha1 and write into cache.

					if(last_finish_time < Cluster[CurNode]->queques[queue] + ACK_TIME)
						last_finish_time = Cluster[CurNode]->queques[queue] + ACK_TIME;
				}
				else //Degraded read
				{
//					printf("Access [blk: %5lld] in Node[%2d]: Failure!\n", pblk_num, CurNode);
					long long t = Degraded_read(pblk_num);

					if(last_finish_time < t)
						last_finish_time = t;
				}

			}


			if (Read_trace[i].Finish_time < last_finish_time)
			{
				Read_trace[i].Finish_time = last_finish_time;
				Read_trace[i].Lasting_time = Read_trace[i].Finish_time - Read_trace[i].Arrive_time;
				Read_trace[i].t_straggler = Read_trace[i].datablks[j];

//				Read_trace[i].G_value = 1 - ((float) Read_trace[i].Lasting_time / Read_trace[i].datablks.size() / Read_trace[i].straggler_pblk);
			}

		}

		Read_trace[i].G_value = 1 - ((float)(READ_LATENCY + DATA_TRANSMISSION) / Read_trace[i].Lasting_time);

	}

}




void Delete_Process(struct traceline *T_line, int ec)
{
	//metrics[DELETE_NUM].total++;
	//Del_file(&laddr_tree, T_line->file_path);
}


void Print_multimap(multimap<long long, int> &A)
{
	multimap<long long, int>::iterator mi;

	for(mi = A.begin(); mi != A.end(); mi++)
	{
		printf("map[%5lld]  == %d\n", mi->first, mi->second);
	}

}



//analysis Read_request[Count_RIO]
void Schedule_request(long long Count_RIO, int policy)
{

//	printf("Request[%5lld]: ", Count_RIO-1);
	long long start_block = R_Req_Tbl[policy][Count_RIO-1].datablks.front();
	long long end_block = R_Req_Tbl[policy][Count_RIO-1].datablks.back();

	map <long long, vector<long long> >S;
	map <long long, long long >Latest_Arrive_T_per_S;
	map <long long, long long >::iterator li;
	map <long long, vector<long long> >::iterator si;

	S.clear();

	/*Getting the stripe infor*/
	for(int i = 0; i < R_Req_Tbl[policy][Count_RIO-1].datablks.size(); i++)
	{
		long long data = R_Req_Tbl[policy][Count_RIO-1].datablks[i];
		long long arrive_time = R_Req_Tbl[policy][Count_RIO-1].arrive_times[data];
//		printf(" [%5lld: %lld   ] ", data, arrive_time);
		S[data/ec_k].push_back(data);

		li = Latest_Arrive_T_per_S.find(data/ec_k);
		if (li != Latest_Arrive_T_per_S.end())//found
		{
			if(Latest_Arrive_T_per_S[data/ec_k] > arrive_time)
			{
				Latest_Arrive_T_per_S[data/ec_k] = arrive_time;
			}
		}
		else// not found
		{
			Latest_Arrive_T_per_S[data/ec_k] = arrive_time;
		}
	}

//	printf("\n");



	/*print stripe composition of a request*/
//	for(si = S.begin(); si != S.end(); si++)
//	{
//		printf("Stripe[%5lld]:", si->first);
//		for(int i = 0; i < si->second.size(); i++)
//		{
//			printf("%5lld ", si->second[i]);
//		}
//		printf("\n");
//	}


	/*Rescheduling*/
	vector<int>selection;
	vector<long long> fullstripe_num;
	selection.clear();
	fullstripe_num.clear();

	multimap<long long, int>result;
	multimap<long long, int>::iterator ri;
	set<int> free_nodes;
	set<int> H_nodes;

//	printf("Reschedule    : ");
	//process first and last stripe
	for(si = S.begin(); si != S.end(); si++)
	{
		if(S[si->first].size() < ec_k)
		{
			for(int j = 0; j < S[si->first].size(); j++)
			{
				long long datablk = S[si->first][j];
				long long pblk_num = blk_mapping[datablk];
				int node_num = global_storage[pblk_num]->node_num;
//				long long arrive_time = R_Req_Tbl[policy][Count_RIO-1].arrive_times[S[si->first][j]];
				long long arrive_time = Latest_Arrive_T_per_S[datablk/ec_k];

//				printf(" [%5lld: %lld ", datablk, arrive_time);
				//process the request with normal read
				if(Cluster[node_num]->failed != 1 && global_storage[pblk_num]->corrupted != 1)
				{
					//Print_Cluster_Time();
//					printf("  ] ");
					Cluster[node_num]->total_access_count++;
					Cluster[node_num]->read_access++;

					if(sys_last_busy_time < arrive_time)
					{
						sys_last_busy_time = arrive_time;
					}

					if (sys_last_busy_time > Cluster[node_num]->Last_Busy_Time)
					{
						Cluster[node_num]->Last_Busy_Time = sys_last_busy_time + READ_LATENCY + DATA_TRANSMISSION;
					}
					else
					{
						//printf("Blocked[Node Busy]!\n");
						read_blk_num++;
						Cluster[node_num]->Last_Busy_Time += READ_LATENCY + DATA_TRANSMISSION;
					}

					//Print_Cluster_Time();
				}
				else//degraded read
				{
//					printf(" X] ");
					//printf("Access [blk: %5lld] in Node[%2d]: Failure!\n", pblk_num, CurNode);
					long long t = Degraded_read(pblk_num);
				}

			}
		}
		else
		{
			fullstripe_num.push_back(si->first);
		}

	}

	for(int i = 0; i < ec_node; i++)
	{
		result.insert(std::make_pair(Cluster[i]->Last_Busy_Time, i));
		//including the healthy nodes
		if(Cluster[i]->failed != 1)
			free_nodes.insert(i);
	}

//	Print_multimap(result);

	for(int i = 0; i < fullstripe_num.size(); i++)
	{
		H_nodes = free_nodes;
		for(int j = 0; j < ec_k; j++)
		{

//			Print_set(free_nodes);
			ri = result.begin();
//			printf("Begin() [%d]: %5lld\n", ri->second, ri->first);
			while(H_nodes.find(ri->second)==H_nodes.end())// it is not a free node
			{
//				printf("Find a used node: %d\n", ri->second);
				ri++;
			}

			//found a healthy node with the least loads.

			int chosen_node = ri->second;

			long long pblk_num = ec_node * fullstripe_num[i] + chosen_node;
			long long datablk_num = global_storage[pblk_num]->data_blk_num;
			long long arrive_time = Latest_Arrive_T_per_S[datablk_num/ec_k];
			long long lbt = -1;

//			printf(" [N:%5d: %lld ", chosen_node, arrive_time);
			//process the request with normal read
			if(Cluster[chosen_node]->failed != 1 && global_storage[pblk_num]->corrupted != 1)
			{
//				printf("  ] ");
				//Print_Cluster_Time();
				Cluster[chosen_node]->total_access_count++;
				Cluster[chosen_node]->read_access++;

				if(sys_last_busy_time < arrive_time)
				{
					sys_last_busy_time = arrive_time;
				}

				if (sys_last_busy_time > Cluster[chosen_node]->Last_Busy_Time)
				{
					Cluster[chosen_node]->Last_Busy_Time = sys_last_busy_time + READ_LATENCY + DATA_TRANSMISSION;
				}
				else
				{
					//printf("Blocked[Node Busy]!\n");
					read_blk_num++;
					Cluster[chosen_node]->Last_Busy_Time += READ_LATENCY + DATA_TRANSMISSION;
				}

				lbt = Cluster[chosen_node]->Last_Busy_Time;
				result.insert(std::make_pair(lbt, chosen_node));
				result.erase(ri);
				selection.push_back(chosen_node);
				H_nodes.erase(chosen_node);

				//printf("Chosen Node[%d]: %5lld---> %5lld\n", chosen_node, lbt - (READ_LATENCY + DATA_TRANSMISSION), lbt);

				//printf("After insert New\n");
				//Print_multimap(result);

				//printf("After Erase old\n");
				//Print_multimap(result);

				//Print_Cluster_Time();

			}
			else//degraded read
			{
//				printf(" X] ");
				//printf("Access [blk: %5lld] in Node[%2d]: Failure!\n", pblk_num, CurNode);
				long long t = Degraded_read(pblk_num);
			}

		}
	}

//	printf("\n");

//	if(selection.size() != 0)
//	{
//		printf("Chosen Nodes: ");
//		for(int i = 0; i < selection.size(); i++)
//		{
//			printf("%d ", selection[i]);
//		}
//		printf("\n");
//	}

}

int Request(struct traceline *T_line, int policy, int recon)
{

	map<int, int>result;

	if(strcmp("-1", Last_RequestID) == 0 && strcmp(T_line->Type, "read") == 0 )
	{
		return -1;
	}


	if (strcmp(T_line->RequestID, Last_RequestID) == 0)
	{
//		printf("Old request!\n");

		if (strcmp(T_line->Type, "write") == 0)
		{
//			printf("line[%lld] CurReq.W_Req_Index: %lld\n", total_line, CurReq.W_Req_Index);
			T_line->Request_index = (Count_WIO-1);
		}
		else//read
		{
			T_line->Request_index = (Count_RIO-1);
		}
	}
	else//new RequestID
	{

//		printf("New request\n");
		Clear_CurRequest();

		CurReq.Arrive_time = T_line->Arrive_Time;
		CurReq.Finish_time = T_line->Finish_Time;

		CurReq.RequestID = strdup(T_line->RequestID);
		CurReq.Type = strdup(T_line->Type);
		CurReq.straggler = T_line->trace_num;

		if (strcmp(T_line->Type, "write") == 0)
		{
			CurReq.W_Req_Index = Count_WIO;
			T_line->Request_index = CurReq.W_Req_Index;
			Count_WIO++;
			W_Req_Tbl[policy].push_back(CurReq);
//			printf("[In Request]: Write_index[%lld]\n", CurReq.W_Req_Index);
		}
		else//read
		{
			//calculate CDF of last read request
			if(Count_RIO -1 >= 0)
			{
				if(recon == 1)
					Schedule_request(Count_RIO, policy);

				load_balancer_lbt[recon].push_back(Calculate_distance_lbt());
				load_balancer_access[recon].push_back(Calculate_distance_access());
			}
//
//			Reset_time();

			CurReq.R_Req_Index = Count_RIO;
			T_line->Request_index = CurReq.R_Req_Index;
			Count_RIO++;

			R_Req_Tbl[policy].push_back(CurReq);

		}

		if(Last_RequestID != NULL)
			free(Last_RequestID);
		Last_RequestID = strdup(T_line->RequestID);

	}

	return 0;

}

void Print_Req_Tbl(std::vector< vector<struct Request> >&Req_Tbl, int write)
{
	if(write == 1)
	{
		printf("----------------------Write_Request_Table--------------------\n");
	}
	else
		printf("----------------------Read_Request_Table--------------------\n");

//	printf("RequestID\tType\tLasting_time\tArrive_time\tFinish_time\n");
	std::cout << "RID\tType\t \t \t Datablk_set(BA) \t Datablk_set(RA) \t Datablk_set(DA)\n";

	for(int w = 0; w < Req_Tbl[0].size(); w++)
	{
//		std::cout << Req_Tbl[0][w].RequestID << "\t" << Req_Tbl[0][w].Type << "\t";
//
//		for (int i = 0; i < Req_Tbl.size(); i++)
//		{
////			if (strcmp(Req_Tbl[i].Type, "write") == 0)
////			{
////				W_Request_lasting_time += Req_Tbl[i].Lasting_time;
////			}
////			else
////			{
////				R_Request_lasting_time += Req_Tbl[i].Lasting_time;
////			}
//
////			std::cout << Req_Tbl[0][i].RequestID << "\t" << Req_Tbl[0][i].Type << "\t" << "\t" << Req_Tbl[0][i].Lasting_time << "\t" << Req_Tbl[0][i].Arrive_time
////				<< "\t" << Req_Tbl[0][i].Finish_time << "\t";
//
////			cout << i ;
//
//
//
//			printf("[ ");
//
//			if(Req_Tbl[i][w].datablks.size() <= ec_node)
//			{
//				for(int j = 0; j < Req_Tbl[i][w].datablks.size(); j++)
//				{
//					printf("%lld ", Req_Tbl[i][w].datablks[j]);
//				}
//			}
//			else
//				printf("%ld ",Req_Tbl[i][w].datablks.size());
//
//			printf("] ");
//
//
//			if(write != 1)//read trace
//			{
//				printf(" %.2f",  Req_Tbl[i][w].G_value);
//			}
//
//			printf("\t\t");
//
//
//		}

		printf("\n");
	}




	printf("\n");
}

void Process_ReadTrace(std::vector<struct Read_request> &Read_trace, std::vector<struct Request> &W_R_Tbl, int tracetype, struct Result &res, int iteratimes)
{
	//	/*----------All whole-request-read------------------*/
	switch (tracetype)
	{
		    case ALL_REQ_READ :
		    {
		    	Generalize_ReadTrace_ALL(Read_trace, W_R_Tbl, WRITE);
		    	Read_Table(Read_trace, 0);
//		    	Print_ReadTrace(Read_trace);
		    	Calculate_Result(res, Read_trace, tracetype);
		    	break;
		    }

		    case ALL_REQ_READ_RAN :
		    {
		    	float sum = 0;
		    	float Ave_G = 0;

		    	for(int seed = 0; seed < iteratimes; seed++)
		    	{

		    		Generalize_ReadTrace_random(Read_trace, W_R_Tbl, seed);

		    		Read_Table(Read_trace, 0);
//		    		Print_ReadTrace(Read_trace);
		    		sum += Sum(Read_trace);
		    		//printf("[%d] sum = %5.3f\n", seed, sum);
		    	}

		    	Ave_G = sum / iteratimes;
		    	res.value.insert(std::make_pair(ALL_REQ_READ_RAN,Ave_G));
		    	break;
		    }
		    case ALL_RANDOM:
		    {
		    	float sum = 0;
		    	float Ave_G = 0;
		    	for(int seed = 0; seed < iteratimes; seed++)
		    	{
		    		Generalize_ReadTrace_All_random(Read_trace, datablk_serial, seed, ec_node);

		    		Recover_Cluster();
		    		Create_Node_Failure(seed);

		    		Read_Table(Read_trace, 0);
//		    		Print_ReadTrace(Read_trace);
		    		sum += Sum(Read_trace);
		    		//printf("[%d] sum = %5.3f\n", seed, sum);
		    	}

		    	Ave_G = sum / iteratimes;
		    	res.value.insert(std::make_pair(ALL_RANDOM,Ave_G));
		    	break;
		    }

		    case ALL_SHORT:
		    {
		    	Generalize_ReadTrace_ALL_SPECIAL(Read_trace, W_R_Tbl, WRITE, tracetype);
		    	Read_Table(Read_trace, 0);
		    //	Print_ReadTrace(Read_trace);
		    	Calculate_Result(res, Read_trace, tracetype);
		    	break;
		    }
		    case ALL_LONG :
		    {
		    	Generalize_ReadTrace_ALL_SPECIAL(Read_trace, W_R_Tbl, WRITE, tracetype);
		    	Read_Table(Read_trace, 0);
		    //	Print_ReadTrace(Read_trace);
		    	Calculate_Result(res, Read_trace, tracetype);
		    	break;
		    }
		    case NO_TRACE:
		    {
		    	printf("No Read trace Processed!\n");
		    	break;
		    }
		    default:
		    	printf("ERROR");
		        break;


	}

}


void Deal_last_request(int Count_RIO, int policy)
{
	Schedule_request(Count_RIO, policy);
}

struct Result Process(char **files, int trace_start, int trace_end, struct traceline *T_line, int ec, int policy, int iteratimes, int degraded, int recon)
{
	FILE *file = NULL;
	struct Result res;
	std::vector<struct Read_request> Read_trace;
	total_line = 0;
	bad_line = 0;
	empty_line = 0;
	effective_line_count = 0;
	int last_op = -1; // 1 is for write, 2 is for read

	res.policy = policy;

	if(recon == 1)
	{
		printf("using Recon!\n");
	}

	else
	{
		printf("Using normal!\n");
	}


	switch(policy)
	{
		case 0:
			res.p_name = (char *)"BA";
			break;
		case 1:
			res.p_name = (char *)"RA";
			break;
	    case 2:
	    	res.p_name = (char *)"DA";
	    	break;
	    case 3:
	    	res.p_name = (char *)"DA_noRR";
	    	break;
	    case 4:
	    	res.p_name = (char *)"DA_access_b";
	    	break;
	    case 5:
	    	res.p_name = (char *)"DA_lbt_b";
	        break;
	    case 6:
	    	res.p_name = (char *)"DA_lbt_mix";
	    	break;
	    case 7:
	   	    res.p_name = (char *)"DA_SRA_B";
	   	    break;
	    case 8:
	   	    res.p_name = (char *)"P_Balance";
	   	    break;
	    default:
	    	res.p_name = (char *)"Wrong Policy";
	}

	if(degraded == 0)
		printf("-----------------------[%-10s]---------------------------\n", res.p_name);

	char buffer[MAX_PATH_SIZE + MAX_META_SIZE];

	for (int i = 0; i < trace_end - trace_start; ++i)
	{
		file = fopen(files[i], "r");
		
		if (file == NULL) 
		{
			printf("Open tracefile[%d] fail %s\n", i, strerror(errno));
			continue;
		}
		
		//new file we'll reset the time.
		Reset_time();
		global_time = 0;

	    while(fgets(buffer, MAX_PATH_SIZE + MAX_META_SIZE, file) != NULL)
	    {
	    	total_line++;

	    	if(total_line == 148)
	    	{
	    		printf("now [%lld]\n", total_line);
	    	}

		    if (strcmp(buffer, "\n") == 0)
		    {
		        empty_line++;
	    		continue;
		    }
	    	
		    if(Split_Trace(buffer, T_line) == 0)
		    {
		    	effective_line_count++;

//				printf("--------------------------------line[%lld]: %s----------------------\n", total_line, T_line->Type);
//				printf("line[%4lld]: A_time: %lld pos: %lld ReqID: %s Type:%s \n", total_line, T_line->Arrive_Time, T_line->pos, T_line->RequestID, T_line->Type);

				if(Request(T_line, policy, recon) == -1)
					continue;

				if(strcmp(T_line->Type, "write") == 0)
				{
					write_count++;

					if(last_op == -1)
						last_op = 1;
					else if(last_op == 2)
					{
//						Reset_time();
						last_op = 1;
					}

					if(sys_last_busy_time < T_line->Arrive_Time)
		    		{
		    			sys_last_busy_time = T_line->Arrive_Time;
		    		}

//					Write_Process(T_line, ec, policy);
					Write_Process_no_cal(T_line, ec, policy);
					
				} 
				else if (strcmp(T_line->Type, "read") == 0)
				{

					if(soe.full != 0)
					{
						sys_last_busy_time += ENCODE_COST;

			   			int s_p = Placement(soe,policy);
			   			Finish_time_SOE(s_p, policy);
			   			Reset_SOE(ec_k);

					}

					if(last_op == -1)
					{
						last_op = 2;
						continue;
					}
					else if(last_op == 1)
					{
//						Reset_time();
						last_op = 2;
//						printf("----------------------------Start Read Process!------------------------\n");

//						Cluster[0]->failed = 1;

						if(degraded == 1)
						{
							Recover_Cluster();
							Cluster[iteratimes]->failed = 1;
						}

					}

					if(recon == 0)
					{
						if(sys_last_busy_time < T_line->Arrive_Time)
						{
							sys_last_busy_time = T_line->Arrive_Time;
						}
					}
					else//recon scheduler system_last_busy_no_change
					{

					}
					read_count++;
					Read_by_FP(T_line, policy, recon);
//					Read_by_lpblk(T_line, policy);
				}
				else
				{
					other_count++;
				}
				
				Clear_Traceline(T_line);	
		    }
		    else
		    {
		    	bad_line++;
		    }

		}


//	    float a = Calculate_G(Count_RIO-1, policy);
//		Cal_CDF(a);

		if(soe.full != 0)
		{
//			printf("[End of File]--> Placement!\n");
			sys_last_busy_time += ENCODE_COST;

			int s_p = Placement(soe, policy);
			Finish_time_SOE(s_p, policy);
//			Print_SOE();
//			Print_stripe(s_p);
			Reset_SOE(ec_k);
		}

		if(recon == 1)
		{
			Deal_last_request(R_Req_Tbl[policy].size(), policy);
		}
	}
	

	Print_Cluster_Time();

	Print_stripe_tbl();

	if(policy == Policy - 1)
	{
//		Print_Req_Tbl(W_Req_Tbl, WRITE);
//		Print_Req_Tbl(R_Req_Tbl, READ);
	}
//	Print_Blk_Mapping();

	Generalize_ReadTrace_ALL(Read_trace, R_Req_Tbl[policy], READ);
//	Print_ReadTrace(Read_trace);

//	Read_Table(Read_trace, 1);
//	Print_ReadTrace(Read_trace);
//	Output_ReadTrace(Read_trace, policy, 1);

//	Calculate_Result(res, Read_trace, RAW_TRACE);

	if(degraded == 0)
	{
		/*------------------------------------------------------------Generate read_countRead_Trace-------------------------------------------------*/
//		Process_ReadTrace(Read_trace, W_Req_Tbl[0], ALL_REQ_READ, res, iteratimes);
//		Process_ReadTrace(Read_trace, W_Req_Tbl[0], ALL_REQ_READ_RAN, res, iteratimes);
//		Process_ReadTrace(Read_trace, W_Req_Tbl[0], ALL_RANDOM, res, iteratimes);
//		Process_ReadTrace(Read_trace, W_Req_Tbl[0], ALL_SHORT, res, iteratimes);
//		Process_ReadTrace(Read_trace, W_Req_Tbl[0], ALL_LONG, res, iteratimes);
	    /*-------------------------------------------------------------------------------------------------------------------------------------------*/

		if(policy == 0)
	    {
		    printf("totalline: %lld || effectiveline: %lld || writecount: %lld || readcount: %lld || badread: %lld degraded_read: %lld || othercount: %lld\n", total_line, effective_line_count, write_count, read_count, readline_not_by_fp, degraded_read, other_count);

		    long long unique_fp = HASH_COUNT(fp_store);
		    printf("Dup_rate: %f\n", (double)(write_count-unique_fp)/(double)write_count);
		    printf("R/W [%4.3f] Read block time[Node busy]: %lld\n", (float) read_count / write_count, read_blk_num);
	    }
	}

	Cal_total_latency();

////Output_Result(policy);
//	printf("policy: %2d  %lld\n", policy, R_Request_lasting_time);

	//printf("pblk number is: %ld\n", pblk_used);
	return res;

}



