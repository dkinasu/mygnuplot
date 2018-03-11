/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "trace.h"


void Init_CurRequest()
{
	CurReq.R_Req_Index = -1;
	CurReq.W_Req_Index = -1;
	CurReq.Arrive_time = -1;
	CurReq.Finish_time = -1;
	CurReq.Lasting_time = -1;
	CurReq.straggler = -1;
	CurReq.G_value = -1;
	CurReq.L_time_straggler = -1;

	CurReq.RequestID = NULL;
	CurReq.Type = NULL;
	CurReq.used_nodes.clear();

	CurReq.remain.clear();
	CurReq.reponse_times.clear();

	for(int i = 0; i < ec_node * QUEUE_NUM; i++)
	{
		CurReq.remain.insert(i);
	}

	CurReq.datablks.clear();
	CurReq.arrive_times.clear();
}

void Clear_CurRequest()
{
	CurReq.R_Req_Index = -1;
	CurReq.W_Req_Index = -1;
	CurReq.Arrive_time = -1;
	CurReq.Finish_time = -1;
	CurReq.Lasting_time = -1;
	CurReq.straggler = -1;
	CurReq.G_value = -1;
	CurReq.L_time_straggler = -1;

	CurReq.used_nodes.clear();

	CurReq.remain.clear();

	CurReq.datablks.clear();
	CurReq.arrive_times.clear();
	CurReq.reponse_times.clear();

	for(int i = 0; i < ec_node * QUEUE_NUM; i++)
	{
		CurReq.remain.insert(i);
	}


	if(CurReq.RequestID != NULL)
		CurReq.RequestID = NULL;

	if(CurReq.Type != NULL)
		CurReq.Type = NULL;
}




void Init_LastReqestID()
{
	Last_RequestID = strdup("-1");
//	strcpy(Last_RequestID, "00000000000000000000");
}




/*
//Parse each traceline and load into &Tline
int TraceLine_Parse(char * buffer, struct traceline *T_line)
{
    //printf("------------------------Parsing One TraceLine----------------------------\n");
	int i = 0;
	char *result = NULL;

	//strsep::  seperate the str with the deliminater ","
	//result is NULL
	//get every single part of the traceline, and put them into replay_node
	while((result = strsep(&buffer, ",")) != NULL) {
		
		switch(i) {
		case 0:
			//get the time_stamp, and put into the &replay_node->time_stamp
			sscanf(result, "%llu", &T_line->time_stamp);
			break;
		case 1:
			T_line->file_path = (char *)malloc(strlen(result) + 1);
			strncpy(T_line->file_path, result, strlen(result));
			T_line->file_path[strlen(result)] = '\0';
			break;
		case 2:
			sscanf(result, "%lu", &T_line->inode_no);
			break;
		case 3:
			sscanf(result, "%lu", &T_line->data_f8);
			break;
		case 4:
			sscanf(result, "%ld", &T_line->pos);
			break;
		case 5:
			//this decides read or write
			sscanf(result, "%d", &T_line->rw);
			break;
		case 6:
			strcpy(T_line->pname, result);
			break;
		case 7:
			if ((strlen(result)) != 41) 
			{
				printf("result: %lu\n", strlen(result));
				T_line->databuf = NULL;
				return 0;
			} 
			else 
			{
				
				T_line->databuf = (char *)malloc(sizeof(char) * (f8_PER_FPRECORD) + 1);
				
				if (!T_line->databuf) 
				{
					printf("low memory on host!\n");
					exit(-1);
				}

				strncpy(T_line->databuf, result, f8_PER_FPRECORD);
				
				if (f8_PER_FPRECORD != (strlen(result) - 1)) 
				{
					
					metrics[PAGE_f8_WRONG].total ++;
				}
				
				T_line->databuf[f8_PER_FPRECORD] = '\0';
			}

			break;
		}

		i++;
	}
	return 1;

    //printf("------------------------Finish Parsing----------------------------------------\n");
}
*/

long long int str2num(char str1[], char str2[])
{
	long long int num = 0, m = 1, q = 0;
	int f7g = strlen(str2);
	for (q = 0; q < f7g; q++)
		m = m * 10;
	num = atoi(str2) + atoi(str1)*m;
	return num;
}



//Parse each traceline and load into &Tline
int Split_Trace(char * buffer, struct traceline *T_line)
{	
	char f1[200];
	
	char *time1;
	char *time2;
	char f2[10];
	char f3[64], f4[64], f5[64], f6[64], f7[64], f8[64], f9[300], f10[64], f11[SHA1SIZE], f12[64];//

	char reqID[50];

	if(trace < 4)
	{
		//split trace for CAFTL
		sscanf(buffer, "[ %s%s%s%s%s%s%s%s%s%s%s%s", f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12);

//		printf("f4 = %s f5 = %s f10 = %s\n", f4, f5, f10);

		// //long long int address = str2num(f5, f9) % MAX_ADDR;

		T_line->Address = str2num(f5, f9) % 10000000;
//		T_line->Address = address;

		//getting the arrival time. f1 is where the time is.
//		printf("f1=%s ", f1);
		char seps[] = ".]";
		time1 = strtok(f1, seps);
		time2 = strtok(NULL, seps);

		long long a_t = str2num(time1, time2);// the unit of time is us.

		if(total_line - 1 == 0)
		{
			First_Arrive_T = a_t;
		}

		T_line->Arrive_Time = a_t - First_Arrive_T;

//		printf("A_T: %lld\n", T_line->Arrive_Time);
//		T_line->Arrive_Time = global_time++;

		T_line->Sha1 = strdup(f11);
		T_line->RequestID = strdup(f4);
		T_line->file_path =  strdup(f6);

		T_line->Type =  strdup(f10);

//		if(strcmp(T_line->Type, "read") == 0)
//		{
//			T_line->Arrive_Time = 0;
//		}
		 // printf("file_path: %s  bio_sector: %s\n", T_line->file_path,  f6);

		T_line->pos = T_line->Address % 1000;
	}
	else//fiu trace
	{
		//	split trace for FIU_trace
		//	printf("sizeof buffer: %ld strlen of buffer: %ld\n", sizeof(buffer), strlen(buffer));

		if(strlen(buffer) > 400)
			return -1;

		sscanf(buffer, "%s%s%s%s%s%s%s%s%s", f1, f2, f3, f4, f5, f6, f7, f8, f9);


		T_line->Address = atoi(f4);
		T_line->Arrive_Time = global_time++;

		T_line->Sha1 = strdup(f9);
		//	printf("sizeof Sha1: %ld   strlen sha1: %ld\n", sizeof(T_line->Sha1), strlen(T_line->Sha1));

//		printf("Address is :%lld  L_A: %lld\n", T_line->Address, Last_address);
		if(llabs(T_line->Address-Last_address) > 8)
		{
//			printf("New request! \n");
			req_serial++;
		}

		sprintf(reqID, "%lld", req_serial);
		reqID[strlen(reqID)] = '\0';

		T_line->RequestID = strdup(reqID);

		Last_address = T_line->Address;

		T_line->file_path =  strdup(f3);

		if(strcmp(f6, "W") == 0)
		{
			T_line->Type =  strdup("write");
		}
		else if (strcmp(f6, "R") == 0)
		{
			T_line->Type =  strdup("read");
		}

		T_line->pos = T_line->Address;
	}

	T_line->fp = NULL;
	T_line->Request_index = 0;
	T_line->trace_num = total_line -1;
	T_line->datablk = -1;


//	Print_traceline(T_line);
	return 0;

}



void Generalize_ReadTrace_ALL_SPECIAL(std::vector<struct Read_request> &ReadTrace, std::vector<struct Request> &Req_Tbl, int write, int type)
{
	struct Read_request t;

	ReadTrace.clear();

	if(type == ALL_SHORT)
	{
		printf("Generating short requests\n");
	}
	else if(type == ALL_LONG)
	{
		printf("Generating Long requests\n");
	}


	for(int i = 0; i < Req_Tbl.size(); i++)
	{
		if(write == 1)
		{
			if(type == ALL_SHORT)
			{
				if( Req_Tbl[i].datablks.size() <= ec_node)
				{
					t.Arrive_time = 0;
					t.Finish_time = -1;
					t.Lasting_time = 0;
					t.G_value = -1;


					t.R_Req_Index = i+1;
					t.t_straggler = Req_Tbl[i].straggler;
					t.datablks.clear();
					t.datablks = Req_Tbl[i].datablks;
					t.reponse_times = Req_Tbl[i].reponse_times;
					ReadTrace.push_back(t);
				}
			}
			else if(type == ALL_LONG)
			{
				if( Req_Tbl[i].datablks.size() > ec_node)
				{
					t.Arrive_time = 0;
					t.Finish_time = -1;
					t.Lasting_time = 0;
					t.G_value = -1;



					t.R_Req_Index = i+1;
					t.t_straggler = Req_Tbl[i].straggler;
					t.datablks.clear();
					t.datablks = Req_Tbl[i].datablks;
					t.reponse_times = Req_Tbl[i].reponse_times;
					ReadTrace.push_back(t);
				}
			}
			else
			{
				printf("Trace generated error!\n");
				return ;
			}

		}
		else
		{
			continue;
		}

	}
//	Print_ReadTrace(ReadTrace);
}


void Generalize_ReadTrace_ALL(std::vector<struct Read_request> &ReadTrace, std::vector<struct Request> &Req_Tbl, int write)
{
	struct Read_request t;

	ReadTrace.clear();

	for(int i = 0; i < Req_Tbl.size(); i++)
	{
		t.Arrive_time = 0;
		t.Finish_time = -1;
		if(write == 1)
		{
			t.Lasting_time = 0;
			t.G_value = -1;
		}
		else
		{
			t.Lasting_time = Req_Tbl[i].Lasting_time;
			t.G_value = Req_Tbl[i].G_value;

//			t.Lasting_time = 0;
//			t.G_value = -1;
		}

		t.R_Req_Index = i+1;
		t.t_straggler = Req_Tbl[i].straggler;
		t.datablks.clear();
		t.datablks = Req_Tbl[i].datablks;
//		t.A_time = Req_Tbl[i].Arrive_time;
		t.reponse_times = Req_Tbl[i].reponse_times;

		ReadTrace.push_back(t);
	}

//	Print_ReadTrace(ReadTrace);
}

//modify the size of intra-request read
void Generalize_ReadTrace_random(std::vector<struct Read_request> &Read, std::vector<struct Request> &Req_Tbl, int seed)
{
	struct Read_request t;
	int z = 0;
	int counter = 0;
	int flag = 0;

	Read.clear();

	std::vector<long long> index_set;

	for(int i = 0; i < Req_Tbl.size(); i++)
	{
		index_set.push_back(i);
	}

	srand(time(NULL)+seed);

	flag = rand() % Req_Tbl.size() + 1;

	std::random_shuffle(index_set.begin(), index_set.end());

	index_set.resize(flag);

	for(int j = 0; j < flag; j++)
	{
		srand(time(NULL)+seed + j);

		z = (rand()% Req_Tbl[index_set[j]].datablks.size())+1;

//		printf("Flag is %d [z = %d]\n", flag, z);
		counter++;

		t.Arrive_time = 0;
		t.Finish_time = -1;
		t.Lasting_time = 0;
		t.G_value = -1;

		t.R_Req_Index = counter;
		t.t_straggler = -1;
		t.datablks.clear();

		std::vector<long long>tmp;
		tmp = Req_Tbl[index_set[j]].datablks;

		std::random_shuffle(tmp.begin(), tmp.end() );

		tmp.resize(z);

		t.datablks = tmp;

//		for(int j = 0; j < z; j++)
//		{
//			t.datablks.push_back(tmp[j]);
//		}

		Read.push_back(t);


	}





//	srand(time(NULL));
//
//	int flag = 0;
//
//
//	for(int i = 0; i < Req_Tbl.size(); i++)
//	{
//		srand(time(NULL)+seed + i);
//
//		flag = rand()%2;
//
//		if(flag == 0)
//			continue;
//
//		z = (rand()% Req_Tbl[i].datablks.size())+1;
//		counter++;
//
//		t.Arrive_time = 0;
//		t.Finish_time = -1;
//		t.Lasting_time = 0;
//		t.G_value = -1;
//
//		t.R_Req_Index = counter;
//		t.straggler_pblk = -1;
//		t.datablks.clear();
//
//		std::vector<long long>tmp;
//		tmp = Req_Tbl[i].datablks;
//		std::random_shuffle(tmp.begin(), tmp.end() );
//
//		for(int j = 0; j < z; j++)
//		{
//			t.datablks.push_back(tmp[j]);
//		}
//
//		Read.push_back(t);
//	}

//	Print_ReadTrace(ReadTrace);
}


//Modify this.
void Generalize_ReadTrace_All_random(std::vector<struct Read_request> &Read, long long pblk_num, int seed, int node_num)
{
	struct Read_request t;
	long long flag = 0;
	int z = -1;
	int counter = 0;
	int index = 0;

	Read.clear();

	srand(time(NULL)+seed);
	flag = random() % (pblk_num);
//	printf("pblk_num: %lld\n", pblk_num);

	while(counter < pblk_num)
	{
		t.Arrive_time = 0;
		t.Finish_time = -1;
		t.Lasting_time = 0;
		t.G_value = -1;
		t.R_Req_Index = index+1;
		t.t_straggler = -1;

		srand(time(NULL)+counter+seed);

		z = random() % node_num +1; //Per request size

		for(int j = 0; j < z && (counter < pblk_num); j++) // just cover all the data for once
		{
//			int m;
//
//			while(global_storage[flag]->parity == 1 || global_storage[flag]->dummy == 1)
//			{
//				m = flag+1;
//				flag = m % pblk_num;
//				counter++;
//			}

//			printf("Flag is %lld\n", flag);
			t.datablks.push_back(flag);
			counter++;
			flag++;
			flag %= pblk_num;
		}

		Read.push_back(t);
		index++;

		t.datablks.clear();
	}

//	Print_ReadTrace(ReadTrace);

}

//it is depreciated!
void Generalize_ReadTrace_partial_random(std::vector<struct Read_request> &ReadTrace, long long pblk_num, int Req_size, int node_num)
{
	struct Read_request t;
	long long flag = 0;
	int i = 0;
	int counter = 0;
	int m;

	ReadTrace.clear();

	srand(time(NULL));
	flag = random() % (pblk_num);

	while(counter + dummy_pblk <= pblk_num)
	{
		t.Arrive_time = 0;
		t.Finish_time = -1;
		t.Lasting_time = 0;
		t.G_value = -1;
		t.R_Req_Index = i+1;
		t.t_straggler = -1;

		i++;

		for(int j = 0; j < Req_size; j++)
		{
//
			while(global_storage[flag]->parity == 1 || global_storage[flag]->dummy == 1)
			{
				m = flag+1;
				flag = m % pblk_num;
				counter++;
			}

//			printf("Flag is %lld\n", flag);
			t.datablks.push_back(flag);
			counter++;
			m = flag+1;
			flag = m % pblk_num;

		}

		ReadTrace.push_back(t);

		t.datablks.clear();
	}

//	Print_ReadTrace(ReadTrace);
}

void Calculate_Result(struct Result &t, std::vector<struct Read_request> ReadTrace, int res_type)
{
	long long total_read_time = 0;
	float total_G = 0;
	float ave_G = 0;

	for(int i = 0; i < ReadTrace.size(); i++)
	{
		if(ReadTrace[i].Lasting_time != -1)
			total_read_time += ReadTrace[i].Lasting_time;

		if(ReadTrace[i].G_value != -1)
			total_G += ReadTrace[i].G_value;
	}

	ave_G = total_G / ReadTrace.size();
//	printf("Hello\n");

/*#define ALL_REQ_READ 1 | ALL_REQ_READ_RAN 2 | FIX_SIZE_RANDOM 3 | ALL_RANDOM 4 */
/*#define DEGRADE_ALL_REQ_READ 5  DEGRADE_ALL_REQ_READ_RAN 6 | DEGRADE_FIX_SIZE_RANDOM 7  | DEGRADE_ALL_RANDOM 8 */
	t.value.insert(std::make_pair(res_type,ave_G));

	if(res_type == RAW_TRACE)
		t.total_latency = total_read_time;
//	printf("in the map: value[%d] =  %f\n", res_type, t.value[res_type]);

}

void Output_ReadTrace(std::vector<struct Read_request> &ReadTrace, int policy, int fiu)
{
	char *result_prefix = (char *)".res";
	char *trace;

	char *R_output = (char *)malloc(500 * sizeof(char));


	if(fiu == 1)
	{
		trace = (char *)"fiu";
	}
	else
		trace = (char *)"caftl";

	sprintf(R_output, "%s%d%s", trace, policy, result_prefix);

	FILE *R_out;

    //open result
    R_out = fopen(R_output, "wb+");

    char result_buf[4096];

    for (int i = 0; i < ReadTrace.size(); i++)
    {
        if(ReadTrace[i].Lasting_time != 0)
        {
        		R_Request_lasting_time += ReadTrace[i].Lasting_time;
        		sprintf(result_buf, "%-6lld  %10lld  %20.2f\n", ReadTrace[i].R_Req_Index, ReadTrace[i].Lasting_time, ReadTrace[i].G_value);
        		result_buf[strlen(result_buf)] = '\0';
           		fwrite(result_buf, 1, strlen(result_buf), R_out);
        }

    }

}

void Output_Data(int policy, int fiu)
{
	char *result_prefix = (char *)".res";
	char *trace;

	char *R_output = (char *)malloc(500 * sizeof(char));


	if(fiu == 1)
	{
		trace = (char *)"fiu";
	}
	else
		trace = (char *)"caftl";

	sprintf(R_output, "%s%d%s", trace, policy, result_prefix);

	FILE *R_out;

    //open result
    R_out = fopen(R_output, "wb+");

    char result_buf[4096];

	if(policy == 0)
    {
	    sprintf(result_buf, "totalline: %lld || effectiveline: %lld || writecount: %lld || readcount: %lld || badread: %lld degraded_read: %lld || othercount: %lld\n", total_line, effective_line_count, write_count, read_count, readline_not_by_fp, degraded_read, other_count);
	    result_buf[strlen(result_buf)] = '\0';
	    fwrite(result_buf, 1, strlen(result_buf), R_out);

	    long long unique_fp = HASH_COUNT(fp_store);
	    sprintf(result_buf, "Dup_rate: %f\n", (double)(write_count-unique_fp)/(double)write_count);
	    result_buf[strlen(result_buf)] = '\0';
	    fwrite(result_buf, 1, strlen(result_buf), R_out);
	    sprintf(result_buf, "R/W [%4.3f] Read block time[Node busy]: %lld\n", (float) read_count / write_count, read_blk_num);

	    result_buf[strlen(result_buf)] = '\0';
	    fwrite(result_buf, 1, strlen(result_buf), R_out);
    }

}





void Print_ReadTrace(std::vector<struct Read_request> &ReadTrace)
{
	printf("%6s  %10s  %-40s  %4s  \n", "Index", "L_time", "Datablk_set", "G_value");

	map<long long, long long>::iterator ai;

	for (int i = 0; i < ReadTrace.size(); i++)
	{

		printf("%-6lld  %10lld ", ReadTrace[i].R_Req_Index, ReadTrace[i].Lasting_time);

		for(int j = 0; j < ReadTrace[i].datablks.size(); j++)
		{
			long long data = ReadTrace[i].datablks[j];
//			printf(" %2lld ", ReadTrace[i].datablks[j] % ec_node);
			printf(" [%5lld: XX] ", data);
		}


		printf(" %20.2f ", ReadTrace[i].G_value);

//		printf(" %lld ", ReadTrace[i].t_straggler);

		printf("\n");
	}

}


//Clear the Tline
int Clear_Traceline(struct traceline *T_line)
{
	// printf("Clear Traceline\n");
	T_line->Arrive_Time = -1;
	T_line->Finish_Time = -1;
	T_line->Address = -1;
	T_line->Hit = -1;
	T_line->Request_index = -1;
	T_line->trace_num = -1;

	T_line->pos = -1;
	T_line->fp = NULL;
	T_line->Sha1 = NULL;
	T_line->RequestID = NULL;
	T_line->Type = NULL;
	T_line->file_path = NULL;


	//do not free those, cos copies in soe will change.
//	free(T_line->Sha1);
//	free(T_line->RequestID);
//	free(T_line->Type);ec_node
//	free(T_line->file_path);

	T_line->dup.clear();

	return 0;
}

//print_trace
void Print_traceline(struct traceline *T_line)
{
	// printf("T_line->Arrive_Time: %lld\n", T_line->Arrive_Time);
	// printf("T_line->Finish_Time: %lld\n", T_line->Finish_Time);
	// printf("T_line->Sha1: %s\n", T_line->Sha1);
	// printf("T_line->RequestID: %s\n", T_line->RequestID);
	// printf("T_line->Address: %lld\n", T_line->Address);
	// printf("T_line->Type: %s\n", T_line->Type);
	// printf("T_line->Hit: %d\n", T_line->Hit);
	printf("line[%lld]: %lld %lld %s %s %lld %s %lld %lld\n", total_line, T_line->Arrive_Time, T_line->Finish_Time, T_line->Sha1, T_line->RequestID, T_line->Address, T_line->Type, T_line->pos, T_line->Request_index);
}

//Parse the args of input
int Argv_Parse(int argc, char ** argv, char *file_prefix, char *file_suffix)
{  
    //printf("------------------------Doing Argv_Parsing----------------------------\n");
	
	if (argc < 9) {
		printf("Do not have enough parameters!\n");
		printf("Usage: ./main [tracefolder_path/] [(policy)1|2] [start_num] [end_num] [result_file] [node_num] [max_blk_num] [maxFp_num] [cache_f8]\n");
		return -1;
	}
                   
    DIR *sp;

//    printf("argv[1]: %s\n", argv[1]);

	if((sp = opendir(argv[1])) == 0) 
    {
		perror("fail to open dir");
		return -1;
	}
    closedir(sp);

	//assign args
	trace_start = atoi(argv[2]);
    trace_end = atoi(argv[3]);
    ec_node = atoi(argv[5]);
    printf("EC_node: %d\n", ec_node);
    max_fp_num = atoi(argv[6]);
    max_blk_num = atoi(argv[7]);
    cache_size = atoi(argv[8]);
    
    // form the legal tracefile address
    files = (char **)malloc((trace_end - trace_start)*sizeof(char *));
    
    for(int i = 0; i < (trace_end - trace_start); i++)
    {
    		files[i] = (char *)malloc(500 * sizeof(char));
    		memset(files[i], '\0', 500);

    		if(file_suffix != NULL)
    			sprintf(files[i], "%s%s%d%s", argv[1], file_prefix, i + trace_start, file_suffix);
    		else
    			sprintf(files[i], "%s%s%d", argv[1], file_prefix, i + trace_start);
    		printf("file[%d]: %s\n", i, files[i]);
   	}
    
    return 0;
    //printf("------------------------Finish Argv_Parsing----------------------------\n");

};

void Print_Req_used_nodes(std::vector<struct Request> &Req_Tbl, long long index)
{
	std::set<int>::iterator si;
	
	printf("Used_nodes: ");

	for (si = Req_Tbl[index].used_nodes.begin(); si != Req_Tbl[index].used_nodes.end(); si++)
	{
		printf("%d ", (*si));
	}

	printf("\n");
}

void Print_Req_remain_nodes(std::vector<struct Request> &Req_Tbl, long long index)
{
	std::set<int>::iterator si;

	printf("\nRemaining_nodes: ");

	for (si = Req_Tbl[index].remain.begin(); si != Req_Tbl[index].remain.end(); si++)
	{
		printf("%d ", (*si));
	}

	printf("\n");
}



//write the results to the place of *result
void Output_Result(int policy)
{
	// printf("1\n");
	char *result_prefix = (char *)".res";
	
	char *R_output = (char *)malloc(500 * sizeof(char));
//	char *W_output = (char *)malloc(500 * sizeof(char));


	sprintf(R_output, "%s%d%s", "Read", policy, result_prefix);
//	sprintf(W_output, "%s%d%s", "Write", policy, result_prefix);

    FILE *R_out;
//	FILE *W_out;
    
    char result_buf[4096];


    //open result
    R_out = fopen(R_output, "wb+");
//  W_out = fopen(W_output, "wb+");
  

    for (int i = 0; i < Count_WIO; i++)
    {
    	    W_Request_lasting_time += W_Req_Tbl[policy - 1][i].Lasting_time;
//    	sprintf(result_buf, "%-8lld%10s%10lld%10lld%10lld\n", W_Req_Tbl[i].W_Req_Index, W_Req_Tbl[i].RequestID, W_Req_Tbl[i].Lasting_time, W_Req_Tbl[i].Arrive_time, W_Req_Tbl[i].Finish_time);
//    	sprintf(result_buf, "%-8lld%lld\n", W_Req_Tbl[i].W_Req_Index, W_Req_Tbl[i].Lasting_time);
//    	result_buf[strlen(result_buf)] = '\0';
//      fwrite(result_buf, 1, strlen(result_buf), W_out);
    }
//
//    fclose(W_out);

    for (int i = 0; i < Count_RIO; i++)
    {
    	   if(R_Req_Tbl[policy - 1][i].Lasting_time != 0)
    	   {
    		    R_Request_lasting_time += R_Req_Tbl[policy - 1][i].Lasting_time;
//    		sprintf(result_buf, "%-8lld%10s%10lld%10lld%10lld\n", R_Req_Tbl[i].R_Req_Index, R_Req_Tbl[i].RequestID, R_Req_Tbl[i].Lasting_time, R_Req_Tbl[i].Arrive_time, R_Req_Tbl[i].Finish_time);
    		    sprintf(result_buf, "%-8lld%-s%10lld%10lld%10lld\n", R_Req_Tbl[policy - 1][i].R_Req_Index + 1, R_Req_Tbl[policy - 1][i].RequestID, R_Req_Tbl[policy - 1][i].Lasting_time, R_Req_Tbl[policy - 1][i].Arrive_time, R_Req_Tbl[policy - 1][i].Finish_time);
    		    result_buf[strlen(result_buf)] = '\0';
    		    fwrite(result_buf, 1, strlen(result_buf), R_out);
    	    }

    }

//    sprintf(result_buf, "\n[Total Read Lasting Time]: %lld\n", R_Request_lasting_time);
//    result_buf[strlen(result_buf)] = '\0';
//    fwrite(result_buf, 1, strlen(result_buf), R_out);
//
//    for (int i = 0; i < ec_node; ++i)
//    {
//    	sprintf(result_buf, "Cluster[%d] dup: %lld  LST: %lld   Used: %lld  [Access: %lld]\n", i, Cluster[i]->dup_count, Cluster[i]->Last_Busy_Time, Cluster[i]->pblk_used, Cluster[i]->access_count);
//    	result_buf[strlen(result_buf)] = '\0';
//    	fwrite(result_buf, 1, strlen(result_buf), R_out);
//    }

    fclose(R_out);

}



void Create_Default_Setting(char *** p)
{
    (*p) = (char **)malloc(11 * sizeof(char *));
//    printf("sizeof: %ld\n", sizeof(*p));

    (*p)[0] = (char *)"./a,out";
    (*p)[1] = (char *)"./caftl/";//CAFTL trace
//    (*p)[1] = (char *)"./trace/fiu/homes/";//CAFTL trace

    (*p)[2] = (char *)"1";
    (*p)[3] = (char *)"2";
    (*p)[4] = (char *)"1.txt";
    (*p)[5] = (char *)"6"; //Node_num
    (*p)[6] = (char *)"5000";
    (*p)[7] = (char *)"200000";
    (*p)[8] = (char *)"500000"; /*500000 * 4KB = 2GB*/
    (*p)[9] = (char *)"1"; //policy
    (*p)[10]= (char *)"0"; //degraded

}
