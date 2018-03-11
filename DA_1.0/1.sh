#!/bin/bash
#  running simulators

#echo "Start"
if [[ $# -lt 6 ]]
then 
	echo "Usage: 1.sh [trace_num] [Single file 0|1] [policy num 1|2|3] [node_num] [caftl 1d|2h|3t] [degraded 0|1]"
	exit
else
	#if [ $5 -eq 1 ] 
	#then
    #    	filedir="/Users/dk/Desktop/FIU/homes/"
        	# filedir="/home/dkinasu/Documents/Research/fiu_trace/homes/"
    #    	trace_type="f"
	#else
    #   	filedir="./caftl/"
    #   	trace_type="c"
	#fi
	
	if [ $5 -eq 0 ]
	then
		filedir="/home/dkinasu/Desktop/DA_1.0/caftl/"
	else
		filedir="/home/dkinasu/Desktop/caftl/"
	fi
	
        #filedir="/home/dkinasu/Documents/Research/fordk/1/"
        #filedir="/home/dkinasu/NetBeansProjects/SSD/F_Dedup/F_Dedup/"
        output="1.txt"
        node_num=$4
        max_blk_num=5000
        maxFp_num=200000
        cachesize=500000

    echo $filedir
	make
	#echo "$2"
	if [ $2 -ne 1 ]
	then
		#for i in {0..8}
		#do
			# echo "Policy is: $i"
			# echo $(($1+1))
		./a.out $filedir $1 $2 $output $node_num $max_blk_num $maxFp_num $cachesize $3 $5 $6
		# done
		# grep "policy*" res.dat > $1".dat"
		# mv res.dat ~/.local/share/Trash/files
		# awk 'BEGIN{getline;x=$3;print $2, 1}{$3=$3/x; print $2, $3}' $1".dat" > $1".d"		
		# mv $1".dat" ~/.local/share/Trash/files
		# echo "Merge"
		# ./merge.sh $1 $trace_type $node_num
	else
		# echo "Policy is: $3"
		# ./a.out $filedir $1 $(($1+1)) $output $node_num $max_blk_num $maxFp_num $cachesize $3 $5 > $trace_type"."$1.dat
		./a.out $filedir $1 $(($1+1)) $output $node_num $max_blk_num $maxFp_num $cachesize $3 $5 $6
	fi

fi
