#!/bin/bash
#  running simulators

if [ $# -lt 3 ]
then 
	echo "Usage: run.sh [node_num:12] [degraded 0|1|all:2] [trace:u1|h2|t3|all:4]"
	exit
fi

echo $1 $2

if [ $3 -eq 4 ]
then
	trace=(1 2 3) 
else
	trace=$3	
fi

if [ $2 -eq 2 ]
then
	degraded=(0 1) 
else
	degraded=$2	
fi


for d in ${degraded[@]}
do
	for i in ${trace[@]}
	do		
		if [ $i -eq 1 ]
		then
		for j in {4..5}
		do
			echo "CAFTL[desktop-ubuntu]-"$j "Nodes:"$1 "Degraded:"$d
			time ./1.sh $j 1 4 $1 $i $d
			done
		elif [ $i -eq 2 ]
		then
			for j in {9..18} 20 21
			do
				echo "CAFTL[hivetpch]-"$j "Nodes:"$1 "Degraded:"$d
				time ./1.sh $j 1 4 $1 $i $d
			done
		elif [ $i -eq 3 ]
		then
			for j in {1..2}
			do
				echo "CAFTL[tpcc]-"$j "Nodes:"$1 "Degraded:"$d
				time ./1.sh $j 1 4 $1 $i $d
			done

		fi
	done
done
 