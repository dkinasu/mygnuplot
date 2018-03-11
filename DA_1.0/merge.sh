#!/bin/bash
#echo "Ploting"

if [[ $# -lt 3 ]]
then 
	echo "Usage: merge.sh [trace_num] [trace_type] [node_num]"
	exit
fi

o_fn=$2"."$1"."$3
echo $o_fn




var=$(ls *.res 2> /dev/null)

for file in ${var[@]}
do
	if [ -e $file ]
	then
		# echo $file
		mv $file ./fig/
	fi
done

cd ./fig/
pwd

if [ ! -d $o_fn ]
then
	mkdir $o_fn
fi


var=$(ls *.dat 2> /dev/null)
for file in ${var[@]}
do
	if [ -f $file ]
	then
		# echo $file
		mv *$file ~/.local/share/Trash/files
	fi
done


# if [ ! -d data ]
# then
# 	echo "File data does not exist! Making it!"
# 	mkdir data
# fi



# array=(Read)
array=(Read)
# array=(Write)
part=".res"

for i in ${array[@]}
do
	out=$o_fn"."$i".ori"

	for j in {0..8}
	do
		name=$i$j$part
		tmp=$i"."$j".tmp"
		# echo $name

		if [ -e $name ]
		then
			if [ "$j" -eq 0 ]
			then 
				# awk '{print $2" "$3}' $name
				awk '{print $1" "$2" "$3}' $name > "$tmp"
			elif [ -e $name ]
			then
				# awk '{print $3}' $name
				awk '{print $3}' $name > "$tmp"
			fi
			mv $name ~/.local/share/Trash/files
		fi 		
		# cat $i.dat		
	done
	
	res=$(ls *.tmp 2> /dev/null | wc -l)

	if [ $res -ne 0 ] 
	then
		echo "Forming the .dat"
		paste -d " " *.tmp > $out
		awk '{ave=(($3+$4+$5+$6+$7+$8+$9+$10)/8); ba=($3/ave*100); ra=($4/ave*100); da=($5/ave*100); dan=($6/ave*100); dab1=($7/ave*100); dab2=($8/ave*100); dab3=($9/ave*100); pb=($10/ave*100); printf "%-5d %6d %9.3f %9.3f %9.3f %9.3f %9.3f %9.3f %9.3f %9.3f\n", $1, $2, ba, ra, da, dan, dab1, dab2, dab3, pb}' $out > $out".nor"
		#gnuplot -c plot.sh $o_fn"."$i
		mv $out $out".nor" ./$o_fn
	fi

	#xdg-open $o_fn"."$i".eps"

done


var=$(ls *.tmp 2> /dev/null)

for file in ${var[@]}
do
	if [ -f $file ]
	then
		echo $file
		mv *$file ~/.local/share/Trash/files
	fi
done


#rm *.tmp