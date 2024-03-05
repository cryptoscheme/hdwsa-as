#!/bin/bash

file=benchmark.txt
directory=datafile

echo "=================== Part 3 extracting data          ==================="

if [ ! -d "$directory" ]; then
  echo '3.creating datafile directory'
  mkdir $directory
fi

# level 1
benchmarkFuncName[0]=BenchmarkSchemeL1SSign
benchmarkFuncName[1]=BenchmarkSchemeL1SVerify
benchmarkFuncName[2]=BenchmarkLevel1Aggregation
benchmarkFuncName[3]=BenchmarkLevel1AggVerify


echo ${#benchmarkFuncName[@]}
for((i=0;i<${#benchmarkFuncName[@]};i++));
do
   echo ${benchmarkFuncName[$i]}
   awk '$1 ~ /^'${benchmarkFuncName[$i]}'$/ {print $1,$3}' $file > ./$directory/${benchmarkFuncName[$i]}.txt
   cat  ./$directory/${benchmarkFuncName[$i]}.txt
   echo 'extracting' ${benchmarkFuncName[$i]}' data done'
done

for filename in ./$directory/*
do
  echo $filename
  cat $filename | awk '{sum+=$2} END {print "#times = ", NR, ", Average = ", sum/NR, " ns"}'
done

echo "=================== Part 3 extracting data done         ===============" 
