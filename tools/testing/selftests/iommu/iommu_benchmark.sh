#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES.

sg_size_kb=("4" "64" "512" "1024" "4096" "16318" "65536")
single_size_kb=("4" "64" "128" "512" "1024" "2048" "4096")
threads=("1" "5" "10" "20" "40" "80" "160")
iters=10000
TEST_MAP=0
TEST_MAP_SG=1
TEST_ALLOC=2
BENCHMARK_DIR=/sys/kernel/debug/iommu/benchmark/

is_number=`echo -n $1 | sed "s/[0-9]*//g"`
if [ "$#" = "1" ] && [ "$is_number" = "" ] ; then
    iters=$1
fi

print_header() {
echo "----------------------------------------------------------------------------"
echo "         $1"
echo "----------------------------------------------------------------------------"
}

# Setup Tests
echo $iters > $BENCHMARK_DIR/iters
print_header "IOMMU MICRO_BENCHMARK RESULTS"

print_header "MAP SG"
echo $TEST_MAP_SG > $BENCHMARK_DIR/test_id
for i in "${sg_size_kb[@]}"
do
    echo $i > $BENCHMARK_DIR/size_kb
    cat $BENCHMARK_DIR/start
done

print_header "MAP"
echo $TEST_MAP > $BENCHMARK_DIR/test_id
for i in "${single_size_kb[@]}"
do
    echo $i > $BENCHMARK_DIR/size_kb
    cat $BENCHMARK_DIR/start
done

print_header "ALLOC"
echo $TEST_ALLOC > $BENCHMARK_DIR/test_id
for i in "${single_size_kb[@]}"
do
    echo $i > $BENCHMARK_DIR/size_kb
    cat $BENCHMARK_DIR/start
done

print_header "MAP SINGLE (threads)"
echo $TEST_MAP > $BENCHMARK_DIR/test_id
echo 4 > $BENCHMARK_DIR/size_kb
for i in "${threads[@]}"
do
    echo $i > $BENCHMARK_DIR/threads
    cat $BENCHMARK_DIR/start
done

# Test cleanup
echo $TEST_MAP_SG > $BENCHMARK_DIR/test_id
