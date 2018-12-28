#!/bin/bash
# Benchmark cli
source `which virtualenvwrapper.sh`

workon nativedroid
BASEDIR=$(dirname "$0")
python $BASEDIR/start_nativedroid_server.py /tmp/binaries/ localhost 50051 localhost 55001 /Users/fengguow/.amandroid_stash/amandroid/taintAnalysis/sourceAndSinks/NativeSourcesAndSinks.txt /Users/fengguow/.amandroid_stash/amandroid/taintAnalysis/sourceAndSinks/TaintSourcesAndSinks.txt &
nativedroid_pid=$!

java -jar $BASEDIR/../../target/scala-2.12/argus-saf-3.1.4-SNAPSHOT-assembly.jar jnsaf /tmp/apks/ 55001 localhost 50051 &
jnsaf_pid=$!

sleep 5

droid_bench_submitter()
{
    java -jar $BASEDIR/../../target/scala-2.12/argus-saf-3.1.4-SNAPSHOT-assembly.jar benchmark -a COMPONENT_BASED $BASEDIR/../../benchmarks/DroidBench localhost 55001 $BASEDIR/../../benchmarks/expected_droid_bench.txt
}

icc_bench_submitter()
{
    java -jar $BASEDIR/../../target/scala-2.12/argus-saf-3.1.4-SNAPSHOT-assembly.jar benchmark -a COMPONENT_BASED $BASEDIR/../../benchmarks/ICCBench localhost 55001 $BASEDIR/../../benchmarks/expected_icc_bench.txt
}

native_flow_bench_submitter()
{
    java -jar $BASEDIR/../../target/scala-2.12/argus-saf-3.1.4-SNAPSHOT-assembly.jar benchmark -a BOTTOM_UP $BASEDIR/../../benchmarks/NativeFlowBench localhost 55001 $BASEDIR/../../benchmarks/expected_nativeflow_bench.txt
}

MODE='ALL'
if [[ -n "$1" ]]; then
    MODE=$1
fi

if [[ "$MODE" == "ALL" ]]; then
    droid_bench_submitter
    icc_bench_submitter
    native_flow_bench_submitter
elif [[ "$MODE" == 'droidbench' ]]; then
    droid_bench_submitter
elif [[ "$MODE" == 'iccbench' ]]; then
    icc_bench_submitter
else
    native_flow_bench_submitter
fi

kill -KILL $nativedroid_pid
kill -KILL $jnsaf_pid