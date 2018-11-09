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

java -jar $BASEDIR/../../target/scala-2.12/argus-saf-3.1.4-SNAPSHOT-assembly.jar submitter $BASEDIR/../../benchmarks/NativeFlowBench localhost 55001

kill -KILL $nativedroid_pid
kill -KILL $jnsaf_pid