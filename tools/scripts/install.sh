#!/bin/bash
# install jnsaf and nativedroid
source `which virtualenvwrapper.sh`

install_nativedroid()
{
    workon nativedroid
    cd nativedroid
    protoc nativedroid/protobuf/java_signatures.proto --python_out=.
    protoc nativedroid/protobuf/taint_result.proto --python_out=.
    protoc nativedroid/protobuf/summary.proto --python_out=.
    python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. nativedroid/protobuf/jnsaf_grpc.proto
    python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. nativedroid/protobuf/nativedroid_grpc.proto
    python setup.py install
    cd ..
}

install_jnsaf()
{
    tools/bin/sbt clean assembly
}

MODE='ALL'
if [[ -n "$1" ]]; then
    MODE=$1
fi

if [[ "$MODE" == "ALL" ]]; then
    install_jnsaf
    install_nativedroid
elif [[ "$MODE" == 'jnsaf' ]]; then
    install_jnsaf
else
    install_nativedroid
fi