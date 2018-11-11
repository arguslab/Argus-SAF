#!/bin/bash
# install jnsaf and nativedroid
source `which virtualenvwrapper.sh`

workon nativedroid
cd nativedroid
protoc nativedroid/protobuf/java_signatures.proto --python_out=.
protoc nativedroid/protobuf/taint_result.proto --python_out=.
protoc nativedroid/protobuf/summary.proto --python_out=.
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. nativedroid/protobuf/jnsaf_grpc.proto
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. nativedroid/protobuf/nativedroid_grpc.proto
python setup.py install
cd ..
tools/bin/sbt clean assembly