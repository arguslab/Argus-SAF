#
# Makefile to call protocol buffer compiler for Python
#

CC :=protoc

JAVA_SIGNATURES_SRC :=nativedroid/protobuf/java_signatures.proto
JAVA_SIGNATURES_NATIVEDROID_OUT :=nativedroid/protobuf/java_signatures_pb2.py

SERVER_SRC :=nativedroid/protobuf/server.proto
SERVER_NATIVEDROID_OUT :=nativedroid/protobuf/server_pb2.py

all: $(JAVA_SIGNATURES_NATIVEDROID_OUT) ${SERVER_NATIVEDROID_OUT}

$(JAVA_SIGNATURES_NATIVEDROID_OUT): $(JAVA_SIGNATURES_SRC)
	$(CC) $(JAVA_SIGNATURES_SRC) --python_out=.

$(SERVER_NATIVEDROID_OUT): $(SERVER_SRC)
	python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. $(SERVER_SRC)

clean:
	$(RM) $(JAVA_SIGNATURES_NATIVEDROID_OUT)
	$(RM) $(SERVER_NATIVEDROID_OUT)