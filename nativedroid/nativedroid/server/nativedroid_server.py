import hashlib
import io
import os
import time

import pkg_resources
from concurrent import futures

from nativedroid.analyses.nativedroid_analysis import *
from nativedroid.jawa.utils import *
from nativedroid.protobuf.nativedroid_grpc_pb2 import *
from nativedroid.protobuf.nativedroid_grpc_pb2_grpc import *
from nativedroid.protobuf.jnsaf_grpc_pb2_grpc import *

__author__ = "Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

logger = logging.getLogger('nativedroid.server.NativeDroidServer')


class JNSafClient(JNSafStub):
    def __init__(self, channel, apk_digest, component_name, depth):
        super(JNSafClient, self).__init__(channel)
        self.apk_digest = apk_digest
        self.component_name = component_name
        self.depth = depth


class NativeDroidServer(NativeDroidServicer):

    def __init__(self, binary_path, jnsaf_address, jnsaf_port, native_ss_file, java_ss_file):
        self._binary_path = binary_path
        self._jnsaf_address = jnsaf_address
        self._jnsaf_port = jnsaf_port
        self._loaded_sos = set()
        self._native_ss_file = native_ss_file
        self._java_ss_file = java_ss_file
        self._call_jnsaf = True  # TODO(fengguow) Add flag for it

    @classmethod
    def from_python_package(cls, jnsaf_address, jnsaf_port, binary_path):
        native_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/NativeSourcesAndSinks.txt')
        java_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/TaintSourcesAndSinks.txt')
        return cls(binary_path, jnsaf_address, jnsaf_port, native_ss_file, java_ss_file)

    @classmethod
    def from_filesystem(cls, binary_path, jnsaf_address, jnsaf_port, native_ss_file, java_ss_file):
        return cls(binary_path, jnsaf_address, jnsaf_port, native_ss_file, java_ss_file)

    def GenSummary(self, request, context):
        """
        Gen summary for give method signature.
        :param GenSummaryRequest request: server_pb2.GenSummaryRequest
        :param context:
        :return: server_pb2.GenSummaryResponse
        """
        logger.info('Server GenSummary: %s', request)
        depth = request.depth
        if depth is 0:
            return GenSummaryResponse()
        jnsaf_client = None
        if self._call_jnsaf:
            jnsaf_client = JNSafClient(grpc.insecure_channel('%s:%s' % (self._jnsaf_address, self._jnsaf_port)),
                                       request.apk_digest, request.component_name, depth - 1)
        so_path = self._binary_path + request.so_digest
        signature = request.method_signature
        name_or_address = request.jni_func if request.HasField('jni_func') else request.addr
        method_signature = method_signature_str(signature)
        jni_method_arguments = get_params_from_method_signature(signature, False)
        arguments_str = ",".join(java_type_str(arg, False) for arg in jni_method_arguments)
        taint_analysis_report, safsu_report, total_instructions = gen_summary(
            jnsaf_client, so_path, name_or_address, method_signature, arguments_str,
            self._native_ss_file, self._java_ss_file)
        return GenSummaryResponse(taint=taint_analysis_report, summary=safsu_report,
                                  analyzed_instructions=total_instructions)

    def AnalyseNativeActivity(self, request, context):
        """
        Analysis given native activity.
        :param AnalyseNativeActivityRequest request: server_pb2.AnalyseNativeActivityRequest
        :param context:
        :return: server_pb2.AnalyseNativeActivityResponse
        """
        logger.info('Server AnalyseNativeActivity: %s', request)
        jnsaf_client = None
        if self._call_jnsaf:
            jnsaf_client = JNSafClient(grpc.insecure_channel('%s:%s' % (self._jnsaf_address, self._jnsaf_port)),
                                       request.apk_digest, request.component_name, 3)
        so_path = self._binary_path + request.so_digest
        custom_entry = request.custom_entry
        total_instructions = native_activity_analysis(
            jnsaf_client, so_path, custom_entry, self._native_ss_file, self._java_ss_file)
        return AnalyseNativeActivityResponse(total_instructions=total_instructions)

    def GetDynamicRegisterMap(self, request, context):
        """
        Get dynamically registered methods
        :param GetDynamicRegisterRequest request: server_pb2.GetDynamicRegisterRequest
        :param context:
        :return: server_pb2.GetDynamicRegisterResponse
        """
        logger.info('Server GetDynamicRegisterMap: %s', request)
        so_path = self._binary_path + request.so_digest
        dynamic_methods = get_dynamic_register_methods(so_path, None)
        method_map = []
        for name, addr in dynamic_methods.items():
            method_map.append(MethodMap(method_name=name, func_addr=addr))
        return GetDynamicRegisterMapResponse(method_map=method_map)

    def LoadBinary(self, request_iterator, context):
        """
        Load given binary file.
        :param request_iterator:
        :param context:
        :return: server_pb2.LoadBinaryResponse
        """
        f = io.BytesIO()
        sha256 = hashlib.sha256()
        for chunk in request_iterator:
            sha256.update(chunk.buffer)
            f.write(chunk.buffer)
        so_digest = sha256.hexdigest()
        so_path = self._binary_path + so_digest

        if so_path not in self._loaded_sos:
            try:
                os.makedirs(self._binary_path)
            except OSError:
                if not os.path.isdir(self._binary_path):
                    raise
            with open(so_path, 'wb') as out:
                out.write(f.getvalue())
            self._loaded_sos.add(so_path)
        size = len(f.getvalue())
        return LoadBinaryResponse(so_digest=so_digest, length=size)

    def HasSymbol(self, request, context):
        """
        Check given symbol in the binary file or not.
        :param request:
        :param context:
        :return:
        """
        logger.info('Server HasSymbol: %s', request)
        so_path = self._binary_path + request.so_digest
        return HasSymbolResponse(has_symbol=has_symbol(so_path, request.symbol))


def serve(binary_path, address, port, jnsaf_address, jnsaf_port, native_ss_file, java_ss_file):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_NativeDroidServicer_to_server(
        NativeDroidServer.from_filesystem(binary_path, jnsaf_address, jnsaf_port, native_ss_file, java_ss_file), server)
    server.add_insecure_port('%s:%s' % (address, port))
    server.start()
    logger.info('Server started.')
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)
    logger.info('Server stopped.')
