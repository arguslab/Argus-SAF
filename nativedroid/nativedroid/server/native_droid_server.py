from concurrent import futures
import hashlib
import pkg_resources
import time
import io
import os

from nativedroid.protobuf.server_pb2 import *
from nativedroid.protobuf.server_pb2_grpc import *
from nativedroid.analyses.nativedroid_analysis import *
from nativedroid.jawa.utils import *

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

logger = logging.getLogger('nativedroid.server.NativeDroidServer')

native_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/NativeSourcesAndSinks.txt')
java_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/TaintSourcesAndSinks.txt')


class NativeDroidServer(NativeDroidServerServicer):

    def __init__(self, binary_path):
        self._binary_path = binary_path
        self._loadedsos = set()

    def GenSummary(self, request, context):
        """
        Gen summary for give method signature.
        :param GenSummaryRequest request: server_pb2.GenSummaryRequest
        :param context:
        :return: server_pb2.GenSummaryResponse
        """
        so_path = request.so_handle
        signature = request.method_signature
        jni_method_name = request.jni_func
        method_signature = method_signature_str(signature)
        jni_method_arguments = get_params_from_method_signature(signature, False)
        arguments_str = ",".join(java_type_str(arg, False) for arg in jni_method_arguments)
        taint_analysis_report, safsu_report, total_instructions = gen_summary(so_path, jni_method_name,
                                                                              method_signature, arguments_str,
                                                                              native_ss_file, java_ss_file)
        response = GenSummaryResponse(taint=taint_analysis_report, summary=safsu_report,
                                      analyzed_instructions=total_instructions)
        return response

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

        if so_path not in self._loadedsos:
            try:
                os.makedirs(self._binary_path)
            except OSError:
                if not os.path.isdir(self._binary_path):
                    raise
            with open(so_path, 'wb') as out:
                out.write(f.getvalue())
            self._loadedsos.add(so_path)
        size = len(f.getvalue())
        return LoadBinaryResponse(so_handle=so_path, length=size)

    def HasSymbol(self, request, context):
        """
        Check given symbol in the binary file or not.
        :param request:
        :param context:
        :return:
        """
        so_path = request.so_handle
        return HasSymbolResponse(has_symbol=has_symbol(so_path, request.symbol))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_NativeDroidServerServicer_to_server(NativeDroidServer('/tmp/binaries/'), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    logger.info('Server started.')
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)
    logger.info('Server stopped.')


if __name__ == '__main__':
    serve()
