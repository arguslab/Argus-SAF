from concurrent import futures
import hashlib
import pkg_resources
import time
import io

from nativedroid.protobuf.server_pb2 import *
from nativedroid.protobuf.server_pb2_grpc import *
from nativedroid.analyses.nativedroid_analysis import *
from nativedroid.jawa.utils import *

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

logger = logging.getLogger('nativedroid.server.NativeDroidServer')

native_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/NativeSourcesAndSinks.txt')
java_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/TaintSourcesAndSinks.txt')


class NativeDroidServer(NativeDroidServerServicer):

    def __init__(self):
        # Map from so_handle to so in memory file
        self.so_map = {}

    def GenSummary(self, request, context):
        """
        Gen summary for give method signature.
        :param GenSummaryRequest request: server_pb2.GenSummaryRequest
        :param context:
        :return: server_pb2.GenSummaryResponse
        """
        so_handle = request.so_handle
        so_file = self.so_map.get(so_handle)
        if not so_file:
            raise Exception("Does not find so file for handle: %s" % so_handle)
        signature = request.method_signature
        jni_method_name = request.jni_func
        method_signature = method_signature_str(signature)
        jni_method_arguments = get_params_from_method_signature(signature, False)
        arguments_str = ",".join(java_type_str(arg, False) for arg in jni_method_arguments)
        taint_analysis_report, safsu_report, total_instructions = gen_summary('testdata/libleak.so', jni_method_name,
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
        sha1 = hashlib.sha1()
        for chunk in request_iterator:
            sha1.update(chunk.buffer)
            f.write(chunk.buffer)
        self.so_map[sha1.hexdigest()] = f
        size = len(f.getvalue())
        return LoadBinaryResponse(so_handle=sha1.hexdigest(), length=size)

    def HasSymbol(self, request, context):
        """
        Check given symbol in the binary file or not.
        :param request:
        :param context:
        :return:
        """
        so_handle = request.so_handle
        so_file = self.so_map.get(so_handle)
        if not so_file:
            raise Exception("Does not find so file for handle: %s" % so_handle)
        return HasSymbolResponse(has_symbol=has_symbol(so_file, request.symbol))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_NativeDroidServerServicer_to_server(NativeDroidServer(), server)
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
