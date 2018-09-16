import unittest

from native_droid_server import *

CHUNK_SIZE = 1024 * 1024  # 1MB


def get_file_chunks(filename):
    with open(filename, 'rb') as f:
        while True:
            piece = f.read(CHUNK_SIZE)
            if len(piece) == 0:
                return
            yield LoadBinaryRequest(buffer=piece)


class NativeDroidServerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
        add_NativeDroidServerServicer_to_server(NativeDroidServer('/tmp/binaries/'), cls.server)
        cls.server.add_insecure_port('[::]:50001')
        cls.server.start()
        logger.info('Server started.')
        channel = grpc.insecure_channel('localhost:50001')
        cls.stub = NativeDroidServerStub(channel)
        file_path = 'testdata/libleak.so'
        chunks_generator = get_file_chunks(file_path)
        cls._lb_response = cls.stub.LoadBinary(chunks_generator)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop(0)
        logger.info('Server stopped.')
        cls.server = None
        cls.stub = None
        path = cls._lb_response.so_handle
        if os.path.exists(path):
            os.remove(path)
        cls._lb_response = None

    def testLoadBinary(self):
        self.assertEqual(self._lb_response.length, os.path.getsize('testdata/libleak.so'))

    def testHasSymbol(self):
        response = self.stub.HasSymbol(HasSymbolRequest(so_handle=self._lb_response.so_handle,
                                                        symbol='Java_org_arguslab_native_1leak_MainActivity_send'))
        self.assertTrue(response.has_symbol)

    def testGenSummary(self):
        package_pb = JavaPackage(name='org')
        package_pb = JavaPackage(name='arguslab', parent=package_pb)
        package_pb = JavaPackage(name='native_leak', parent=package_pb)
        class_type_pb = ClassType(package=package_pb, name='MainActivity', unknown=False)
        java_type_pb = JavaType(class_type=class_type_pb)
        package_pb = JavaPackage(name='java')
        package_pb = JavaPackage(name='lang', parent=package_pb)
        class_type_pb = ClassType(package=package_pb, name='String', unknown=False)
        proto = MethodProto(param_types=[JavaType(class_type=class_type_pb)],
                            return_void_type=VoidType())
        method_signature_pb = MethodSignature(owner=java_type_pb, name='send', proto=proto)
        request = GenSummaryRequest(so_handle=self._lb_response.so_handle,
                                    jni_func='Java_org_arguslab_native_1leak_MainActivity_send',
                                    method_signature=method_signature_pb)
        response = self.stub.GenSummary(request)
        self.assertEqual('Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V -> _SINK_ 1',
                         response.taint)


if __name__ == '__main__':
    unittest.main()
