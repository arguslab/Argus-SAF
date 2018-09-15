import unittest
from nativedroid.jawa.utils import *
from nativedroid.protobuf.java_signatures_pb2 import *


class JawaUtilsTest(unittest.TestCase):
    def test_java_package_str(self):
        package_pb = JavaPackage(name='com')
        package_pb = JavaPackage(name='test', parent=package_pb)
        self.assertEqual('com.test', java_package_str(package_pb, '.'))

    def test_primitive_type_str(self):
        primitive_type_pb = PrimitiveType(type=PrimitiveType.INT)
        self.assertEqual(primitive_type_str(primitive_type_pb, True), 'I')
        self.assertEqual(primitive_type_str(primitive_type_pb, False), 'int')

    def test_class_type_str(self):
        package_pb = JavaPackage(name='com')
        package_pb = JavaPackage(name='test', parent=package_pb)
        class_type_pb = ClassType(package=package_pb, name='MyTest', unknown=True)
        self.assertEqual(class_type_str(class_type_pb, True), 'Lcom/test/MyTest?;')
        self.assertEqual(class_type_str(class_type_pb, False), 'com.test.MyTest?')

    def test_java_type_str(self):
        primitive_type_pb = PrimitiveType(type=PrimitiveType.DOUBLE)
        java_type = JavaType(primitive_type=primitive_type_pb, dimension=2)
        self.assertEqual(java_type_str(java_type, True), '[[D')
        self.assertEqual(java_type_str(java_type, False), 'double[][]')
        package_pb = JavaPackage(name='com')
        package_pb = JavaPackage(name='test', parent=package_pb)
        class_type_pb = ClassType(package=package_pb, name='MyTest', unknown=True)
        java_type_pb = JavaType(class_type=class_type_pb, dimension=2)
        self.assertEqual(java_type_str(java_type_pb, True), '[[Lcom/test/MyTest?;')
        self.assertEqual(java_type_str(java_type_pb, False), 'com.test.MyTest?[][]')

    def test_method_signature_str(self):
        package_pb = JavaPackage(name='com')
        package_pb = JavaPackage(name='test', parent=package_pb)
        class_type_pb = ClassType(package=package_pb, name='MyTest', unknown=False)
        java_type_pb = JavaType(class_type=class_type_pb)
        proto = MethodProto(param_types=[JavaType(primitive_type=PrimitiveType(type=PrimitiveType.INT))],
                            return_void_type=VoidType())
        method_signature_pb = MethodSignature(owner=java_type_pb, name='foo', proto=proto)
        self.assertEqual(method_signature_str(method_signature_pb), 'Lcom/test/MyTest;.foo:(I)V')

    def test_get_params_from_method_signature(self):
        package_pb = JavaPackage(name='com')
        package_pb = JavaPackage(name='test', parent=package_pb)
        class_type_pb = ClassType(package=package_pb, name='MyTest', unknown=False)
        java_type_pb = JavaType(class_type=class_type_pb)
        proto = MethodProto(param_types=[JavaType(primitive_type=PrimitiveType(type=PrimitiveType.INT))],
                            return_void_type=VoidType())
        method_signature_pb = MethodSignature(owner=java_type_pb, name='foo', proto=proto)
        param_types = get_params_from_method_signature(method_signature_pb, False)
        self.assertEqual(len(param_types), 2)
        self.assertEqual(java_type_str(param_types[1], False), 'int')


if __name__ == '__main__':
    unittest.main()
