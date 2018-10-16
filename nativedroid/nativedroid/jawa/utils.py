from nativedroid.protobuf.java_signatures_pb2 import *

__author__ = "Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


def java_package_str(java_package_pb, delimiter):
    """
    Return full string of a java package proto.
    :param JavaPackage java_package_pb: java_signatures_pb2.JavaPackage
    :param str delimiter:
    :return: str
    """
    pkg_str = java_package_pb.name
    tmp = java_package_pb
    while tmp.HasField('parent'):
        tmp = tmp.parent
        pkg_str = tmp.name + delimiter + pkg_str
    return pkg_str


def primitive_type_str(primitive_type_pb, is_signature):
    """
    Return full string of a primitive type proto.
    :param PrimitiveType primitive_type_pb: java_signatures_pb2.PrimitiveType
    :param bool is_signature: normal form int, signature form I
    :return: str
    """
    if primitive_type_pb.type == PrimitiveType.BYTE:
        if is_signature:
            return 'B'
        else:
            return 'byte'
    elif primitive_type_pb.type == PrimitiveType.SHORT:
        if is_signature:
            return 'S'
        else:
            return 'short'
    elif primitive_type_pb.type == PrimitiveType.INT:
        if is_signature:
            return 'I'
        else:
            return 'int'
    elif primitive_type_pb.type == PrimitiveType.FLOAT:
        if is_signature:
            return 'F'
        else:
            return 'float'
    elif primitive_type_pb.type == PrimitiveType.BOOLEAN:
        if is_signature:
            return 'Z'
        else:
            return 'boolean'
    elif primitive_type_pb.type == PrimitiveType.CHAR:
        if is_signature:
            return 'C'
        else:
            return 'char'
    elif primitive_type_pb.type == PrimitiveType.LONG:
        if is_signature:
            return 'L'
        else:
            return 'long'
    elif primitive_type_pb.type == PrimitiveType.DOUBLE:
        if is_signature:
            return 'D'
        else:
            return 'double'


def class_type_str(class_type_pb, is_signature):
    """
    Return full string of a class type proto.
    :param ClassType class_type_pb: java_signatures_pb2.ClassType
    :param bool is_signature: normal form java.lang.Object, signature form Ljava/lang/Object;
    :return: str
    """
    type_str = class_type_pb.name
    if is_signature:
        delimiter = '/'
    else:
        delimiter = '.'
    if class_type_pb.HasField('package'):
        type_str = java_package_str(class_type_pb.package, delimiter) + delimiter + type_str
    if class_type_pb.unknown:
        type_str += '?'
    if is_signature:
        type_str = 'L' + type_str + ';'
    return type_str


def java_type_str(java_type_pb, is_signature):
    """
    Return full string of a java type proto.
    :param JavaType java_type_pb: java_signatures_pb2.JavaType
    :param bool is_signature: normal form java.lang.Object[], signature form [Ljava/lang/Object;
    :return: str
    """
    if java_type_pb.HasField('primitive_type'):
        type_str = primitive_type_str(java_type_pb.primitive_type, is_signature)
    else:
        type_str = class_type_str(java_type_pb.class_type, is_signature)
    dimension = java_type_pb.dimension
    while dimension > 0:
        if is_signature:
            type_str = '[' + type_str
        else:
            type_str += '[]'
        dimension -= 1
    return type_str


def method_proto_str(method_proto_pb):
    """
    Return full string of a method proto proto.
    :param MethodProto method_proto_pb: java_signatures_pb2.MethodProto
    :return: str
    """
    proto = '('
    for param in method_proto_pb.param_types:
        proto += java_type_str(param, True)
    proto += ')'
    if method_proto_pb.HasField('return_java_type'):
        proto += java_type_str(method_proto_pb.return_java_type, True)
    else:
        proto += 'V'
    return proto


def method_signature_str(method_signature_pb):
    """
    Return full string of a method signature proto.
    :param MethodSignature method_signature_pb: java_signatures_pb2.MethodSignature
    :return: str
    """
    owner_str = java_type_str(method_signature_pb.owner, is_signature=True)
    proto_str = method_proto_str(method_signature_pb.proto)
    return owner_str + '.' + method_signature_pb.name + ':' + proto_str


def get_params_from_method_signature(method_signature_pb, is_static):
    """
    Get parameter types from method signature.
    :param MethodSignature method_signature_pb: java_signatures_pb2.MethodSignature
    :param bool is_static: is static method
    :return: list of JavaType
    """
    param_types = []
    if not is_static:
        param_types.append(method_signature_pb.owner)
    param_types.extend(method_signature_pb.proto.param_types)
    return param_types
