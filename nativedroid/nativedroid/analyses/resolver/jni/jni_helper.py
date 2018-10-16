import re

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

jni_types = {
    'boolean': 'jboolean',
    'byte': 'jbyte',
    'char': 'jchar',
    'short': 'jshort',
    'int': 'jint',
    'long': 'jlong',
    'float': 'jfloat',
    'double': 'jdouble',
    'string': 'jstring',
    'object': 'jobject',
    'void': 'void'
}

jni_signatures = {
    'B': 'byte',
    'C': 'char',
    'D': 'double',
    'F': 'float',
    'I': 'int',
    'S': 'short',
    'J': 'long',
    'Z': 'boolean',
    'V': 'void',
    '[B': 'byte[]',
    '[C': 'char[]',
    '[D': 'double[]',
    '[F': 'float[]',
    '[I': 'int[]',
    '[S': 'short[]',
    '[J': 'long[]',
    '[Z': 'boolean[]'
}


def count_arg_nums(method_signature):
    """
    Based on the method signature(jni format) to count the arguments number.
    :param method_signature: method signature(jni format)
    :return: arguments number
    """
    arg_signature = re.findall(re.compile(r'\((.*?)\)'), method_signature)[0]
    pattern = re.compile(r'(L.*?;)|([BCDFISJZ])|(\[[BCDFISJZ])')
    args = pattern.findall(arg_signature)
    args_num = len(args)
    return args_num
    # print(len(args))
    # print(args)


def get_java_return_type(method_signature):
    """
    Based on the method signature(jni format) to get the return type(java format) of method.
    :param method_signature: method signature(jni format)
    :return: return type(java format)
    """
    jni_ret_type = method_signature.split(')')[-1]
    if jni_ret_type.endswith(';'):
        res = re.split(r'[L;]', jni_ret_type)
        java_ret_type = res[1].replace('/', '.')
    else:
        java_ret_type = jni_signatures[jni_ret_type]
    # print java_ret_type
    return java_ret_type


def get_jni_return_type(method_signature):
    """
    Based on the method signature(jni format) to get the return type of method.
    :param method_signature: method signature(jni format)
    :return: return type(jni format)
    """
    jni_ret_type = method_signature.split(')')[-1]
    if jni_ret_type.endswith(';'):
        res = re.split(r'[L;]', jni_ret_type)[1]
    else:
        res = jni_signatures[jni_ret_type]
    # print java_ret_type
    return res


def get_method_full_signature(class_name, method_name, method_signature):
    """
    Based on the class name, method name and method signature to get the full method signature
    :param class_name: class name
    :param method_name: method name
    :param method_signature: method signature
    :return: method full signature
    """
    if class_name:
        class_name = 'L' + class_name + ';'
        method_full_signature = class_name + '.' + method_name + ':' + method_signature
        # print(method_full_signature)
        return method_full_signature
    else:
        return None


def get_jni_type(java_type):
    """
    Based on the java type to get the jni type
    :param java_type: java type
    :return: jni type
    """
    postfix = ''
    jtype = java_type.lower()
    if jtype.endswith('[]'):
        postfix = 'Array'
        jtype = jtype[:-2]
    if jtype not in jni_types:
        tp = 'jobject'
    else:
        tp = jni_types[jtype] + postfix

    return tp


def get_args_type(java_args):
    """
    Get the JNI arguments type
    :param java_args: java arguments
    :return: JNI argument type
    """
    if len(java_args) == 0:
        return 'JNIEnv* env, jobject thiz'
    jargs = java_args.lower()
    args = jargs.split(', ')
    # print 'arg count:', len(args)
    full_arg = 'JNIEnv* env, jobject thiz, '
    i = 1
    for java_arg in args:
        java_type = java_arg.split(' ')[0]
        full_arg += get_jni_type(java_type)
        full_arg += ' arg'
        full_arg += str(i)
        full_arg += ', '
        i += 1

    return full_arg[:-2]
