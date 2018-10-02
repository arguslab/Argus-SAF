from nativedroid.analyses.resolver.jni.java_type.primitive import *
from nativedroid.analyses.resolver.jni.java_type.reference import *


def get_type(project, java_type):
    """
    Get JType based on java type.

    :param angr.project.Project project: angr project
    :param str java_type: java type
    :return: return jtype
    :rtype: JType
    """
    if java_type == 'boolean':
        return JBoolean(project)
    elif java_type == 'byte':
        return JByte(project)
    elif java_type == 'char':
        return JChar(project)
    elif java_type == 'short':
        return JShort(project)
    elif java_type == 'int':
        return JInt(project)
    elif java_type == 'long':
        return JLong(project)
    elif java_type == 'float':
        return JFloat(project)
    elif java_type == 'double':
        return JDouble(project)
    elif java_type == 'void':
        return Void(project)
    elif java_type == 'java.lang.Class':
        return JClass(project)
    elif java_type == 'java.lang.String':
        return JString(project)
    elif java_type == 'java.lang.Throwable':
        return JThrowlable(project)
    elif java_type == 'boolean[]':
        return JBooleanArray(project)
    elif java_type == 'byte[]':
        return JByteArray(project)
    elif java_type == 'char[]':
        return JCharArray(project)
    elif java_type == 'short[]':
        return JShortArray(project)
    elif java_type == 'int[]':
        return JIntArray(project)
    elif java_type == 'long[]':
        return JLongArray(project)
    elif java_type == 'float[]':
        return JFloatArray(project)
    elif java_type == 'double[]':
        return JDoubleArray(project)
    elif '[]' in java_type:
        return JObjectArray(project)
    else:
        return JObject(project)


def get_type_size(project, java_type):
    """
    Get JType size based on java type.

    :param angr.project.Project project: angr project
    :param str java_type: java type
    :return: return jtype
    :rtype: int
    """

    arch_bits = project.arch.bits
    ptr_size = arch_bits / 4
    if java_type == 'boolean':
        return ptr_size * 1
    elif java_type == 'byte':
        return ptr_size * 1
    elif java_type == 'char':
        return ptr_size * 2
    elif java_type == 'short':
        return ptr_size * 2
    elif java_type == 'int':
        return ptr_size * 4
    elif java_type == 'long':
        return ptr_size * 8
    elif java_type == 'float':
        return ptr_size * 4
    elif java_type == 'double':
        return ptr_size * 8
    elif java_type == 'void':
        return arch_bits
    elif java_type == 'java.lang.Class':
        return arch_bits
    elif java_type == 'java.lang.String':
        return arch_bits
    elif java_type == 'java.lang.Throwable':
        return arch_bits
    elif java_type == 'boolean[]':
        return arch_bits
    elif java_type == 'byte[]':
        return arch_bits
    elif java_type == 'char[]':
        return arch_bits
    elif java_type == 'short[]':
        return arch_bits
    elif java_type == 'int[]':
        return arch_bits
    elif java_type == 'long[]':
        return arch_bits
    elif java_type == 'float[]':
        return arch_bits
    elif java_type == 'double[]':
        return arch_bits
    elif '[]' in java_type:
        return arch_bits
    else:
        return arch_bits
