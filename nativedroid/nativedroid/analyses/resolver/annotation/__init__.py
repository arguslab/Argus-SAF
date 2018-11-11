from nativedroid.analyses.resolver.annotation.java_type_annotations import *
from nativedroid.analyses.resolver.annotation.jclass_annotation import *
from nativedroid.analyses.resolver.annotation.jfield_id_annotation import *
from nativedroid.analyses.resolver.annotation.jmethod_id_annotation import *
from nativedroid.analyses.resolver.annotation.taint_position_annotation import *


def construct_annotation(jni_type, obj_source):
    """
    Get annotation based on jni type.

    :param str jni_type: jni type
    :param obj_source:
    :return: return annotation
    :rtype: JavaTypeAnnotation
    """
    if jni_type == 'boolean':
        return JbooleanAnnotation(obj_source)
    elif jni_type == 'byte':
        return JbyteAnnotation(obj_source)
    elif jni_type == 'char':
        return JcharAnnotation(obj_source)
    elif jni_type == 'short':
        return JshortAnnotation(obj_source)
    elif jni_type == 'int':
        return JintAnnotation(obj_source)
    elif jni_type == 'long':
        return JlongAnnotation(obj_source)
    elif jni_type == 'float':
        return JfloatAnnotation(obj_source)
    elif jni_type == 'double':
        return JdoubleAnnotation(obj_source)
    elif jni_type == 'java/lang/String':
        return JstringAnnotation(obj_source, None)
    elif jni_type == 'boolean[]':
        return JbooleanArrayAnnotation(obj_source)
    elif jni_type == 'byte[]':
        return JbyteArrayAnnotation(obj_source)
    elif jni_type == 'char[]':
        return JcharArrayAnnotation(obj_source)
    elif jni_type == 'short[]':
        return JshortArrayAnnotation(obj_source)
    elif jni_type == 'int[]':
        return JintArrayAnnotation(obj_source)
    elif jni_type == 'long[]':
        return JlongArrayAnnotation(obj_source)
    elif jni_type == 'float[]':
        return JfloatArrayAnnotation(obj_source)
    elif jni_type == 'double[]':
        return JdoubleArrayAnnotation(obj_source)
    elif '[]' in jni_type:
        return JobjectArrayAnnotation(obj_source, jni_type)
    else:
        return JobjectAnnotation(obj_source, jni_type, list())
