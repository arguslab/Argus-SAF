from nativedroid.analyses.resolver.jni.jtype import JType

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class JObject(JType):
    def __init__(self, project, name='jobject'):
        super(JObject, self).__init__(project, name)


class JClass(JObject):
    def __init__(self, project):
        super(JClass, self).__init__(project, 'jclass')


class JString(JObject):
    def __init__(self, project):
        super(JString, self).__init__(project, 'jstring')


class JThrowlable(JObject):
    def __init__(self, project):
        super(JThrowlable, self).__init__(project, 'jthrowlable')


class JArray(JObject):
    def __init__(self, project, name='jarray'):
        super(JArray, self).__init__(project, name)


class JObjectArray(JArray):
    def __init__(self, project):
        super(JObjectArray, self).__init__(project, 'jobjectarray')


class JBooleanArray(JArray):
    def __init__(self, project):
        super(JBooleanArray, self).__init__(project, 'jbooleanarray')


class JByteArray(JArray):
    def __init__(self, project):
        super(JByteArray, self).__init__(project, 'jbytearray')


class JCharArray(JArray):
    def __init__(self, project):
        super(JCharArray, self).__init__(project, 'jchararray')


class JShortArray(JArray):
    def __init__(self, project):
        super(JShortArray, self).__init__(project, 'jshortarray')


class JIntArray(JArray):
    def __init__(self, project):
        super(JIntArray, self).__init__(project, 'jintarray')


class JLongArray(JArray):
    def __init__(self, project):
        super(JLongArray, self).__init__(project, 'jlongarray')


class JFloatArray(JArray):
    def __init__(self, project):
        super(JFloatArray, self).__init__(project, 'jfloatarray')


class JDoubleArray(JArray):
    def __init__(self, project):
        super(JDoubleArray, self).__init__(project, 'jdoublearray')


class JMethodID(JObject):
    def __init__(self, project):
        super(JMethodID, self).__init__(project, 'jmethodID')


class JFieldID(JObject):
    def __init__(self, project):
        super(JFieldID, self).__init__(project, 'JFieldID')


class JSize(JObject):
    def __init__(self, project):
        super(JSize, self).__init__(project, 'JSize')


class JWeak(JObject):
    def __init__(self, project):
        super(JWeak, self).__init__(project, 'JWeak')


class JObjectRefType(JObject):
    def __init__(self, project):
        super(JObjectRefType, self).__init__(project, 'JObjectRefType')
