from nativedroid.analyses.resolver.jni.jtype import JType

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class JBoolean(JType):
    def __init__(self, project):
        super(JBoolean, self).__init__(project, 'jboolean', 1)


class JByte(JType):
    def __init__(self, project):
        super(JByte, self).__init__(project, 'jbyte', 1)


class JChar(JType):
    def __init__(self, project):
        super(JChar, self).__init__(project, 'jchar', 2)


class JShort(JType):
    def __init__(self, project):
        super(JShort, self).__init__(project, 'jshort', 2)


class JInt(JType):
    def __init__(self, project):
        super(JInt, self).__init__(project, 'jint', 4)


class JLong(JType):
    def __init__(self, project):
        super(JLong, self).__init__(project, 'jlong', 8)


class JFloat(JType):
    def __init__(self, project):
        super(JFloat, self).__init__(project, 'jfloat', 4)


class JDouble(JType):
    def __init__(self, project):
        super(JDouble, self).__init__(project, 'jdouble', 8)


class Void(JType):
    def __init__(self, project):
        super(Void, self).__init__(project, 'void')
