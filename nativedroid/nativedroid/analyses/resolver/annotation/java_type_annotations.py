from claripy import Annotation

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "EPL v1.0"


class JavaTypeAnnotation(Annotation):
    def __init__(self, source, obj_type):
        """

        :param source: Source of this Java value.
        :param obj_type: Type of this Java value.
        """
        self._source = source
        self._obj_type = obj_type
        self._field_info = {'is_field': False, 'field_name': None, 'original_subordinate_obj': None,
                            'current_subordinate_obj': None}
        self._taint_info = {'is_taint': False, 'taint_type': None, 'taint_info': None}
        self._icc_info = {'is_icc': False, 'activity_name': None, 'extra': None}

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        self._source = value

    @property
    def obj_type(self):
        return self._obj_type

    @obj_type.setter
    def obj_type(self, value):
        self._obj_type = value

    @property
    def field_info(self):
        return self._field_info

    @field_info.setter
    def field_info(self, value):
        self._field_info = value

    @property
    def taint_info(self):
        return self._taint_info

    @taint_info.setter
    def taint_info(self, value):
        self._taint_info = value

    @property
    def icc_info(self):
        return self._icc_info

    @icc_info.setter
    def icc_info(self, value):
        self._icc_info = value

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def relocate(self, src, dst):
        return self


class JobjectAnnotation(JavaTypeAnnotation):
    """
    This annotation is used to annotate the flow of the object related operations.
    """

    def __init__(self, source, obj_type, fields_info):
        """

        :param source: Source of this object.
        :param obj_type: Type of this object.
        :param fields_info: The fields of this object.
        """
        super(JobjectAnnotation, self).__init__(source, obj_type)
        self._fields_info = fields_info

    @property
    def fields_info(self):
        return self._fields_info

    @fields_info.setter
    def fields_info(self, value):
        self._fields_info = value


class PrimitiveTypeAnnotation(JavaTypeAnnotation):
    """
    This annotation is used to store primitive type value information.
    Primitive type includes jboolean, jbyte, jchar, jdouble, jfloat, jint, jlong, jshort.
    """

    def __init__(self, source, obj_type, value=None):
        """

        :param source: Source of this primitive value.
        :param obj_type: Type of this primitive value.
        :param value: Value of this primitive value.
        """
        super(PrimitiveTypeAnnotation, self).__init__(source, obj_type)
        self._value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class JbooleanAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jboolean type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this bool value.
        :param value: Value of this bool value.
        """
        super(JbooleanAnnotation, self).__init__(source, 'boolean', value)


class JbyteAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jbyte type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this byte value.
        :param value: Value of this byte value.
        """
        super(JbyteAnnotation, self).__init__(source, 'byte', value)


class JcharAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jchar type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this char value.
        :param value: Value of this char value.
        """
        super(JcharAnnotation, self).__init__(source, 'char', value)


class JdoubleAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jdouble type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this double value.
        :param value: Value of this double value.
        """
        super(JdoubleAnnotation, self).__init__(source, 'double', value)


class JfloatAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jfloat type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this float value.
        :param value: Value of this float value.
        """
        super(JfloatAnnotation, self).__init__(source, 'float', value)


class JintAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jint type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this int value.
        :param value: Value of this int value.
        """
        super(JintAnnotation, self).__init__(source, 'int', value)


class JlongAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jlong type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this long value.
        :param value: Value of this long value.
        """
        super(JlongAnnotation, self).__init__(source, 'long', value)


class JshortAnnotation(PrimitiveTypeAnnotation):
    """
    This annotation is used to store jshort type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this short value.
        :param value: Value of this short value.
        """
        super(JshortAnnotation, self).__init__(source, 'short', value)


class ObjectTypeAnnotation(JavaTypeAnnotation):
    """
    This annotation is used to store object type.
    """

    def __init__(self, source, obj_type, value=None):
        """

        :param source: Source of this object value.
        :param obj_type: Type of this object value
        :param value: Value of this object value.
        """
        super(ObjectTypeAnnotation, self).__init__(source, obj_type)
        self._value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class JstringAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to store jstring type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this string value.
        :param value: Value of this string value.
        """
        super(JstringAnnotation, self).__init__(source, 'java/lang/String', value)


class JbooleanArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the boolean array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this bool array value.
        :param value: Value of this bool array value.
        """
        super(JbooleanArrayAnnotation, self).__init__(source, 'boolean[]', value)


class JbyteArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the byte array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this byte array value.
        :param value: Value of this byte array value.
        """
        super(JbyteArrayAnnotation, self).__init__(source, 'byte[]', value)


class JcharArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the char array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this char value.
        :param value: Value of this char value.
        """
        super(JcharArrayAnnotation, self).__init__(source, 'char[]', value)


class JdoubleArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the double array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this double value.
        :param value: Value of this double value.
        """
        super(JdoubleArrayAnnotation, self).__init__(source, 'double[]', value)


class JfloatArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the float array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this float value.
        :param value: Value of this float value.
        """
        super(JfloatArrayAnnotation, self).__init__(source, 'float[]', value)


class JintArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the int array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this int value.
        :param value: Value of this int value.
        """
        super(JintArrayAnnotation, self).__init__(source, 'int[]', value)


class JlongArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the long array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this long value.
        :param value: Value of this long value.
        """
        super(JlongArrayAnnotation, self).__init__(source, 'long[]', value)


class JobjectArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the object array related operations.
    """

    def __init__(self, source, obj_type='java/lang/Object[]', value=None):
        """

        :param source: Source of this object value.
        :param obj_type: Type of this object array.
        :param value: Value of this object value.
        """
        super(JobjectArrayAnnotation, self).__init__(source, obj_type, value)


class JshortArrayAnnotation(ObjectTypeAnnotation):
    """
    This annotation is used to annotate the flow of the short array related operations.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this short value.
        :param value: Value of this short value.
        """
        super(JshortArrayAnnotation, self).__init__(source, 'short[]', value)
