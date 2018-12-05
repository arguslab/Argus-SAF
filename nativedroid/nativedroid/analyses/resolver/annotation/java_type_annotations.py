import re
from claripy import Annotation

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class JavaTypeAnnotation(Annotation):
    def __init__(self, source, obj_type):
        """

        :param source: Source of this Java value.
        :param obj_type: Type of this Java value.
        """
        self._source = source
        self._heap = 'arg:' + str(re.split('arg|_', source)[1]) if source.startswith('arg') else None
        self._obj_type = obj_type
        self._field_info = {'is_field': False, 'field_name': None, 'base_annotation': None}
        self._array_info = {'is_element': False, 'element_index': None, 'base_annotation': None}
        self._taint_info = {'is_taint': False, 'taint_type': None, 'taint_info': None,
                            'source_kind': None, 'sink_kind': None}
        self._icc_info = {'is_icc': False, 'activity_name': None, 'extra': None}

    def __repr__(self):
        text = '%s {\n  Source: %s\n  Heap: %s\n  Type: %s\n  '\
               'Field Info: %s\n  Array Info: %s\n  Taint Info: %s\n  ICC Info: %s\n}' % \
               (self.__class__.__name__, self._source, self.heap, self.obj_type, self.field_info,
                self.array_info, self.taint_info, self.icc_info)
        return text

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value):
        self._source = value

    @property
    def heap(self):
        return self._heap

    @heap.setter
    def heap(self, value):
        self._heap = value

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
    def array_info(self):
        return self._array_info

    @array_info.setter
    def array_info(self, value):
        self._array_info = value

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


class JstringAnnotation(JobjectAnnotation):
    """
    This annotation is used to store jstring type value information.
    """

    def __init__(self, source, value=None):
        """

        :param source: Source of this string value.
        :param value: Value of this string value.
        """
        super(JstringAnnotation, self).__init__(source, 'java/lang/String', list())
        self._value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class JArrayAnnotation(JobjectAnnotation):
    """
    This annotation is used to store array type value information.
    """

    def __init__(self, source, obj_type, elements=None):
        """

        :param source: Source of this array value.
        :param obj_type: Type of this array value
        :param elements: Elements of this array value.
        """
        super(JArrayAnnotation, self).__init__(source, obj_type, list())
        self._elements = elements

    @property
    def elements(self):
        return self._elements

    @elements.setter
    def elements(self, value):
        self._elements = value


class JbooleanArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the boolean array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this bool array value.
        :param elements: Elements of this bool array value.
        """
        super(JbooleanArrayAnnotation, self).__init__(source, 'boolean[]', elements)


class JbyteArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the byte array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this byte array value.
        :param elements: Elements of this byte array value.
        """
        super(JbyteArrayAnnotation, self).__init__(source, 'byte[]', elements)


class JcharArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the char array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this char array value.
        :param elements: Elements of this char array value.
        """
        super(JcharArrayAnnotation, self).__init__(source, 'char[]', elements)


class JshortArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the short array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this short array value.
        :param elements: Elements of this short array value.
        """
        super(JshortArrayAnnotation, self).__init__(source, 'short[]', elements)


class JintArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the int array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this int array value.
        :param elements: Elements of this int array value.
        """
        super(JintArrayAnnotation, self).__init__(source, 'int[]', elements)


class JlongArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the long array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this long array value.
        :param elements: Elements of this long array value.
        """
        super(JlongArrayAnnotation, self).__init__(source, 'long[]', elements)


class JfloatArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the float array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this float array value.
        :param elements: Elements of this float array value.
        """
        super(JfloatArrayAnnotation, self).__init__(source, 'float[]', elements)


class JdoubleArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the double array related operations.
    """

    def __init__(self, source, elements=None):
        """

        :param source: Source of this double array value.
        :param elements: Elements of this double array value.
        """
        super(JdoubleArrayAnnotation, self).__init__(source, 'double[]', elements)


class JobjectArrayAnnotation(JArrayAnnotation):
    """
    This annotation is used to annotate the flow of the object array related operations.
    """

    def __init__(self, source, obj_type='java/lang/Object[]', elements=None):
        """

        :param source: Source of this object array value.
        :param obj_type: Type of this object array value.
        :param elements: Elements of this object array value.
        """
        super(JobjectArrayAnnotation, self).__init__(source, obj_type, elements)
