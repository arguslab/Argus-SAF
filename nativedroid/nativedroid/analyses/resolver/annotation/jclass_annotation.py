from claripy import Annotation

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class JclassAnnotation(Annotation):
    """
    This annotation is used to store jclass type information.
    """

    def __init__(self, class_type, fields_info):
        """

        :param class_type: The type of this class.
        :param fields_info: The static fields of this class.
        """
        self._class_type = class_type
        self._fields_info = fields_info

    @property
    def class_type(self):
        return self._class_type

    @class_type.setter
    def class_type(self, value):
        self._class_type = value

    @property
    def fields_info(self):
        return self._fields_info

    @fields_info.setter
    def fields_info(self, value):
        self._fields_info = value

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def relocate(self, src, dst):
        return self
