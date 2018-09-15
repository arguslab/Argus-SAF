from claripy import Annotation


class JfieldIDAnnotation(Annotation):
    """
    This annotation is used to store jfieldID type information.
    """

    def __init__(self, class_name=None, field_name=None, field_signature=None):
        self._class_name = class_name
        self._field_name = field_name
        self._field_signature = field_signature

    @property
    def class_name(self):
        return self._class_name

    @class_name.setter
    def class_name(self, value):
        self._class_name = value

    @property
    def field_name(self):
        return self._field_name

    @field_name.setter
    def field_name(self, value):
        self._field_name = value

    @property
    def field_signature(self):
        return self._field_signature

    @field_signature.setter
    def field_signature(self, value):
        self._field_signature = value

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def relocate(self, src, dst):
        return self
