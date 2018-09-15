from claripy import Annotation


class JmethodIDAnnotation(Annotation):
    """
    This annotation is used to store jmethodID type information.
    """

    def __init__(self, class_name=None, method_name=None, method_signature=None):
        self._class_name = class_name
        self._method_name = method_name
        self._method_signature = method_signature

    @property
    def class_name(self):
        return self._class_name

    @class_name.setter
    def class_name(self, value):
        self._class_name = value

    @property
    def method_name(self):
        return self._method_name

    @method_name.setter
    def method_name(self, value):
        self._method_name = value

    @property
    def method_signature(self):
        return self._method_signature

    @method_signature.setter
    def method_signature(self, value):
        self._method_signature = value

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return False

    def relocate(self, src, dst):
        return self
