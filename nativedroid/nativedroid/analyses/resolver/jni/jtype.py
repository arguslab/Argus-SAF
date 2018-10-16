from cle.backends.externs import ExternObject

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class JType(ExternObject):
    """
    This class represents the java or jni types.
    """
    def __init__(self, project, name, alloc_size=0x4000):
        super(JType, self).__init__(project.loader)
        self._provides = name
        self._project = project
        self._alloc_size = alloc_size
        self._fptr_size = project.arch.bits / 8
        # register before construct because of rebasing
        self._project.loader.add_object(self)
        self._construct()

    def _construct(self):
        # allocate memory for the fake JType object
        self._jtype = self.allocate(self._alloc_size)
        # # allocate memory to a pointer and make it to point to the fake env
        # self._JNIEnv_struct_ptr = self.allocate(self._fptr_size)
        # self.memory.write_addr_at(self._JNIEnv_struct_ptr - self.min_addr, self._JNIEnv_struct)

    @property
    def ptr(self):
        return self._jtype
