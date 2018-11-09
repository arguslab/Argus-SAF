from nativedroid.analyses.resolver.jni.jni_type.jni_invoke_interface import *
from nativedroid.analyses.resolver.annotation import *

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class ANativeActivity(ExternObject):
    vm_offset = 1
    env_offset = 2
    clazz_offset = 3

    ANativeActivity_index_to_name = {
        0: "callbacks",
        1: "vm",
        2: "env",
        3: "clazz",
        4: "internalDataPath",
        5: "externalDataPath",
        6: "sdkVersion",
        7: "instance",
        8: "assetManager",
        9: "obbPath"
    }

    def __init__(self, project, analysis_center, state=None):
        super(ANativeActivity, self).__init__(project.loader)
        self._provides = 'ANativeActivity'
        self._project = project
        self._analysis_center = analysis_center
        self._state = state
        self._fptr_size = project.arch.bits / 8
        self._project.loader.add_object(self)
        self._construct()

    def _construct(self):
        # Construct ANativeActivity struct and map the ANativeActivity struct to its pointer
        self._ANativeActivity_ptr = self.allocate(self._fptr_size)
        self._ANativeActivity = self.allocate(len(self.ANativeActivity_index_to_name) * self._fptr_size)
        self.memory.write_addr_at(self._ANativeActivity_ptr - self.min_addr, self._ANativeActivity)

        # set the right field off ANativeActivity struct to point to JavaVM(JNIInvokeInterface)
        self._vm = JNIInvokeInterface(self._project, self._analysis_center)
        self.memory.write_addr_at(self._ANativeActivity_ptr - self.min_addr + self.vm_offset * self._fptr_size,
                                  self._vm.ptr)

        # set the right field off ANativeActivity struct to point to JNIEnv(JNINativeInterface)
        # self._env = JNINativeInterface(self._project)
        # self.memory.write_addr_at(self._ANativeActivity_ptr - self.min_addr + self.env_offset * self._fptr_size,
        #                           self._env.ptr)

        # assign an address to clazz element in ANativeActivity
        jobject = JObject(self._project)
        clazz = claripy.BVV(jobject.ptr, self._project.arch.bits)
        clazz = clazz.annotate(
            JobjectAnnotation(source='from_native', obj_type='android/app/Activity', fields_info=list()))
        self._state.memory.store(self._ANativeActivity_ptr + self.clazz_offset * self._fptr_size, clazz,
                                 endness='Iend_LE')

    @property
    def ptr(self):
        return self._ANativeActivity_ptr
