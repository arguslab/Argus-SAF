import logging
import angr
import claripy
from cle.backends.externs import ExternObject

from nativedroid.analyses.resolver.jni.java_type import *
from nativedroid.analyses.resolver.jni.jni_type.jni_native_interface import JNINativeInterface

java_vm_origin_dict = {
    "DestroyJavaVM": 0,
    "AttachCurrentThread": 0,
    "DetachCurrentThread": 0,
    "GetEnv": 0,
    "AttachCurrentThreadAsDaemon": 0
}

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

nativedroid_logger = logging.getLogger('nativedroid.jni_invoke_interface')
nativedroid_logger.setLevel(logging.INFO)


class DestroyJavaVM(angr.SimProcedure):
    def run(self, java_vm, JNIEnv_ptr=None):
        nativedroid_logger.info('JNIInvokeInterface SimProcedure: %s', self)

        jint = JInt(self.project)
        return_value = claripy.BVV(jint.ptr, self.arch.bits)
        return return_value

    def __repr__(self):
        return 'DestroyJavaVM'


class AttachCurrentThread(angr.SimProcedure):
    def run(self, java_vm, p_env, thr_args, JNIEnv_ptr=None):
        nativedroid_logger.info('JNIInvokeInterface SimProcedure: %s', self)
        # JavaVM_ptr_addr = JavaVM_ptr.ast.args[0]
        # JavaVM_addr = self.state.se.any_int(self.state.memory.load(JavaVM_ptr_addr, 4, endness='Iend_LE'))

        self.state.memory.store(p_env, JNIEnv_ptr, endness='Iend_LE')
        # JNIEnv_ptr_ptr_addr = JNIEnv_ptr_ptr.ast.args[0]
        # JNIEnv_ptr_addr = self.state.se.any_int(self.state.memory.load(JNIEnv_ptr_ptr_addr, 4, endness='Iend_LE'))
        # jni_env_addr = self.state.se.any_int(self.state.memory.load(JNIEnv_ptr_addr, 4, endness='Iend_LE'))
        # print 'env address: ', hex(java_vm_addr)
        jint = JInt(self.project)
        return_value = claripy.BVV(jint.ptr, self.arch.bits)
        return return_value

    def __repr__(self):
        return 'AttachCurrentThread'


class DetachCurrentThread(angr.SimProcedure):
    def run(self, java_vm, JNIEnv_ptr=None):
        nativedroid_logger.info('JNIInvokeInterface SimProcedure: %s', self)
        jint = JInt(self.project)
        return_value = claripy.BVV(jint.ptr, self.arch.bits)
        return return_value

    def __repr__(self):
        return 'DetachCurrentThread'


class GetEnv(angr.SimProcedure):
    def run(self, java_vm, env, version, JNIEnv_ptr=None):
        nativedroid_logger.info('JNIInvokeInterface SimProcedure: %s', self)
        self.state.memory.store(env, JNIEnv_ptr, endness='Iend_LE')
        # void_ptr_ptr_addr = void_ptr_ptr.ast.args[0]
        # out = self.state.solver.eval(self.state.memory.load(void_ptr_ptr_addr, 4, endness='Iend_LE'), cast_to=int)
        # print 'out address: ', hex(out)

        version = JInt(self.project)
        return_value = claripy.BVV(version.ptr, self.arch.bits)
        return return_value

    def __repr__(self):
        return 'GetEnv'


class AttachCurrentThreadAsDaemon(angr.SimProcedure):
    def run(self, java_vm, p_env, thr_args, JNIEnv_ptr=None):
        nativedroid_logger.info('JNIInvokeInterface SimProcedure: %s', self)

        jint = JInt(self.project)
        return_value = claripy.BVV(jint.ptr, self.arch.bits)
        return return_value

    def __repr__(self):
        return 'AttachCurrentThreadAsDaemon'


class JNIInvokeInterface(ExternObject):
    jni_invoke_interface_index_to_name = {
        0: "reserved0",
        1: "reserved1",
        2: "reserved2",
        3: "DestroyJavaVM",
        4: "AttachCurrentThread",
        5: "DetachCurrentThread",
        6: "GetEnv",
        7: "AttachCurrentThreadAsDaemon"
    }

    jni_invoke_interface_index_to_simproc = {
        'DestroyJavaVM': DestroyJavaVM,
        'AttachCurrentThread': AttachCurrentThread,
        'DetachCurrentThread': DetachCurrentThread,
        'GetEnv': GetEnv,
        'AttachCurrentThreadAsDaemon': AttachCurrentThreadAsDaemon
    }

    def __init__(self, project, analysis_center):
        super(JNIInvokeInterface, self).__init__(project.loader)
        self._provides = 'JavaVM'
        self._project = project
        self._analysis_center = analysis_center
        self._fptr_size = self._project.arch.bits / 8
        self._project.loader.add_object(self)
        self._construct()

    def _construct(self):
        # allocate memory for the fake JNIInvokeInterface struct
        self._JNIInvokeInterface = self.allocate(len(self.jni_invoke_interface_index_to_name) * self._fptr_size)
        # allocate memory to JavaVM (a pointer) and make it to point to the fake JNIInvokeInterface struct
        self._JavaVM = self.allocate(self._fptr_size)
        self.memory.write_addr_at(self._JavaVM - self.min_addr, self._JNIInvokeInterface)

        self._JNINativeInterface = JNINativeInterface(self._project, self._analysis_center)
        self._JNIEnv = self._JNINativeInterface.ptr

        # iterate through the mapping
        for index, name in self.jni_invoke_interface_index_to_name.iteritems():
            # if the mappped value is None (there are 3 reserved entries), hook it with PathTerminator
            if name.startswith("reserved"):
                addr = self.allocate(self._fptr_size)
                self._project.hook(addr, angr.SIM_PROCEDURES['stubs']['PathTerminator']())
            else:
                addr = self.allocate(self._fptr_size)
                # if we have a custom simprocedure for that function, hook it with that
                if name in self.jni_invoke_interface_index_to_simproc:
                    self._project.hook(addr,
                                       self.jni_invoke_interface_index_to_simproc[name](
                                           JNIEnv_ptr=self._JNIEnv))
                # otherwise hook with ReturnUnconstrained
                else:
                    self._project.hook(addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'],
                                       kwargs={'resolves': name})
            self.memory.write_addr_at(self._JNIInvokeInterface - self.min_addr + index * self._fptr_size, addr)

    @property
    def ptr(self):
        return self._JavaVM
