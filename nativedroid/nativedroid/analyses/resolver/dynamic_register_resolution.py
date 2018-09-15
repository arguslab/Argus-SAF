import angr
import claripy
from nativedroid.analyses.resolver.jni.jni_type import jni_native_interface
from nativedroid.analyses.resolver.jni.jni_type.jni_invoke_interface import JNIInvokeInterface
import logging

nativedroid_logger = logging.getLogger('RegisterNativeMethods')
nativedroid_logger.setLevel(logging.INFO)

DYNAMIC_REGISTER_METHODS = {}


class RegisterNativeMethods(angr.SimProcedure):
    def run(self, env, class_name, g_methods, num_methods):
        logging.info('SimProcedure: %s', self)
        method_num = num_methods.ast.args[0]
        for i in range(method_num):
            method = self.state.mem[g_methods + i * 3 * self.state.arch.bytes].JNINativeMethod
            name = method.name.deref.string.concrete
            signature = method.signature.deref.string.concrete
            fn_ptr = method.fnPtr.resolved.args[0]
            DYNAMIC_REGISTER_METHODS[(name, signature)] = fn_ptr

    def __repr__(self):
        return 'RegisterNativeMethods'


def dynamic_register_resolve(project):
    """
    Resolve the dynamic register process and get the native methods mapping
    :param project: Angr project
    :return: dynamic_register_methods_dict: native methods mapping information
    """
    jni_on_load_symb = project.loader.main_object.get_symbol('JNI_OnLoad')
    if jni_on_load_symb is None:
        nativedroid_logger.error("JNI_OnLoad method doesn't exist. It should be some tricks that obfuscate the symbol.")
        return dict()
    else:
        nativedroid_logger.info('Dynamic register resolution begins.')
        state = project.factory.blank_state(addr=jni_on_load_symb.rebased_addr)
        java_vm = JNIInvokeInterface(project)
        state.regs.r0 = claripy.BVV(java_vm.ptr, project.arch.bits)
        if 'jniRegisterNativeMethods' in project.loader.main_object.imports or \
                '_ZN7android14AndroidRuntime21registerNativeMethodsEP7_JNIEnvPKcPK15JNINativeMethodi' in \
                project.loader.main_object.imports:
            project.hook_symbol('jniRegisterNativeMethods', RegisterNativeMethods())

        project.analyses.CFGAccurate(fail_fast=True, initial_state=state, starts=[jni_on_load_symb.rebased_addr],
                                     context_sensitivity_level=1, enable_function_hints=False, keep_state=True,
                                     enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,
                                     normalize=True, iropt_level=1)

        register_natives_dict = jni_native_interface.DYNAMIC_REGISTER_METHODS
        register_native_methods_dict = DYNAMIC_REGISTER_METHODS
        dynamic_register_methods_dict = dict(register_natives_dict, **register_native_methods_dict)
        return dynamic_register_methods_dict
