import angr
import claripy
import logging

from nativedroid.analyses.resolver.annotation.taint_position_annotation import *
from nativedroid.analyses.resolver.jni.java_type.reference import *

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

nativedroid_logger = logging.getLogger('AndroidLogPrint')
nativedroid_logger.setLevel(logging.INFO)


class AndroidLogPrint(angr.SimProcedure):
    """
    __android_log_print SimProcedure.
    """

    def run(self, prio, tag, fmt):
        nativedroid_logger.info('SimProcedure: %s', self)
        strlen_simproc = angr.SIM_PROCEDURES['libc']['strlen']
        fmt_strlen = self.inline_call(strlen_simproc, fmt)

        fmt_str = self.state.solver.eval(self.state.memory.load(fmt, fmt_strlen.ret_expr), cast_to=str)
        arg_num = fmt_str.count('%')

        reg_position = 3
        stack_position = list()
        if arg_num > 1:
            stack_args_num = arg_num - 1
            stack_position = range(1, stack_args_num + 1)
        jobject = JObject(self.project)
        return_value = claripy.BVV(jobject.ptr, self.project.arch.bits)
        return_value = return_value.annotate(
            TaintPositionAnnotation(reg_position=reg_position, stack_position=stack_position))
        return return_value

    def __repr__(self):
        return '__android_log_print'
