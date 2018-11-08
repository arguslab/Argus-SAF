import angr
import logging
import re
from nativedroid.analyses.analysis_center import AnalysisCenter
from nativedroid.analyses.annotation_based_analysis import AnnotationBasedAnalysis
from nativedroid.analyses.resolver.dynamic_register_resolution import dynamic_register_resolve
from nativedroid.analyses.resolver.jni.jni_type import jni_native_interface
from nativedroid.analyses.resolver.model.native_pure_model import EnvMethodModel
from nativedroid.analyses.source_and_sink_manager import SourceAndSinkManager

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

nativedroid_logger = logging.getLogger('nativedroid')
nativedroid_logger.setLevel(logging.INFO)


def gen_summary(jnsaf_client, so_file, jni_method_name, jni_method_signature, jni_method_arguments,
                native_ss_file, java_ss_file):
    """
    Generate summary and taint tracking report based on annotation-based analysis.
    :param JNSafClient jnsaf_client: JNSaf client
    :param so_file: Binary path
    :param jni_method_name: JNI method name
    :param jni_method_signature: JNI method signature
    :param jni_method_arguments: Arguments of JNI method
    :param native_ss_file: Native source and sink file path
    :param java_ss_file: Java source and sink file path
    :return: Taint analysis report, safsu_report and total execution instructions number
    :rtype: tuple
    """
    nativedroid_logger.info(jni_method_name)
    jni_native_interface.java_sas_file = java_ss_file
    angr.register_analysis(AnnotationBasedAnalysis, 'AnnotationBasedAnalysis')
    project = angr.Project(so_file, load_options={'main_opts': {'custom_base_addr': 0x0}})
    jni_method_symb = project.loader.main_object.get_symbol(jni_method_name)
    if jni_method_symb is None:
        dynamic_register_methods = dynamic_register_resolve(project)
        res = re.split(r";\.|:", jni_method_signature)
        java_method_info = (res[1], res[2])
        jni_method_addr = dynamic_register_methods[java_method_info]
    else:
        jni_method_addr = jni_method_symb.rebased_addr
    ssm = SourceAndSinkManager(native_ss_file, java_ss_file)
    analysis_center = AnalysisCenter(jni_method_signature, jnsaf_client, ssm)
    annotation_based_analysis = project.analyses.AnnotationBasedAnalysis(
        analysis_center, jni_method_addr, jni_method_arguments, False)
    sources, sinks = annotation_based_analysis.run()
    taint_analysis_report = annotation_based_analysis.gen_taint_analysis_report(sources, sinks, jni_method_signature)
    safsu_report = annotation_based_analysis.gen_saf_summary_report(jni_method_signature)
    nativedroid_logger.info('[Taint Analysis]\n%s', taint_analysis_report)
    nativedroid_logger.info('[SafSu Analysis]\n%s', safsu_report)
    total_instructions = annotation_based_analysis.count_cfg_instructions()
    return taint_analysis_report, safsu_report, total_instructions


def clean_nativedroid(project, jni_method, jni_method_signature, jni_method_arguments, dynamic_register_methods,
                      native_ss_file, java_ss_file):
    """
    generate summary using annotation-based taint analysis
    :param project: Loaded Angr project
    :param jni_method: JNI method name
    :param jni_method_signature: JNI method signature
    :param jni_method_arguments: Arguments of JNI method
    :param dynamic_register_methods: Mapping information of dynamic register methods
    :param native_ss_file: native source and sink file path
    :param java_ss_file: java source and sink file path
    :return:
    """

    angr.register_analysis(AnnotationBasedAnalysis, 'AnnotationBasedAnalysis')
    jni_method_symb = project.loader.main_object.get_symbol(jni_method)
    if jni_method_symb is None:
        res = re.split(r";\.|:", jni_method_signature)
        java_method_info = (res[1], res[2])
        jni_method_addr = dynamic_register_methods[java_method_info]
        nativedroid_logger.debug('[JNI Method Addr]: %s', hex(jni_method_addr))
    else:
        jni_method_addr = jni_method_symb.rebased_addr
    ssm = SourceAndSinkManager(native_ss_file, java_ss_file)
    annotation_based_analysis = project.analyses.AnnotationBasedAnalysis(ssm, jni_method_addr, jni_method_arguments,
                                                                         False)
    sources, sinks = annotation_based_analysis.run()
    taint_analysis_report = annotation_based_analysis.gen_taint_analysis_report(sources, sinks, jni_method_signature)
    safsu_report = annotation_based_analysis.gen_saf_summary_report(jni_method_signature)
    nativedroid_logger.info('[Taint Analysis]\n%s', taint_analysis_report)
    nativedroid_logger.info('[SafSu Analysis]\n%s', safsu_report)
    total_instructions = annotation_based_analysis.count_cfg_instructions()
    nativedroid_logger.info('[Total Instructions]\n%d', total_instructions)


def has_symbol(so_file, symbol):
    """
    check is given symbol in the so_file
    :param so_file: so file
    :param symbol: the symbol to check
    :return: boolean
    """
    project = angr.Project(so_file, load_options={'auto_load_libs': False, 'main_opts': {'custom_base_addr': 0x0}})
    return project.loader.main_object.get_symbol(symbol) is not None


def native_activity_analysis(so_file, custom_entry_func_name, native_ss_file, java_ss_file):
    """
    Do the analysis for pure native activity.
    :param so_file: so file
    :param custom_entry_func_name: Custom entry function name
    :param native_ss_file: native source and sink file path
    :param java_ss_file: java source and sink file path
    :return: total instructions: total execution instructions
    """

    angr.register_analysis(AnnotationBasedAnalysis, 'AnnotationBasedAnalysis')
    project = angr.Project(so_file, load_options={'auto_load_libs': False, 'main_opts': {'custom_base_addr': 0x0}})
    env_method_model = EnvMethodModel()
    ssm = SourceAndSinkManager(native_ss_file, java_ss_file)

    android_main_symbol = project.loader.main_object.get_symbol('android_main')
    if android_main_symbol:
        entry_func_symbol = android_main_symbol
    else:
        if custom_entry_func_name:
            entry_func_symbol = project.loader.main_object.get_symbol(custom_entry_func_name)
        else:
            entry_func_symbol = project.loader.main_object.get_symbol('ANativeActivity_onCreate')

    if entry_func_symbol:
        if android_main_symbol:
            initial_state, native_activity_argument, initial_instructions = \
                env_method_model.hook_android_main_callbacks(project, entry_func_symbol)
        else:
            initial_state, native_activity_argument, initial_instructions = \
                env_method_model.hook_native_activity_direct_callbacks(project, entry_func_symbol)

        nativedroid_logger.info(entry_func_symbol.name)
        annotation_based_analysis = project.analyses.AnnotationBasedAnalysis(ssm, entry_func_symbol.rebased_addr,
                                                                             list(), True,
                                                                             (initial_state, native_activity_argument))
        annotation_based_analysis.run()
        analysis_instructions = annotation_based_analysis.count_cfg_instructions()
        total_instructions = initial_instructions + analysis_instructions
        nativedroid_logger.info('[Total Instructions] %s', total_instructions)
    else:
        total_instructions = 0
    return total_instructions
