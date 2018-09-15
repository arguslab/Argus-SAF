import re
import logging
import angr
from nativedroid.analyses.resolver.jni.jni_type import jni_native_interface
from nativedroid.analyses.annotation_based_analysis import AnnotationBasedAnalysis
from nativedroid.analyses.source_and_sink_manager import SourceAndSinkManager
from nativedroid.analyses.resolver.model.native_pure_model import EnvMethodModel
from nativedroid.analyses.resolver.dynamic_register_resolution import dynamic_register_resolve

nativedroid_logger = logging.getLogger('nativedroid')
nativedroid_logger.setLevel(logging.INFO)


def gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file):
    """
    Generate summary and taint tracking report based on annotation-based analysis.
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
        # nativedroid_logger.debug('[JNI Method Addr]: %s', hex(jni_method_addr))
    else:
        jni_method_addr = jni_method_symb.rebased_addr
    ssm = SourceAndSinkManager(native_ss_file)
    annotation_based_analysis = project.analyses.AnnotationBasedAnalysis(ssm, jni_method_addr, jni_method_arguments,
                                                                         False)
    sources, sinks = annotation_based_analysis.run()
    taint_analysis_report = annotation_based_analysis.gen_taint_analysis_report(sources, sinks, jni_method_signature)
    safsu_report = annotation_based_analysis.gen_saf_summary_report(jni_method_signature)
    nativedroid_logger.info('[Taint Analysis]\n%s', taint_analysis_report)
    nativedroid_logger.info('[SafSu Analysis]\n%s', safsu_report)
    total_instructions = annotation_based_analysis.count_cfg_instructions()
    # nativedroid_logger.info('[Total Instructions]\n%d', total_instructions)
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

    jni_native_interface.java_sas_file = java_ss_file
    angr.register_analysis(AnnotationBasedAnalysis, 'AnnotationBasedAnalysis')
    jni_method_symb = project.loader.main_object.get_symbol(jni_method)
    if jni_method_symb is None:
        res = re.split(r";\.|:", jni_method_signature)
        java_method_info = (res[1], res[2])
        jni_method_addr = dynamic_register_methods[java_method_info]
        nativedroid_logger.debug('[JNI Method Addr]: %s', hex(jni_method_addr))
    else:
        jni_method_addr = jni_method_symb.rebased_addr
    ssm = SourceAndSinkManager(native_ss_file)
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

    jni_native_interface.java_sas_file = java_ss_file
    angr.register_analysis(AnnotationBasedAnalysis, 'AnnotationBasedAnalysis')
    project = angr.Project(so_file, load_options={'auto_load_libs': False, 'main_opts': {'custom_base_addr': 0x0}})
    # project = angr.Project(so_file, load_options={'auto_load_libs': False, 'main_opts': {'custom_base_addr': 0x0}},
    #                        exclude_sim_procedures_list=['pthread_create'])
    env_method_model = EnvMethodModel()
    ssm = SourceAndSinkManager(native_ss_file)

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
                                                                             list(),
                                                                             True,
                                                                             (initial_state, native_activity_argument))
        annotation_based_analysis.run()
        analysis_instructions = annotation_based_analysis.count_cfg_instructions()
        total_instructions = initial_instructions + analysis_instructions
        nativedroid_logger.info('[Total Instructions] %s', total_instructions)
    else:
        total_instructions = 0
    return str(total_instructions)


def native_flow_bench_debug(native_ss_file, java_ss_file):
    """

    :param native_ss_file:
    :param java_ss_file:
    :return:
    """

    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_leak/lib/armeabi/libleak.so'
    # jni_method_name = 'Java_org_arguslab_native_1leak_MainActivity_send'
    # jni_method_signature = 'Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V'
    # jni_method_arguments = 'org.arguslab.native_leak.MainActivity,java.lang.String'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/icc_nativetojava/lib/armeabi/libintent.so'
    # jni_method_name = 'Java_org_arguslab_icc_1nativetojava_MainActivity_sendIntent'
    # jni_method_signature = 'Lorg/arguslab/icc_nativetojava/MainActivity;.sendIntent:(Ljava/lang/String;)V'
    # jni_method_arguments = 'org.arguslab.icc_nativetojava.MainActivity,java.lang.String'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_method_overloading/lib/armeabi/libmethod_overloading.so'
    # jni_method_name = 'Java_org_arguslab_native_1method_1overloading_MainActivity_send___3I_3Ljava_lang_String_2Ljava_lang_String_2D'
    # jni_method_signature = 'Lorg/arguslab/native_method_overloading/MainActivity;.send:([I[Ljava/lang/String;Ljava/lang/String;D)V'
    # jni_method_arguments = 'org.arguslab.native_method_overloading.MainActivity,int[],java.lang.String[],java.lang.String,double'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_heap_modify/lib/armeabi/libheap_modify.so'
    # jni_method_name = 'Java_org_arguslab_native_1heap_1modify_MainActivity_heapModify'
    # jni_method_signature = 'Lorg/arguslab/native_heap_modify/MainActivity;.heapModify:(Landroid/content/Context;Lorg/arguslab/native_heap_modify/Data;)V'
    # jni_method_arguments = 'org.arguslab.native_heap_modify.MainActivity,android.content.Context,org.arguslab.native_heap_modify.Data'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_leak_dynamic_register/lib/armeabi/libleak_dynamic_register.so'
    # jni_method_name = 'Java_org_arguslab_native_1leak_1dynamic_1register_MainActivity_send'
    # jni_method_signature = 'Lorg/arguslab/native_leak_dynamic_register/MainActivity;.send:(Ljava/lang/String;)V'
    # jni_method_arguments = 'org.arguslab.native_leak_dynamic_register.MainActivity,java.lang.String'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_dynamic_register_multiple/lib/armeabi/libdynamic_register_multiple.so'
    # jni_method_name = 'Java_org_arguslab_native_1dynamic_1register_1multiple_MainActivity_send'
    # jni_method_signature = 'Lorg/arguslab/native_dynamic_register_multiple/MainActivity;.send:(Ljava/lang/String;)V'
    # jni_method_arguments = 'org.arguslab.native_dynamic_register_multiple.MainActivity,java.lang.String'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_source/lib/armeabi/libsource.so'
    # jni_method_name = 'Java_org_arguslab_native_1source_MainActivity_getImei'
    # jni_method_signature = 'Lorg/arguslab/native_source/MainActivity;.getImei:(Landroid/content/Context;)Ljava/lang/String;'
    # jni_method_arguments = 'org.arguslab.native_source.MainActivity,android.content.Context'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_complexdata/lib/armeabi/libdata.so'
    # jni_method_name = 'Java_org_arguslab_native_1complexdata_MainActivity_send'
    # jni_method_signature = 'Lorg/arguslab/native_complexdata/MainActivity;.send:(Lorg/arguslab/native_complexdata/ComplexData;)V'
    # jni_method_arguments = 'org.arguslab.native_complexdata.MainActivity,org.arguslab.native_complexdata.ComplexData'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_set_field_from_arg/lib/armeabi/libset_field_from_arg.so'
    # jni_method_name = 'Java_org_arguslab_native_1set_1field_1from_1arg_MainActivity_setField'
    # jni_method_signature = 'Lorg/arguslab/native_set_field_from_arg/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg/ComplexData;Lorg/arguslab/native_set_field_from_arg/Foo;)Lorg/arguslab/native_set_field_from_arg/Foo;'
    # jni_method_arguments = 'org.arguslab.native_set_field_from_arg.MainActivity,org.arguslab.native_set_field_from_arg.ComplexData,org.arguslab.native_set_field_from_arg.Foo'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_set_field_from_arg_field/lib/armeabi/libset_field_from_arg_field.so'
    # jni_method_name = 'Java_org_arguslab_native_1set_1field_1from_1arg_1field_MainActivity_setField'
    # jni_method_signature = 'Lorg/arguslab/native_set_field_from_arg_field/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg_field/ComplexData;Lorg/arguslab/native_set_field_from_arg_field/ComplexData;)Lorg/arguslab/native_set_field_from_arg_field/Foo;'
    # jni_method_arguments = 'org.arguslab.native_set_field_from_arg_field.MainActivity,org.arguslab.native_set_field_from_arg_field.ComplexData,org.arguslab.native_set_field_from_arg_field.ComplexData'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_set_field_from_native/lib/armeabi/libset_field_from_native.so'
    # jni_method_name = 'Java_org_arguslab_native_1set_1field_1from_1native_MainActivity_setField'
    # jni_method_signature = 'Lorg/arguslab/native_set_field_from_native/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_native/ComplexData;)Lorg/arguslab/native_set_field_from_native/Foo;'
    # jni_method_arguments = 'org.arguslab.native_set_field_from_native.MainActivity,org.arguslab.native_set_field_from_native.ComplexData'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # so_file = '../../../src/test/resources/NativeFlowBench/NativeLibs/native_leak_array/lib/armeabi/libleak_array.so'
    # jni_method_name = 'Java_org_arguslab_native_1leak_1array_MainActivity_send'
    # jni_method_signature = 'Lorg/arguslab/native_leak_array/MainActivity;.send:([Ljava/lang/String;)V'
    # jni_method_arguments = 'org.arguslab.native_leak_array.MainActivity,java.lang.String[]'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
    #
    # native_activity_analysis(
    #     "../../../src/test/resources/NativeFlowBench/NativeLibs/icc_javatonative/lib/armeabi/libnative-activity.so", None,
    #     native_ss_file, java_ss_file)
    #
    # native_activity_analysis(
    #     "../../../src/test/resources/NativeFlowBench/NativeLibs/native_pure/lib/armeabi/libnative-activity.so", None,
    #     native_ss_file, java_ss_file)
    #
    # native_activity_analysis(
    #     "../../../src/test/resources/NativeFlowBench/NativeLibs/native_pure_direct/lib/armeabi/libnative-activity.so", None,
    #     native_ss_file, java_ss_file)
    #
    # native_activity_analysis(
    #     "../../../src/test/resources/NativeFlowBench/NativeLibs/native_pure_direct_customized/lib/armeabi/libnative-activity.so",
    #     'NativeActivity_Entry',
    #     native_ss_file, java_ss_file)


# if __name__ == "__main__":
    # native_ss_file = '../../../files/sourceAndSinks/NativeSourcesAndSinks.txt'
    # java_ss_file = '../../../files/sourceAndSinks/TaintSourcesAndSinks.txt'
    # native_flow_bench_debug(native_ss_file, java_ss_file)
    # so_file = '/home/xwlin/Desktop/Data/statistics_debug/native_array-release/lib/armeabi-v7a/libdata.so'
    # jni_method_name = 'Java_org_arguslab_native_1complexdata_1stringop_MainActivity_BooleanArray'
    # jni_method_signature = 'Lorg/arguslab/native_complexdata_stringop/MainActivity;.BooleanArray:()V'
    # jni_method_arguments = 'org.arguslab.native_complexdata_stringop.MainActivity'
    # gen_summary(so_file, jni_method_name, jni_method_signature, jni_method_arguments, native_ss_file, java_ss_file)
