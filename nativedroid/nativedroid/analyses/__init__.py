import angr
from annotation_based_analysis import AnnotationBasedAnalysis
from source_and_sink_manager import SourceAndSinkManager
from resolver.model import *
from resolver import *


from nativedroid_analysis import *


def register(so_file):
    """
    Load so file using angr, and register AnnotationBasedAnalysis.

    :param str so_file: file path.
    :return: Angr project
    :rtype Project
    """
    angr.register_analysis(AnnotationBasedAnalysis, 'AnnotationBasedAnalysis')
    b = angr.Project(so_file, load_options={'main_opts': {'custom_base_addr': 0x0}})
    return b


def generate_ssm(sas_file):
    """
    :param str sas_file: file path
    :return: Source and sink manager
    :rtype: SourceAndSinkManager
    """
    return SourceAndSinkManager(sas_file)


def do_taint(project, ssm, main_func, is_jni, is_android_main, params):
    """
    Perform taint analysis for given function.

    :param angr.project.Project project: Angr project
    :param SourceAndSinkManager ssm: Source and sink manager
    :param str main_func: Main function name
    :param bool is_jni: Given function is jni call or not.
    :param bool is_android_main: Is jni pure native activity or not.
    :param java.util.List[Tuple(str, java.util.Set[str])] params: List of params
    :return:
    """
    params_py = []
    for param in params.toArray():
        tags_py = param._2.toArray()
        params_py.append((param._1, tags_py))
    taint = project.analyses.AnnotationBasedTaintAnalysis(ssm, main_func, is_jni, is_android_main, params_py)
    taint.run()
