__author__ = "Xingwei Lin"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class TaintResolver(object):
    """
    This class provides the architecture specific taint solutions.
    """

    def __init__(self, project, analysis_center):
        self._project = project
        self._analysis_center = analysis_center

    def prepare_initial_state(self, arguments):
        """
        Prepare initial state for CFGAccurate.

        :param list arguments: Arguments need to put to the state.
        :return: Initial state
        :rtype: angr.sim_type.SimState
        """
        raise NotImplementedError()

    def get_taint_args(self, input_state, final_states, positions, tags):
        """
        Get args with TaintAnnotation from given state.

        :param angr.sim_type.SimState input_state: SimState of current program point.
        :param list final_states: Fianl SimStates of current point.
        :param list positions: Taint argument candidates.
        :param list tags: Taint tags.
        :return: Tainted args
        :rtype: list
        """
        raise NotImplementedError()

    def prepare_native_pure_state(self, native_pure_info, other_arguments=None):
        """
        Prepare native pure initial state for CFGAccurate.

        :param Object native_pure_info: initial SimState and native pure argument
        :param list other_arguments: Arguments (with taint flags) need to put to the state.
        :return: Initial state
        :rtype: angr.sim_type.SimState
        """

        raise NotImplementedError()

    @staticmethod
    def _is_taint(annotation, tags):
        """
        Is given situation tainted.

        :param TaintAnnotation annotation: taint annotation
        :param list tags: taint tags
        :return: is tainted
        :rtype: bool
        """
        return annotation.label is 'TOP' or 'TOP' in tags or annotation.label in tags
