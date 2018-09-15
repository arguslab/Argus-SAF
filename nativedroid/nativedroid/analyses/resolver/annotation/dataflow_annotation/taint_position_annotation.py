from claripy import Annotation


class TaintPositionAnnotation(Annotation):
    """
    Annotate taint position information.
    """

    def __init__(self, reg_position=None, stack_position=None):
        self._reg_position = reg_position
        self._stack_position = stack_position

    @property
    def reg_position(self):
        return self._reg_position

    @reg_position.setter
    def reg_position(self, value):
        self._reg_position = value

    @property
    def stack_position(self):
        return self._stack_position

    @stack_position.setter
    def stack_position(self, value):
        self._stack_position = value

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        return TaintPositionAnnotation(self._reg_position, self._stack_position)
