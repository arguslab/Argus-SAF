from nativedroid.analyses.resolver.model.anativeactivity_model import *

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class AndroidApp(ExternObject):
    activity_offset = 3

    android_app_index_to_name = {
        0: "userData",
        1: "onAppCmd",
        2: "onInputEvent",
        3: "activity",
        4: "config",
        5: "savedState",
        6: "savedStateSize",
        7: "looper",
        8: "inputQueue",
        9: "window",
        10: "contentRect",
        11: "activityState",
        12: "destroyRequested",
        13: "mutex",
        14: "cond",
        15: "msgread",
        16: "msgwrite",
        17: "thread",
        18: "cmdPollSource",
        19: "inputPollSource",
        20: "running",
        21: "stateSaved",
        22: "destroyed",
        23: "redrawNeeded",
        24: "pendingInputQueue",
        25: "pendingWindow",
        26: "pendingContentRect"
    }

    def __init__(self, project, analysis_center, state=None):
        super(AndroidApp, self).__init__(project.loader)
        self._provides = 'android_app'
        self._project = project
        self._analysis_center = analysis_center
        self._state = state
        self._fptr_size = project.arch.bits / 8
        self._project.loader.add_object(self)
        self._construct()

    def _construct(self):
        self._android_app = self.allocate(len(self.android_app_index_to_name) * self._fptr_size)
        # construct struct android_app* state point to android_app struct
        self._android_app_ptr = self.allocate(self._fptr_size)
        self.memory.write_addr_at(
            self._android_app_ptr - self.min_addr, self._android_app)

        # construct ANativeActivity struct
        self._activity = ANativeActivity(self._project, self._analysis_center, self._state)
        # set the right field off android_app struct to point to ANativeActivity struct
        self.memory.write_addr_at(
            self._android_app_ptr - self.min_addr + self.activity_offset * self._fptr_size,
            self._activity.ptr)

    @property
    def ptr(self):
        return self._android_app_ptr
