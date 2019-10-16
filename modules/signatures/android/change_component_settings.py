# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ComponentEnabledSetting(Signature):
    name = "changes_component_enabled_setting"
    description = "Modifies its component enabled setting " \
        "(likely to remove its launcher activity in order to stay hidden)"
    severity = 4
    categories = ["stealth"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.app.ApplicationPackageManager.setComponentEnabledSetting"
    ]

    def on_call(self, call, process):
        states = {
            "0": "COMPONENT_ENABLED_STATE_DEFAULT",
            "1": "COMPONENT_ENABLED_STATE_ENABLED",
            "2": "COMPONENT_ENABLED_STATE_DISABLED",
        }

        component = call["arguments"]["p0"]
        state = call["arguments"]["p1"]

        self.mark(
            component_name="%s/%s" % (component["package"], component["class"]),
            new_state=states.get(state, "")
        )

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()

