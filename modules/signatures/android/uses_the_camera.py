# Copyright (C) Check Point Software Technologies LTD.
# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UsesTheCamera(Signature):
    name = "uses_the_camera"
    description = "Takes photos with the camera"
    severity = 4
    categories = ["infostealer"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.1"

    filter_apinames = [
        "android.content.Intent.$init",
        "android.content.Intent.setAction"
    ]

    def on_call(self, call, process):
        if "p0" in call["arguments"] and type(call["arguments"]["p0"]) == str:
            if call["arguments"]["p0"] == "android.media.action.IMAGE_CAPTURE":
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
