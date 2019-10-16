# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DroppedSo(Signature):
    name = "drops_so"
    description = "Application drops shared library file"
    severity = 3
    categories = ["dropper", "evader", "stealth"]
    authors = ["idanr1986"]
    minimum = "2.1"

    filter_apinames = [
        "java.lang.Runtime.load"
    ]

    def on_call(self, call, process):
        self.mark_ioc("file", call["arguments"]["p0"])

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()
