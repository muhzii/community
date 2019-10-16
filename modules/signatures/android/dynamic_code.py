# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DynamicCode(Signature):
    name = "dynamic_code"
    description = "Application loads classes from bytecode/ dex dynamically"
    severity = 2
    categories = ["stealth"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "dalvik.system.PathClassLoader.$init",
        "dalvik.system.DexClassLoader.$init",
        "dalvik.system.InMemoryDexClassLoader.$init"
    ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            api = ".".join("%s.<init>" % api.split(".")[:3])
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()
