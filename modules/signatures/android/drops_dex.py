# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DroppedDex(Signature):
    name = "drops_dex"
    description = "Application drops dex file"
    severity = 3
    categories = ["dropper", "evader", "stealth"]
    authors = ["idanr1986"]
    minimum = "2.1"

    filter_apinames = [
        "dalvik.system.DexFile.openDexFile"
    ]

    def on_call(self, call, process):
        filepath = call["arguments"]["p0"]
        if "/system/" not in filepath and "/data/app/" not in filepath:
            self.mark_ioc("file", filepath)

    def on_complete(self):
        return self.has_marks()
