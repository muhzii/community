# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ContainsSo(Signature):
    name = "contains_so"
    description = "Application contains shared object files"
    severity = 2
    categories = ["generic"]
    authors = ["idanr1986"]
    minimum = "2.1"

    def on_complete(self):
        for f in self.get_apkinfo("files", []):
            if "shared object" in f["type"]:
                self.mark_ioc("file", f["name"])

        return self.has_marks()
