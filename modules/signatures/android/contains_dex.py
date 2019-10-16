# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ContainsDex(Signature):
    name = "contains_dex"
    description = "Application contains secondary DEX file"
    severity = 3
    categories = ["generic"]
    authors = ["idanr1986"]
    minimum = "2.1"

    def on_complete(self):
        for f in self.get_apkinfo("files", []):
            filename = f["name"]
            if "Dalvik" in f["type"] and filename != "classes.dex":
                self.mark_ioc("file", filename)

        return self.has_marks()
