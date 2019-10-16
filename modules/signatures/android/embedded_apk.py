# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class EmbeddedApk(Signature):
    name = "embedded_apk"
    description = "Application contains a secondary APK file"
    severity = 3
    categories = ["stealth"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.1"

    def on_complete(self):
        for f in self.get_apkinfo("files", []):
            if "Android application package file" in f["type"]:
                self.mark_ioc("file", f["name"])

        return self.has_marks()
