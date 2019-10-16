# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class HiddenPayload(Signature):
    name = "hidden_payload"
    description = "Hidden payload (files) found"
    severity = 4
    categories = ["stealth"]
    authors = ["idanr1986"]
    minimum = "2.1"

    def is_file_payload_hidden(self, f):
        extension = f["name"].split(".")[-1]

        if "JAR" in f["type"]:
            if "apk" not in extension and "jar" not in extension:
                return True
        elif "shared object" in f["type"]:
            if "so" not in extension and "art" not in extension:
                return True
        elif "executable, ARM" in f["type"]:
            if "" != extension:
                return True
        elif "relocatable" in f["type"]:
            if "ko" not in extension:
                return True
        elif "Dalvik" in f["type"]:
            if "dex" not in extension:
                return True

        return False

    def on_complete(self):
        for f in self.get_apkinfo("files", []):
            if self.is_file_payload_hidden(f):
                self.mark_ioc("file", f["name"])

        return self.has_marks()
