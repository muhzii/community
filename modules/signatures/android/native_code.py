# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class NativeCode(Signature):
    name = "native_code"
    description = "Application uses native JNI methods"
    severity = 2
    categories = ["generic"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.1"

    def on_complete(self):
        return True if self.get_apkinfo("native_methods") else False
