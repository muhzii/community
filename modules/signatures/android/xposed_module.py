# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class HasXposedModule(Signature):
    name = "has_xposed_module"
    description = "Application utilizes Xposed"
    severity = 4
    categories = ["monitoring"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "de.robv.android.xposed.*"

    def on_complete(self):
        matches = self.check_apk_api_call(self.indicator)
        if matches:
            self.mark_ioc("package", self.indicator[1:-2])

        return self.has_marks()
