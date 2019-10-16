# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DeletesApps(Signature):
    name = "can_delete_apps"
    description = "Application may try to delete other apps at runtime"
    severity = 3
    categories = ["stealth", "phishing"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicators = ["REQUEST_DELETE_PACKAGES", "DELETE_PACKAGES"]

    def on_complete(self):
        for indicator in self.indicators:
            if self.check_apk_permission(indicator):
                self.mark_ioc("permission", indicator)

            if indicator == "DELETE_PACKAGES":
                self.severity += 1

        return self.has_marks()
