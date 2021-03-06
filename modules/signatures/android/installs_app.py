# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CanInstallThirdPartApps(Signature):
    name = "can_install_apps"
    description = "Application may try to install other apps at runtime"
    severity = 3
    categories = ["generic", "downloader"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicators = ["REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES"]

    def on_complete(self):
        for indicator in self.indicators:
            if self.check_apk_permission(indicator):
                self.mark_ioc("permission", indicator)

            if indicator == "INSTALL_PACKAGES":
                self.severity += 1

        return self.has_marks()
