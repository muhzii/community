# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UsesAccessibilityServices(Signature):
    name = "uses_accessibility_service"
    description = "Makes use of accessibility services (usually to monitor user input)"
    severity = 5
    categories = ["monitoring", "keylogger", "phishing", "banker"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "android.accessibilityservice.AccessibilityService"

    def on_complete(self):
        services = self.get_apkinfo("services", [])
        for service in services:
            if self.indicator in service["action"]:
                self.mark_ioc("service", service["name"])

        return self.has_marks()
