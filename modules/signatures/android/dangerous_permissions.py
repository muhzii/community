# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DangerousPermissions(Signature):
    name = "dangerous_permissions"
    description = "Application asks for dangerous permissions"
    severity = 3
    categories = ["permissions"]
    authors = ["muhzii"]
    minimum = "2.1"

    def on_complete(self):
        for perm in self.get_apkinfo("manifest").get("permissions", []):
            if "dangerous" in perm["protection_level"] and "Unknown" not in perm["name"]:
                self.mark_ioc("permission", perm["name"], perm["description"])
                self.severity += 1

        if self.severity > 7:
            self.severity = 7

        return self.has_marks()
