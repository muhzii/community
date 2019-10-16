# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ContainsEncryptedAssets(Signature):
    name = "contains_encrypted_assets"
    description = "Application contains encrypted assets"
    severity = 4
    categories = ["stealth"]
    authors = ["idanr1986"]
    minimum = "2.1"

    def on_complete(self):
        for asset in self.get_apkinfo("encrypted_assets", []):
            self.mark_ioc(
                "file", asset["name"], "entropy = %s" % asset["entropy"]
            )

        return self.has_marks()
