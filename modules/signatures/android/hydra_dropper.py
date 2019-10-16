# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class HydraDropper(Signature):
    name = "hydra_dropper"
    description = "Hydra dropper malware - installs overlay apps to steal info"
    severity = 5
    categories = ["dropper", "bankbot", "phishing", "trojan", "infostealer"]
    authors = ["muhzii"]
    minimum = "2.1"

    def on_complete(self):
        match = self.check_apk_file(".*libhoter.so", True)
        if match:
            self.mark_ioc("file", match)

        package_name = self.get_apkinfo("manifest", {}).get("package", "")
        if "taxationtex" in package_name:
            self.mark_ioc("package", package_name)

        for f in self.get_results("dropped", []):
            if f.get("name", None) == "xwcnhfc.dex":
                self.mark_ioc("file", "xwcnhfc.dex", "dropped malicious SDK")

        return self.has_marks()
