# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UmengAdware(Signature):
    name = "umeng_adware"
    description = "Umeng Adware (Detection)"
    severity = 5
    categories = ["adware"]
    authors = ["ofercas"]
    minimum = "2.1"
    families = ["Umeng"]

    indicators = ["alog.umeng.com", "oc.umeng.com"]

    def on_complete(self):
        for query in self.get_net_generic("dns"):
            for indicator in self.indicators:
                if indicator in query["request"]:
                    self.mark_ioc("dns", indicator)

        return self.has_marks()
