# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AirPushAdware(Signature):
    name = "airpush_adware"
    description = "AirPush adware sdk detection"
    severity = 4
    categories = ["adware"]
    authors = ["ofercas"]
    minimum = "2.1"
    families = ["AirPush adware"]

    def on_complete(self):
        indicators = [
            "AirpushAdActivity.java",
            "&airpush_url=",
            "getAirpushAppId",
            "Airpush SDK is disabled",
            "api.airpush.com/dialogad/adclick.php",
            "res/layout/airpush_notify.xml"
        ]

        strings = self.get_results("static").get("strings", [])
        for indicator in indicators:
            if self._check_value(indicator, strings):
                self.mark_ioc("string", indicator)

        return self.has_marks()
