# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CanChangeWifiState(Signature):
    name = "can_change_wifi_state"
    description = "Application may try to change WiFi state"
    severity = 3
    categories = ["spreading"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "CHANGE_WIFI_STATE"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()
