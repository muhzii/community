# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AcquiresWakeLock(Signature):
    name = "acquires_wakelock"
    description = "Acquires wake lock"
    severity = 2
    categories = ["generic"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.os.PowerManager$WakeLock.acquire"
    ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()
