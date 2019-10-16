# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AbortBroadcast(Signature):
    name = "aborts_broadcast"
    description = "Application aborted broadcast receiver (usually for hiding" \
        "system events from other apps)."
    severity = 4
    categories = ["stealth"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.content.BroadcastReceiver.abortBroadcast"
    ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()
