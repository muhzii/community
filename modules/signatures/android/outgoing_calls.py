# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MonitorsOutgoingCalls(Signature):
    name = "monitors_outgoing_calls"
    description = "Monitors outgoing calls"
    severity = 3
    categories = ["phishing", "spyware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "android.intent.action.NEW_OUTGOING_CALL"

    def on_complete(self):
        for receiver in self.get_apkinfo("receivers", []):
            if self.indicator in receiver["action"]:
                self.mark_ioc(
                    "receiver", "%s: %s" % (receiver["name"], receiver["action"])
                )

        return self.has_marks()

class CanPerformCalls(Signature):
    name = "has_permission_to_perform_calls"
    description = "Has permission to perform calls in the background"
    severity = 4
    categories = ["adware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "CALL_PHONE"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()

class CanProcessOutgoingCalls(Signature):
    name = "has_permission_to_process_calls"
    description = "Has permission to redirect, block or monitor outgoing calls"
    severity = 3
    categories = ["adware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "PROCESS_OUTGOING_CALLS"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()

class CanReadCallLogs(Signature):
    name = "has_permission_to_read_call_logs"
    description = "Has permission to read call logs"
    severity = 3
    categories = ["adware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "READ_CALL_LOG"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()
