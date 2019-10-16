# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MonitorsBrowserHistory(Signature):
    name = "monitors_browser_history"
    description = "Application monitors browser history"
    severity = 4
    categories = ["infostealer"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.content.ContentResolver.registerContentObserver"
    ]

    indicators = [
        "content://browser/bookmarks",
        "content://com.android.chrome.browser/history"
    ]

    def on_call(self, call, process):
        uri = call["arguments"]["p0"]

        for indicator in self.indicators:
            if indicator in uri:
                self.mark_ioc("content observer", uri)

    def on_complete(self):
        return self.has_marks()

class CanReadBrowserHistory(Signature):
    name = "can_read_browser_history"
    description = "Application has permission to read browser history"
    severity = 4
    categories = ["infostealer"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "READ_HISTORY_BOOKMARKS"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()

class CanWriteToBrowserHistory(Signature):
    name = "can_write_to_browser_history"
    description = "Application has permission to write to browser history"
    severity = 4
    categories = ["adware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "WRITE_HISTORY_BOOKMARKS"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()
