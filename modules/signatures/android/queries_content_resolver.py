# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class QueriesContentResolvers(Signature):
    name = "queries_content_resolvers"
    description = "Queries content resolver (usually for accessing data from other apps)"
    severity = 2
    categories = ["infostealer"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.content.ContentResolver.query",
        "android.content.ContentResolver.insert",
        "android.content.ContentResolver.delete"
    ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()
