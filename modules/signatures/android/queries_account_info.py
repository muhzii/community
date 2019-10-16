# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AccountInfo(Signature):
    name = "queries_account_info"
    description = "Queries accounts information"
    severity = 2
    categories = ["ifnostealer"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.1"

    filter_apinames = [
        "android.accounts.AccountManager.getAccountsByType"
    ]

    def on_call(self, call, process):
        self.mark_ioc("queried_account", call["arguments"]["p0"])
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()

