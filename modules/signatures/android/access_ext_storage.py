# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CanAccessExternalStorage(Signature):
    name = "can_access_external_storage"
    description = "Has permission to access external storage"
    severity = 3
    categories = ["spreading"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicators = [
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE"
    ]

    def on_complete(self):
        for indicator in self.indicators:
            if self.check_apk_permission(indicator):
                self.mark_ioc("permission", indicator)

        return self.has_marks()

class AccessesExternalStorageLocation(Signature):
    name = "can_access_external_storage"
    description = "Accesses external storage location"
    severity = 3
    categories = ["spreading"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.os.Environment.getExternalStorageState",
        "android.os.Environment.getExternalStorageDirectory"
    ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()