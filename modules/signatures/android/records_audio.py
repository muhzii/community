# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RecordsAudio(Signature):
    name = "records_audio"
    description = "Application records audio"
    severity = 4
    categories = ["infostealer"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.media.AudioRecord.startRecording",
        "android.media.MediaRecorder.start"
    ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()

class CanRecordAudio(Signature):
    name = "has_permission_to_record_audio"
    description = "Has permission to record audio"
    severity = 4
    categories = ["spyware", "generic"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "RECORD_AUDIO"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()
