# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SendsSMS(Signature):
    name = "sends_sms"
    description = "Sends SMS messages"
    severity = 4
    categories = ["adware"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.telephony.SmsManager.sendTextMessage",
        "android.telephony.SmsManager.sendMultipartTextMessage",
    ]

    def on_call(self, call, process):
        msg = call["arguments"][2]
        if type(msg) == list:
            msg = "".join(msg)

        self.mark_ioc("sms", msg)

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()

class DefaultSMS(Signature):
    name = "default_sms"
    description = "Sets itself as the default SMS application"
    severity = 4
    categories = ["phishing", "spyware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "android.provider.Telephony.SMS_DELIVER"

    def on_complete(self):
        for receiver in self.get_apkinfo("receivers", []):
            if self.indicator in receiver["action"]:
                self.mark_ioc(
                    "receiver", "%s: %s" % (receiver["name"], receiver["action"])
                )

        return self.has_marks()

class CanReadSMS(Signature):
    name = "has_permission_to_read_sms"
    description = "Has permission to read SMS"
    severity = 4
    categories = ["spyware", "phishing"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "READ_SMS"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()

class CanReceiveSMS(Signature):
    name = "has_permission_to_receive_sms"
    description = "Has permission to receive SMS"
    severity = 4
    categories = ["spyware", "phishing"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "RECEIVE_SMS"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()


class CanWriteSMS(Signature):
    name = "has_permission_to_write_sms"
    description = "Has permission to write SMS"
    severity = 4
    categories = ["adware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "WRITE_SMS"

    def on_complete(self):
        if self.check_apk_permission(self.indicator):
            self.mark_ioc("permission", self.indicator)

        return self.has_marks()

class MonitorsSMSMessages(Signature):
    name = "monitors_sms"
    description = "Monitors SMS messages"
    severity = 3
    categories = ["phishing", "spyware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicator = "android.provider.Telephony.SMS_RECEIVED"

    def on_complete(self):
        for receiver in self.get_apkinfo("receivers", []):
            if self.indicator in receiver["action"]:
                self.mark_ioc(
                    "receiver", "%s: %s" % (receiver["name"], receiver["action"])
                )

        return self.has_marks()
