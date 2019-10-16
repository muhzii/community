# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidFingerprint(Signature):
    name = "fingerprint"
    description = "Application detects system and device information"
    severity = 1
    categories = ["fingerprint", "generic"]
    authors = ["muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "android.telephony.TelephonyManager.getDeviceId",
        "android.telephony.TelephonyManager.getSubscriberId",
        "android.telephony.TelephonyManager.getImei",
        "android.telephony.TelephonyManager.getNetworkOperatorName",
        "android.telephony.TelephonyManager.getSimOperatorName",
        "android.telephony.TelephonyManager.getNetworkCountryIso",
        "android.telephony.TelephonyManager.getSimCountryIso",
        "android.telephony.TelephonyManager.getNetworkOperator",
        "android.telephony.TelephonyManager.getSimSerialNumber",
        "android.telephony.TelephonyManager.getVoiceMailNumber",
        "android.net.wifi.WifiInfo.getMacAddress",
        "android.provider.Settings.Secure.getString"
    ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()
