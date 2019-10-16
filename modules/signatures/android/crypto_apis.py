# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidCryptoAPIs(Signature):
    name = "application_uses_crypto_apis"
    description = "Application uses cryptographic APIs"
    severity = 3
    categories = ["protection", "stealth", "ransomware"]
    authors = ["muhzii"]
    minimum = "2.1"

    indicators = [
        "javax\\.crypto.*",
        "java\\.security.*",
        "org\\.spongycastle.*",
        "org\\.bouncycastle.*"
    ]

    def on_call(self, call, process):
        if any(self._check_value(p, call["class"]) for p in self.indicators):
            self.mark_call()

    def on_complete(self):
        for indicator in self.indicators:
            match = self.check_apk_api_call(indicator)
            if match:
                self.mark_ioc("API call", match)

        return self.has_marks()
