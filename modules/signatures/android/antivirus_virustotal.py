# Copyright (C) Check Point Software Technologies LTD.
# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class KnownVirustotal(Signature):
    name = "android_antivirus_virustotal"
    description = "File has been identified by at least one AntiVirus on VirusTotal as malicious (Osint)"
    severity = 2
    categories = ["antivirus"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.1"

    av_whitelist = [
        "Kingsoft",
        "NANO-Antivirus",
        "F-Prot",
        "McAfee-GW-Edition",
        "McAfee",
        "MicroWorld-eScan",
        "AVG",
        "CAT-QuickHeal",
        "F-Secure",
        "Emsisoft",
        "VIPRE",
        "BitDefender",
        "Fortinet",
        "Commtouch",
        "TrendMicro-HouseCall",
        "DrWeb",
        "Comodo", "Kaspersky",
        "AntiVir",
        "Avast",
        "Sophos",
        "Ikarus",
        "GData",
        "ESET-NOD32",
    ]

    def on_complete(self):
        

        sign_cnt = 0
        for engine, signature in self.get_virustotal().get("scans", {}).items():
            if engine in self.av_whitelist and signature["detected"]:
                self.mark_ioc(engine, signature["result"])
                sign_cnt += 1

        return sign_cnt > 0
