# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class KnownVirustotalThreshold(Signature):
    name = "android_antivirus_virustotal_threshold"
    description = "File has been identified by more the 10 AntiVirus on VirusTotal as malicious (Osint)"
    severity = 4
    categories = ["antivirus"]
    authors = ["idanr1986"]
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
        "Comodo",
        "Kaspersky",
        "AntiVir",
        "Avast",
        "Sophos",
        "Ikarus",
        "GData",
        "ESET-NOD32"
    ]

    def on_complete(self):
        cnt_threshold = 10

        av_cnt = 0
        results = self.get_virustotal()
        if results.get("scans"):
            for engine, signature in results["scans"].items():
                if engine in self.av_whitelist:
                    if signature["detected"]:
                        self.mark_ioc(engine, signature["result"])
                        av_cnt = av_cnt + 1

        return av_cnt >= cnt_threshold
