# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class APKProtect(Signature):
    name = "APKProtect_packer"
    description = "Application uses APKProtect packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    indicators = [".*libAPKProtect.so", ".*libbaiduprotect.so"]

    def on_complete(self):
        for indicator in self.indicators:
            match = self.check_apk_file(indicator, True)
            if match:
                self.mark_ioc("packer", match)

        return self.has_marks()

class Bangcle(Signature):
    name = "Bangcle_packer"
    description = "Application uses Bangcle packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    indicators = [
        "libapkprotect2.so",
        "assets/bangcleplugin/container.dex",
        "bangcleclasses.jar",
        "libsecexe.so",
        "bangcle_classes.jar",
        "libsecmain"
    ]

    def on_complete(self):
        for indicator in self.indicators:
            match = self.check_apk_file(".*%s.*" % indicator, True)
            if match:
                self.mark_ioc("packer", match)

        return self.has_marks()

class LIAPP(Signature):
    name = "LIAPP_packer"
    description = "Application uses LIAPP packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    def on_complete(self):
        match = self.check_apk_file(".*/LIAPPEgg.*", True)
        if match:
            self.mark_ioc("packer", match)

        return self.has_marks()

class Qihoo(Signature):
    name = "Qihoo_packer"
    description = "Application uses Qihoo packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    def on_complete(self):
        match = self.check_apk_file(".*libprotectClass.so", True)
        if match:
            self.mark_ioc("packer", match)

        return self.has_marks()

class NQShield(Signature):
    name = "NQShield_packer"
    description = "Application uses NQShield packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    indicators = ["libNSaferOnly.so", "nqshield", "nqshell"]

    def on_complete(self):
        for indicator in self.indicators:
            match = self.check_apk_file(".*%s.*" % indicator, True)
            if match:
                self.mark_ioc("packer", match)

        return self.has_marks()

class Tencent(Signature):
    name = "Tencent_packer"
    description = "Application uses Tencent packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    def on_complete(self):
        match = self.check_apk_file(".*libshell.so", True)
        if match:
            self.mark_ioc("packer", match)

        return self.has_marks()

class Ijiami(Signature):
    name = "Ijiami_packer"
    description = "Application uses Ijiami packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    def on_complete(self):
        match = self.check_apk_file(".*ijiami.dat", True)
        if match:
            self.mark_ioc("packer", match)

        return self.has_marks()

class Naga(Signature):
    name = "Naga_packer"
    description = "Application uses Naga packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    def on_complete(self):
        match = self.check_apk_file(".*libddog.so", True)
        if match:
            self.mark_ioc("packer", match)

        return self.has_marks()

class Alibaba(Signature):
    name = "Alibaba_packer"
    description = "Application uses Alibaba packer"
    severity = 3
    categories = ["packer"]
    authors = ["ofercas"]
    minimum = "2.1"

    def on_complete(self):
        match = self.check_apk_file(".*libmobisec.so", True)
        if match:
            self.mark_ioc("packer", match)

        return self.has_marks()
