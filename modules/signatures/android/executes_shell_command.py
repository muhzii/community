# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidShellCommands(Signature):
    name = "executes_shell_command"
    description = "Application Executed Shell Command"
    severity = 4
    categories = ["shellcode"]
    authors = ["Check Point Software Technologies LTD", "muhzii"]
    minimum = "2.1"

    filter_apinames = [
        "java.lang.Runtime.exec",
        "java.lang.ProcessBuilder.start"
    ]

    def on_call(self, call, process):
        if "exec" in call["api"]:
            cmd = call["arguments"]["p0"]
        else:
            cmd = call["this"]["command"]

        self.mark_ioc("cmdline", cmd)

    def on_complete(self):
        for api in self.filter_apinames:
            if self.check_apk_api_call(api):
                self.mark_ioc("API call", api)

        return self.has_marks()
