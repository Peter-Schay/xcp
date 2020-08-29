# Copyright (c) 2020 NetApp Inc. - All Rights Reserved
# This sample code is provided AS IS, with no support or warranties of any kind, including but not limited to warranties of merchantability or fitness of any kind, expressed or implied.
#
# Utility to exclude directories from the scanner

# Updates: 
#   29 August 2020 - created (Peter Schay)
#
# USAGE
# The script dynamically adds a hook to the scanner, for any xcp command.  
# The hook will test the exclude condition expression and skip all dirs for which the condition is true.
# The exclude condition uses the same variables and syntax as a -match or -fmt expresssion.
# For example this command will run the scan and skip any directory that's deeper than 2 or named "skipme":
#
# xcp diag -run exclude.py 'depth > 2 or name == "skipme"' scan localhost:/usr/lib

import rd
import scan
import sched
import client
import report
import time
import xcp
import xfilter
import sys

nExcluded = 0

def run(argv):
    # The first argument after "xcp diag -run exclude.py" is argv[1]
    if len(argv) > 1:
        s = argv[1]
        try:
            filter = xfilter.Filter(s, sched.engine.osCache, when=time.time())
        except Exception as e:
            raise sched.ShortError("Error in filter <{}>: {}".format(s, e))
        sys.stderr.write("excluding dirs which match {}\n".format(s))
    else:
        sys.stderr.write("expected condition expression for paths to exclude\n")
        sys.exit(1)

    class Exclude(sched.SimpleTask):
        def gRun(self, d):
            global nExcluded
            path = d.getPath()
            if filter.check(d):
                sys.stderr.write("*** skipping {}\n".format(d))
                nExcluded += 1
                raise rd.ESkipDir
            if 0:
                yield # Required to make this a python generator

    origInit = scan.ScanTree.__init__
    def customInit(*args, **kwargs):
        hooks = kwargs.get("hooks", {})
        hooks[rd.Hooks.StartDir] = Exclude
        kwargs["hooks"] = hooks
        return origInit(*args, **kwargs)
    scan.ScanTree.__init__ = customInit

    print("argv {}".format(argv))
    newargv = ["xcp"] + argv[2:]
    print("newargv {}".format(newargv))
    xcp.xcp(newargv)
    sys.stderr.write("excluded {} dirs\n".format(nExcluded))
