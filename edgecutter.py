from burp import IBurpExtender
from burp import IScanIssue
from burp import IScannerCheck
from java.io import PrintWriter
from java.lang import RuntimeException

#
# Globals
#

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):

        # Callbacks and helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Extension name
        self._callbacks.setExtensionName("Edgecu++er -- v1.0")

        # Writers
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Register listeners
        self._callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):

        pass

    def doActiveScan(self, baseRequestResponse, insertionPoint):

        # DEBUG
        self._stdout.println("Edge detection started")

        # TODO: url and parameter output + make a finding (not log entry)
        # TODO: 100k and 1kk symbols (too large)
        # TODO: other detections (see email)
        # TODO: fix \ => %5c encoding that causes lots of 414. For now - partial fix with code check

        # Required lists
        length_nums = [1000,4000,5000,8000,10000,20000]

        # List for responses "aa[..]aa", format {length:res_code}
        stage_1_normal_reslist = dict()
        stage_1_edge_slashes_reslist = dict()

        # Check length to filter out 414 errors
        for length in length_nums:

            len_string = "a" * length

            # Modify the original request
            len_req = insertionPoint.buildRequest(self._helpers.bytesToString(len_string))
            len_reqres = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), len_req)
            len_res = len_reqres.getResponse()
            analyzed_len_res = self._helpers.analyzeResponse(len_res)
            len_res_status = str(analyzed_len_res.getStatusCode())

            # Check for 414 errors
            if len_res_status != "414":
                stage_1_normal_reslist[length] = len_res_status
            else:
                break

        for normal_len,normal_code in sorted(stage_1_normal_reslist.items()):
            for x in range(0,9):

                # Construct the payload
                slashes_payload = ("a" * x + "\\" * normal_len)[:normal_len]

                #Send the request
                slashed_req = insertionPoint.buildRequest(self._helpers.bytesToString(slashes_payload))
                slashed_reqres = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), slashed_req)
                slashed_res = slashed_reqres.getResponse()
                analyzed_slashed_res = self._helpers.analyzeResponse(slashed_res)
                slashed_res_status = str(analyzed_slashed_res.getStatusCode())

                # Check for status code
                if slashed_res_status != normal_code:

                    ###TBD
                    if slashed_res_status != "414":
                    ###TBD
                    
                        self._stdout.println(">> Edge cu++ed! With " + "a" * x + "[" + str(normal_len) + "*\\]")
