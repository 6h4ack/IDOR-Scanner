# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, IScanIssue, IContextMenuFactory
import re, json, random, time, threading

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

# Import Swing classes for the context menu
from javax.swing import JMenuItem

#
# Helper Functions
#

def is_numeric(value):
    """
    Returns True if the value (converted to Unicode) represents an integer (positive or negative).
    """
    try:
        if not isinstance(value, unicode):
            value = unicode(value, 'utf-8', errors='ignore')
    except NameError:
        value = str(value)
    return re.match(r"^-?\d+$", value, re.UNICODE) is not None

def extract_request_parts(request_str):
    """
    Extracts from the HTTP request:
      - HTTP Method
      - Path
      - Query string
      - Body

    Assumes that the separator is CRLF (\r\n).
    """
    parts = request_str.split("\r\n\r\n", 1)
    headers_part = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = headers_part.splitlines()
    if not lines:
        return None, None, None, None
    request_line = lines[0]
    try:
        method, url, protocol = request_line.split()
    except Exception:
        return None, None, None, None
    parsed = urlparse.urlparse(url)
    path = parsed.path
    query = parsed.query
    return method, path, query, body

def analyze_path(path):
    """
    Returns a list of tuples (index, segment value) for numeric segments in the path.
    Now it also detects segments in the format <number>.<ext> (e.g., "2.txt").
    """
    segments = path.split("/")
    candidates = []
    for i, segment in enumerate(segments):
        if segment:
            if is_numeric(segment):
                candidates.append((i, segment))
            else:
                m = re.match(r'^(\d+)(\.\w+)$', segment)
                if m:
                    candidates.append((i, segment))
    return candidates

def analyze_query(query):
    """
    Returns a list of tuples (parameter, value) for numeric values in the query string.
    """
    candidates = []
    params = urlparse.parse_qs(query)
    for key, values in params.items():
        for value in values:
            if is_numeric(value):
                candidates.append((key, value))
    return candidates

def analyze_json_body(body):
    """
    Returns a list of tuples (key, value) for numeric values in a simple JSON body (dictionary).
    """
    candidates = []
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key, value in data.items():
                if is_numeric(value):
                    candidates.append((key, value))
    except Exception:
        pass
    return candidates

def analyze_urlencoded_body(body):
    """
    Returns a list of tuples (parameter, value) for numeric values in a URL-encoded body.
    """
    candidates = []
    try:
        params = urlparse.parse_qs(body)
        for key, values in params.items():
            for value in values:
                if is_numeric(value):
                    candidates.append((key, value))
    except Exception:
        pass
    return candidates

def analyze_multipart_body(body, boundary):
    """
    Returns a list of tuples (field, value) for numeric values in a multipart/form-data body.
    """
    candidates = []
    sep = "--" + boundary
    parts = body.split(sep)
    for part in parts:
        part = part.strip()
        if not part or part == "--":
            continue
        if "\r\n\r\n" in part:
            header_part, value = part.split("\r\n\r\n", 1)
            value = value.strip()
            m = re.search(r'name="([^"]+)"', header_part)
            if m:
                field_name = m.group(1)
                if is_numeric(value):
                    candidates.append((field_name, value))
    return candidates

def update_path(original_path, index_to_update, new_value):
    """
    Replaces the numeric segment in the path at the specified index with new_value.
    If the segment is in the format <number>.<ext>, preserves the extension.
    Returns the reconstructed path.
    """
    segments = original_path.split("/")
    old_segment = segments[index_to_update]
    m = re.match(r'^(\d+)(\.\w+)$', old_segment)
    if m:
        ext = m.group(2)
        segments[index_to_update] = str(new_value) + ext
    else:
        segments[index_to_update] = str(new_value)
    return "/".join(segments)

def update_query(original_query, param_to_update, new_value):
    """
    Updates a numeric parameter in the query string.
    If the parameter appears multiple times, all instances are updated.
    """
    try:
        new_value_str = str(new_value)
        parsed = urlparse.parse_qs(original_query, keep_blank_values=True)
        if param_to_update in parsed:
            parsed[param_to_update] = [new_value_str for _ in parsed[param_to_update]]
        new_query_parts = []
        for key, vals in parsed.items():
            for v in vals:
                new_query_parts.append("{}={}".format(key, v))
        new_query = "&".join(new_query_parts)
        return new_query
    except Exception as e:
        return original_query

def update_json_body(original_body, key_to_update, new_value):
    """
    Updates a numeric value in a JSON body (simple dictionary).
    Returns the new JSON body as a string.
    """
    try:
        data = json.loads(original_body)
        if isinstance(data, dict) and key_to_update in data:
            data[key_to_update] = int(new_value)
        return json.dumps(data)
    except Exception:
        return original_body

def update_urlencoded_body(original_body, param_to_update, new_value):
    """
    Updates a numeric parameter in the URL-encoded body.
    If the parameter appears multiple times, all instances are updated.
    """
    try:
        new_value_str = str(new_value)
        parsed = urlparse.parse_qs(original_body, keep_blank_values=True)
        if param_to_update in parsed:
            parsed[param_to_update] = [new_value_str for _ in parsed[param_to_update]]
        new_parts = []
        for key, vals in parsed.items():
            for v in vals:
                new_parts.append("{}={}".format(key, v))
        new_body = "&".join(new_parts)
        return new_body
    except Exception as e:
        return original_body

def update_multipart_body(original_body, boundary, param_to_update, new_value):
    """
    Updates a numeric parameter in the multipart/form-data body.
    If the parameter appears multiple times, all instances are actualizadas.
    Returns the new multipart body as a string.
    """
    sep = "--" + boundary
    parts = original_body.split(sep)
    new_parts = []
    for part in parts:
        if part.strip() == "" or part.strip() == "--":
            new_parts.append(part)
            continue
        if "\r\n\r\n" in part:
            header_part, value = part.split("\r\n\r\n", 1)
            m = re.search(r'name="([^"]+)"', header_part)
            if m and m.group(1) == param_to_update and is_numeric(value.strip()):
                new_value_str = str(new_value)
                part = header_part + "\r\n\r\n" + new_value_str + "\r\n"
        new_parts.append(part)
    new_body = sep.join(new_parts)
    return new_body

def rebuild_request_with_updates(helpers, original_request, method, original_path, new_query, new_body):
    """
    Rebuilds the HTTP request (headers + body) using:
      - the modified path (if applicable)
      - the modified query (if applicable)
      - the modified body (if applicable)
    """
    analyzedRequest = helpers.analyzeRequest(original_request)
    headers = list(analyzedRequest.getHeaders())
    # First line: "METHOD /path?query HTTP/1.1"
    first_line = headers[0]
    parts = first_line.split(" ", 2)
    if len(parts) == 3:
        http_protocol = parts[2]
        new_path_query = original_path
        if new_query:
            new_path_query += "?" + new_query
        headers[0] = "{} {} {}".format(method, new_path_query, http_protocol)
    new_request = helpers.buildHttpMessage(headers, new_body)
    return new_request

#
# Issue Classes
#

class EnumerableIssue(IScanIssue):
    def __init__(self, httpMessage, helpers, detail):
        self._httpMessage = httpMessage
        self._helpers = helpers
        self._detail = detail

    def getUrl(self):
        request_info = self._helpers.analyzeRequest(self._httpMessage)
        return request_info.getUrl()

    def getIssueName(self):
        return "Potentially IDOR Endpoint Detected"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return "The request contains numeric fields that could be vulnerable to enumeration attacks."

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self._httpMessage]

    def getHttpService(self):
        return self._httpMessage.getHttpService()

class IDORsScannedIssue(IScanIssue):
    def __init__(self, httpMessages, helpers, detail):
        self._httpMessages = httpMessages
        self._helpers = helpers
        self._detail = detail

    def getUrl(self):
        if self._httpMessages and len(self._httpMessages) > 0:
            request_info = self._helpers.analyzeRequest(self._httpMessages[0])
            return request_info.getUrl()
        return None

    def getIssueName(self):
        return "IDORs Scanned (Active)"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return ("The request was re-sent to analyze possible enumerable numeric fields, "
                "which may indicate IDOR vulnerabilities.")

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        if self._httpMessages and len(self._httpMessages) > 0:
            return self._httpMessages[0].getHttpService()
        return None

class IDORsConfirmedIssue(IScanIssue):
    def __init__(self, httpMessages, helpers, detail):
        self._httpMessages = httpMessages
        self._helpers = helpers
        self._detail = detail

    def getUrl(self):
        if self._httpMessages and len(self._httpMessages) > 0:
            request_info = self._helpers.analyzeRequest(self._httpMessages[0])
            return request_info.getUrl()
        return None

    def getIssueName(self):
        return "IDORs Confirmed (Active)"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return ("One or more modified requests returned a 200 OK response and the response size "
                "differs from the original response, confirming a possible IDOR vulnerability.")

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        if self._httpMessages and len(self._httpMessages) > 0:
            return self._httpMessages[0].getHttpService()
        return None

#
# BurpExtender implementing IScannerCheck and IContextMenuFactory
#

class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        """
        This method is called by Burp Suite when the extension is loaded.
        It registers the extension as a ScannerCheck and as a Context Menu Factory.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IDOR Scanner")
        # Register as a ScannerCheck
        callbacks.registerScannerCheck(self)
        # Register as a Context Menu Factory
        callbacks.registerContextMenuFactory(self)
        # Optional dictionary to map candidate fields
        self._candidateMapping = {}
        print "[IDOR] Extension loaded and active as IDOR Scanner."

    def doPassiveScan(self, baseRequestResponse):
        """
        Performs a passive scan on the given request/response.
        It analyzes the request for numeric fields in the URL path, query string, and body
        (JSON, URL-encoded or multipart/form-data). Additionally, if the response exists,
        it checks if at the end of the content a file name in the format "<number>.txt" is found.
        """
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        method, path, query, body = extract_request_parts(request_str)
        if method is None:
            return None

        path_candidates = analyze_path(path)
        query_candidates = analyze_query(query)

        analyzedRequest = self._helpers.analyzeRequest(request)
        headers = analyzedRequest.getHeaders()
        content_type = ""
        for header in headers:
            if header.lower().startswith("content-type:"):
                content_type = header.split(":", 1)[1].strip().lower()
                break

        if "application/json" in content_type:
            body_candidates = analyze_json_body(body)
        elif "application/x-www-form-urlencoded" in content_type:
            body_candidates = analyze_urlencoded_body(body)
        elif "multipart/form-data" in content_type:
            m = re.search(r'boundary=(.+)', content_type)
            boundary = m.group(1) if m else None
            if boundary:
                body_candidates = analyze_multipart_body(body, boundary)
            else:
                body_candidates = []
        else:
            body_candidates = []

        total_candidates = len(path_candidates) + len(query_candidates) + len(body_candidates)

        # Check for a response file candidate (e.g., "1.txt" at the end of response body)
        file_candidate = None
        response_body = ""
        if baseRequestResponse.getResponse():
            response_body = self._helpers.bytesToString(baseRequestResponse.getResponse())
            m = re.search(r'(\d+\.txt)\s*$', response_body)
            if m:
                file_candidate = m.group(1)

        # If no numeric candidates and no file candidate are found, do not create an issue.
        if total_candidates == 0 and not file_candidate:
            return None

        marker = '<!--|||NUM_CANDIDATES:{}|||-->'.format(total_candidates)
        detail = marker
        detail += "<b>Potentially enumerable numeric fields detected: {} </b><br><br>".format(total_candidates)
        if path_candidates:
            detail += "<b>Path segments:</b><br>"
            for pos, val in path_candidates:
                detail += "Position {}: {}<br>".format(pos, val)
            detail += "<br>"
        if query_candidates:
            detail += "<b>Query parameters:</b><br>"
            for key, val in query_candidates:
                detail += "{}: {}<br>".format(key, val)
            detail += "<br>"
        if body_candidates:
            detail += "<b>Body parameters:</b><br>"
            for key, val in body_candidates:
                detail += "{}: {}<br>".format(key, val)
            detail += "<br>"
        if file_candidate:
            detail += "<b>Response file candidate found:</b> {}<br>".format(file_candidate)

        issue = EnumerableIssue(baseRequestResponse, self._helpers, detail)
        return [issue]

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """
        Performs an active scan by modifying numeric fields (in the path, query, and body)
        and re-sending the request to detect potential IDOR vulnerabilities.
        Generates "IDORs Scanned (Active)" and, if applicable, "IDORs Confirmed (Active)" issues.
        This method is used by Burp's active scanner.
        """
        messages = []
        modifications = []  # Stores tuples: (description of candidate, modified message)
        originalMessage = baseRequestResponse
        httpService = originalMessage.getHttpService()
        request_str = self._helpers.bytesToString(originalMessage.getRequest())
        method, path, query, body = extract_request_parts(request_str)
        if method is None:
            return None

        path_candidates = analyze_path(path)
        query_candidates = analyze_query(query)

        analyzedRequest = self._helpers.analyzeRequest(originalMessage.getRequest())
        headers = analyzedRequest.getHeaders()
        content_type = ""
        for header in headers:
            if header.lower().startswith("content-type:"):
                content_type = header.split(":", 1)[1].strip().lower()
                break

        if "application/json" in content_type:
            body_candidates = analyze_json_body(body)
        elif "application/x-www-form-urlencoded" in content_type:
            body_candidates = analyze_urlencoded_body(body)
        elif "multipart/form-data" in content_type:
            m = re.search(r'boundary=(.+)', content_type)
            boundary = m.group(1) if m else None
            if boundary:
                body_candidates = analyze_multipart_body(body, boundary)
            else:
                body_candidates = []
        else:
            body_candidates = []

        if not (path_candidates or query_candidates or body_candidates):
            return None

        # Re-send the original request to obtain the base response
        freshOriginalMessage = self.safe_make_request(httpService, originalMessage.getRequest())
        if not freshOriginalMessage:
            return None
        messages.append(freshOriginalMessage)
        orig_response = freshOriginalMessage.getResponse()
        orig_length = len(orig_response)
        time.sleep(0.05)

        # For each numeric parameter in the PATH
        for (i, val) in path_candidates:
            try:
                new_val = int(re.search(r'\d+', val).group()) + 1
            except:
                continue
            candidate_desc = "Path segment at position {}: {} -> {}".format(i, val, new_val)
            new_path = update_path(path, i, new_val)
            new_req = rebuild_request_with_updates(self._helpers, originalMessage.getRequest(), method, new_path, query, body)
            new_req = self.add_unique_headers(new_req)
            freshMessage = self.safe_make_request(httpService, new_req)
            if freshMessage:
                messages.append(freshMessage)
                modifications.append((candidate_desc, freshMessage))
            time.sleep(0.05)

        # For each numeric parameter in the QUERY
        for (param, val) in query_candidates:
            try:
                new_val = int(val) + 1
            except:
                continue
            candidate_desc = "Query parameter '{}' changed from {} to {}".format(param, val, new_val)
            new_query = update_query(query, param, new_val)
            new_req = rebuild_request_with_updates(self._helpers, originalMessage.getRequest(), method, path, new_query, body)
            new_req = self.add_unique_headers(new_req)
            freshMessage = self.safe_make_request(httpService, new_req)
            if freshMessage:
                messages.append(freshMessage)
                modifications.append((candidate_desc, freshMessage))
            time.sleep(0.05)

        # For each numeric parameter in the BODY (JSON, URL-encoded or multipart)
        for (key, val) in body_candidates:
            try:
                new_val = int(val) + 1
            except:
                continue
            if "application/json" in content_type:
                candidate_desc = "JSON body field '{}' changed from {} to {}".format(key, val, new_val)
                new_body = update_json_body(body, key, new_val)
            elif "application/x-www-form-urlencoded" in content_type:
                candidate_desc = "Body parameter '{}' changed from {} to {}".format(key, val, new_val)
                new_body = update_urlencoded_body(body, key, new_val)
            elif "multipart/form-data" in content_type:
                candidate_desc = "Multipart form-data field '{}' changed from {} to {}".format(key, val, new_val)
                new_body = update_multipart_body(body, boundary, key, new_val)
            else:
                continue
            new_req = rebuild_request_with_updates(self._helpers, originalMessage.getRequest(), method, path, query, new_body)
            new_req = self.add_unique_headers(new_req)
            freshMessage = self.safe_make_request(httpService, new_req)
            if freshMessage:
                messages.append(freshMessage)
                modifications.append((candidate_desc, freshMessage))
            time.sleep(0.05)

        # Generate the "IDORs Scanned (Active)" issue
        total_candidates = len(path_candidates) + len(query_candidates) + len(body_candidates)
        marker = '<!--|||NUM_CANDIDATES:{}|||-->'.format(total_candidates)
        scanned_detail = marker
        scanned_detail += "<b>Potentially enumerable numeric fields (Active Scan): {} </b><br><br>".format(total_candidates)
        if path_candidates:
            scanned_detail += "<b>Path segments:</b><br>"
            for pos, val in path_candidates:
                scanned_detail += "Position {}: {}<br>".format(pos, val)
            scanned_detail += "<br>"
        if query_candidates:
            scanned_detail += "<b>Query parameters:</b><br>"
            for key, val in query_candidates:
                scanned_detail += "{}: {}<br>".format(key, val)
            scanned_detail += "<br>"
        if body_candidates:
            scanned_detail += "<b>Body parameters:</b><br>"
            for key, val in body_candidates:
                scanned_detail += "{}: {}<br>".format(key, val)
            scanned_detail += "<br>"

        issues = []
        scanned_issue = IDORsScannedIssue(messages, self._helpers, scanned_detail)
        issues.append(scanned_issue)

        # Check each modified response to confirm an IDOR vulnerability:
        confirmed_details = ""
        confirmed_messages = [freshOriginalMessage]  # include the original response
        for candidate_desc, mod_msg in modifications:
            analyzedResponse = self._helpers.analyzeResponse(mod_msg.getResponse())
            status_code = analyzedResponse.getStatusCode()
            mod_length = len(mod_msg.getResponse())
            if status_code == 200 and mod_length != orig_length:
                confirmed_details += candidate_desc + " - Response size: {} -> {}<br>".format(orig_length, mod_length)
                confirmed_messages.append(mod_msg)
        if confirmed_details:
            confirmed_detail = "<b>IDOR Confirmed:</b><br>" + confirmed_details
            confirmed_issue = IDORsConfirmedIssue(confirmed_messages, self._helpers, confirmed_detail)
            issues.append(confirmed_issue)

        return issues if issues else None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """
        Determines if two issues are duplicates.
        If the issues have the same name, they are considered duplicates.
        """
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

    #
    # Auxiliary methods for sending modified requests
    #

    def safe_make_request(self, httpService, request):
        """
        Wraps the call to makeHttpRequest in a try/except block.
        """
        try:
            response = self._callbacks.makeHttpRequest(httpService, request)
            return response
        except Exception as e:
            return None

    def add_unique_headers(self, request):
        """
        Adds headers to distinguish scanning requests:
          - X-Unique-ID: random value
          - X-Scan-Request: true
        """
        analyzedRequest = self._helpers.analyzeRequest(request)
        headers = list(analyzedRequest.getHeaders())
        request_line = headers[0]
        header_rest = headers[1:]
        unique_header = "X-Unique-ID: {}".format(random.randint(100000, 999999))
        scan_header = "X-Scan-Request: true"
        header_rest.append(unique_header)
        header_rest.append(scan_header)
        body_offset = analyzedRequest.getBodyOffset()
        full_req_str = self._helpers.bytesToString(request)
        body = full_req_str[body_offset:]
        new_request = self._helpers.buildHttpMessage([request_line] + header_rest, body)
        return new_request

    #
    # Methods for the context menu (IContextMenuFactory)
    #
    # Note: The parallel processing (launching individual threads) is applied only when the Scan IDOR button is used.
    # When active scanning is triggered automatically by Burp, doActiveScan runs sequentially.
    #

    def createMenuItems(self, invocation):
        """
        Creates a context menu item when right-clicking on an issue.
        The menu is added only if at least one issue of type
        "Potentially IDOR Endpoint Detected" is selected.
        """
        selectedIssues = invocation.getSelectedIssues()
        if not selectedIssues or len(selectedIssues) == 0:
            return None
        valid = False
        for issue in selectedIssues:
            if issue.getIssueName() == "Potentially IDOR Endpoint Detected":
                valid = True
                break
        if not valid:
            return None
        menuList = []
        menuItem = JMenuItem("Scan IDOR", actionPerformed=lambda event: self.scanSelectedIDOR(invocation))
        menuList.append(menuItem)
        return menuList

    def scanSelectedIDOR(self, invocation):
        """
        For each selected issue of type "Potentially IDOR Endpoint Detected",
        launches an individual thread to execute the active scan (doActiveScan).
        This parallelization is applied only when triggered manually via the Scan IDOR button.
        """
        selectedIssues = invocation.getSelectedIssues()
        if not selectedIssues:
            return
        # Launch a separate thread for each issue
        for issue in selectedIssues:
            if issue.getIssueName() == "Potentially IDOR Endpoint Detected":
                threading.Thread(target=self.process_issue, args=(issue,)).start()

    def process_issue(self, issue):
        """
        Processes an individual issue by executing doActiveScan.
        Errors are caught to ensure one issue failure does not affect the others.
        """
        try:
            messages = issue.getHttpMessages()
            if messages and len(messages) > 0:
                baseRequestResponse = messages[0]
                newIssues = self.doActiveScan(baseRequestResponse, None)
                if newIssues:
                    for newIssue in newIssues:
                        self._callbacks.addScanIssue(newIssue)
        except Exception as e:
            print("Error processing issue: {}".format(e))
