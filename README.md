# IDOR Scanner

IDOR Scanner is a Burp Suite extension written in Python that detects potentially enumerable numeric fields in HTTP requests and responses. It leverages both passive and active scanning techniques to identify potential Insecure Direct Object Reference (IDOR) vulnerabilities.

## Features

### Detection of Numeric Fields
The extension scans for numeric fields in various parts of HTTP requests:

- **URL paths** (e.g., `/user/123/profile`)
- **Query parameters** (e.g., `?id=123`)
- **JSON bodies** (e.g., `{ "id": 123 }`)
- **URL-encoded bodies** (e.g., `id=123&customer_id=456`)
- **Multipart/form-data bodies** (e.g., form fields in file uploads)
- **Response body file references** (detecting filenames such as `1.txt` at the end of responses)

### Passive Scanning
During Burp Suite's passive scanning phase, the extension analyzes outgoing HTTP requests and their responses:

- If numeric fields are found in the request, it generates an issue titled **"Potentially IDOR Endpoint Detected,"** detailing the identified numeric fields.
- If a response body contains a reference to a file named in the format `<number>.txt` (e.g., `2.txt`), this is also flagged as a potential enumeration vector.

### Active Scanning
The extension performs an active scan by modifying detected numeric fields:

1. Sends the original request to establish a baseline response.
2. Modifies detected numeric fields by incrementing their values.
3. Sends modified requests to the target.
4. Collects and reports responses in an issue titled **"IDORs Scanned (Active)"** for further analysis.

### Confirmed IDOR Check
If any modified response returns a `200 OK` and its response size differs from the original, an issue titled **"IDORs Confirmed (Active)"** with high severity is generated, confirming a potential IDOR vulnerability.

### Manual IDOR Scanning via Context Menu
In addition to automatic scanning, a **"Scan IDOR"** option is available when right-clicking on an issue in Burp Suite.

#### How It Works:
1. Right-click on an issue titled **"Potentially IDOR Endpoint Detected."**
2. Select **"Extensions -> Scan IDOR"** from the context menu.
3. The extension extracts numeric fields and performs an active scan, generating **"IDORs Scanned (Active)"** and **"IDORs Confirmed (Active)"** issues as needed.

This allows users to selectively test specific issues without scanning an entire site.

## Integration with Burp Suite

- **Scanner Check:** The extension integrates with both passive and active scanning.
- **Context Menu Integration:** The **"Scan IDOR"** option integrates into the Burp Suite UI, enabling quick manual scans.

## Easy Deployment
Written in Python, the extension is simple to install via the **Extender** tab in Burp Suite.

### Installation

#### Clone the Repository:
```sh
git clone https://github.com/6h4ack/IDOR-Scanner.git
cd IDOR-Scanner
```

#### Load the Extension in Burp Suite:
1. Open **Burp Suite**.
2. Go to the **Extender** tab and click **Add**.
3. Select **Python** as the extension type.
4. Browse to the `IDOR-scanner.py` file in this repository.
5. Click **Next**, then **Done**.

#### Verification:
You should see the message:
```
[IDOR] Extension loaded and active as IDOR Scanner.
```
in the Burp Suite extension output.

## How It Works

### Request and Response Analysis
The extension analyzes:

- **HTTP method**
- **Path**
- **Query string**
- **Request body**
- **Response body** (looking for numeric file references)

### Detection of Numeric Fields
- **Path segments:** Detects numeric segments and filenames in the format `<number>.ext` (e.g., `2.txt`).
- **Query parameters:** Identifies numeric values.
- **JSON bodies:** Detects numeric fields.
- **URL-encoded bodies:** Extracts numeric values from form data.
- **Multipart/form-data bodies:** Identifies numeric values in uploaded form fields.
- **Response bodies:** Checks if a filename (e.g., `1.txt`) is referenced at the end of the response.

### Passive Scanning
- Detects numeric fields in requests and logs a **"Potentially IDOR Endpoint Detected"** issue.
- Scans response bodies for file references matching `<number>.txt`, flagging them as potential IDOR attack vectors.

### Active Scanning
1. Resends the original request.
2. Modifies numeric fields by incrementing their values.
3. Sends modified requests.
4. Compares the responses:
   - If any modified request returns a `200 OK` with a different response size, an **"IDORs Confirmed (Active)"** issue is raised.

### Manual IDOR Scanning (Context Menu)
1. Open the **Issues** tab in Burp Suite.
2. Select a **"Potentially IDOR Endpoint Detected"** issue.
3. Right-click and choose **"Extensions -> Scan IDOR."**
4. The extension will test for IDOR vulnerabilities by modifying numeric fields.

#### If an IDOR vulnerability is found:
- A **"IDORs Scanned (Active)"** issue is generated.
- If a confirmed vulnerability is detected, a **"IDORs Confirmed (Active)"** issue is raised.

## Usage

### Automatic Scanning
Use Burp Suite normally. The extension will automatically analyze requests and responses:

- **Passive Scan:** Detects numeric fields and file references in responses.
- **Active Scan:** Modifies detected numeric values and evaluates responses for IDOR vulnerabilities.

### Reviewing Issues
Go to the **Scanner** tab or the **Issues** list to review detected issues and analyze response variations.

## Extension Name
The extension appears as **"IDOR Scanner"** in Burp Suite.

## Contributing
Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request.
