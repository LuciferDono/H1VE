# Cloud, Mobile & IoT Security Reference

## Table of Contents
1. [AWS Security](#aws-security)
2. [Azure Security](#azure-security)
3. [GCP Security](#gcp-security)
4. [Kubernetes & Container Security](#kubernetes--container-security)
5. [Android Security Testing](#android-security-testing)
6. [iOS Security Testing](#ios-security-testing)
7. [Serverless Security](#serverless-security)
8. [IoT Security](#iot-security)

---

## AWS Security

### S3 Bucket Misconfiguration

Check public access: `aws s3 ls s3://target-bucket --no-sign-request`

Common naming: target-com, target-backup, target-dev, target-staging, target-assets, target-logs

Tools: s3scanner, cloud_enum

Test permissions: get-bucket-acl, get-bucket-policy, list-objects, cp (write test)

### SSRF to AWS Metadata

IMDSv1 (no token): `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME`

IMDSv2 (token required): PUT request to get token, then use in subsequent requests.

After obtaining creds: `aws sts get-caller-identity`, enumerate S3/IAM/etc.

### IAM Misconfiguration

Tools: Pacu (exploitation), ScoutSuite (auditing), Prowler (assessment)

---

## Azure Security

### Blob Storage

Check public: `https://account.blob.core.windows.net/container?restype=container&comp=list`

Metadata: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires Metadata:true header)

### Azure AD

Tenant enum: `https://login.microsoftonline.com/target.com/.well-known/openid-configuration`

User enumeration via login response differences.

---

## GCP Security

Bucket check: `https://storage.googleapis.com/target-bucket`

Metadata: `http://metadata.google.internal/computeMetadata/v1/` (requires Metadata-Flavor:Google header)

Token theft: `/instance/service-accounts/default/token`

---

## Kubernetes & Container Security

### Exposed API Server

Test unauthenticated access to: 6443 (API), 10250 (Kubelet), 2379 (etcd), 10255 (Kubelet RO)

### RBAC Exploitation

Check permissions: `kubectl auth can-i --list`

Dangerous permissions: create pods, escalate/bind roles, list secrets.

Secrets are only base64-encoded by default, not encrypted.

### Container Escape

Check: `/proc/1/cgroup`, `/.dockerenv`, `capsh --print`

Docker socket: if `/var/run/docker.sock` accessible, full host compromise possible.

---

## Android Security Testing

### APK Analysis

Decompile: `apktool d target.apk`, `jadx target.apk`

Search: api_key, secret, password, token, firebase, http/https URLs

Check AndroidManifest.xml: exported components, allowBackup, debuggable, cleartext traffic, deep links

### Runtime Analysis

Frida: dynamic instrumentation, certificate pinning bypass

Objection: `android sslpinning disable`, `android root disable`

### Common Vulnerabilities

Exported components, insecure storage (SharedPreferences, SQLite), cert pinning bypass, deep link hijacking, WebView JS interface, backup extraction, tapjacking, clipboard leakage, hardcoded secrets.

---

## iOS Security Testing

### IPA Analysis

Extract and check Info.plist: URL schemes, ATS exceptions, permissions

Search binary: `strings App | grep -iE "api|key|secret|token|password"`

class-dump for Objective-C headers.

### Runtime Analysis

Frida/Objection: `ios sslpinning disable`, `ios keychain dump`, `ios cookies get`

### Common Vulnerabilities

Insecure Keychain, URL scheme hijacking, pasteboard leakage, snapshot caching, cert pinning bypass, insecure local storage, jailbreak detection bypass, universal link misconfiguration.

---

## Serverless Security

AWS Lambda: event injection, over-permissive IAM, env variable secrets, shared /tmp, dependency vulns.

Azure Functions / GCP Cloud Functions: injection via HTTP triggers, over-permissive service account, exposed function URLs, SSRF to metadata.

---

## IoT Security

Attack vectors: default credentials, unencrypted comms (HTTP, Telnet, MQTT), firmware extraction (binwalk), debug interfaces (UART, JTAG), update hijacking, hardcoded API keys, buffer overflows, command injection, insecure MQTT broker.

Tools: binwalk, firmwalker, EMBA, RouterSploit.
