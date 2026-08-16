*Read this in other languages: [English](README.md), [Türkçe](README_tr.md).*

# Macedit Keycloak SMS Authenticator

Keycloak authentication plugins developed for **MACEDIT Authentication**. It provides SMS-based two-factor authentication (2FA) and custom login flows.

## Table of Contents

- [Features](#features)
- [Structure](#structure)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [SMS Gateway Support](#sms-gateway-support)
- [Direct Grant (REST API) Flow](#direct-grant-rest-api-flow)
- [Cache OTP Storage](#cache-otp-storage)
- [SMS Quota and Brute-Force Protection](#sms-quota-and-brute-force-protection)
- [Internal Network Bypass (Regex)](#internal-network-bypass-regex)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

---

## Features

### 1. SMS 2FA Authenticator (`sms-authenticator`)
- OTP verification via SMS after username + password login
- Dynamic user phone number attribute (`User Mobile Number Attribute` setting)
- Customizable code length and time-to-live (TTL)
- SMS Quota Protection (SMS reuse strategy for the same user/IP)
- Brute-Force protection (password reset/invalidation after 3 failed attempts)
- Customizable SMS message template
- Simulation mode (for testing environments - writes OTP to Event details and logs)
- Internal network IP bypass support (using Regex rules)

### 2. SMS Direct Grant Authenticator (`sms-direct-grant-authenticator`)
- SMS OTP for REST API / Direct Grant flows
- OTP storage using Keycloak's internal cache (Infinispan) (No external database or Redis required)
- Fully identical SMS Quota, Brute-Force protection, and Bypass support as the Browser flow
- Returns response in OAuth2 error format (`otp_required`)
- Verifies token request with `otp` parameter

---

## Structure

```
sms-authenticator/
├── src/main/java/macedit/keycloak/authenticator/
│   ├── SmsAuthenticator.java              # Main SMS authenticator
│   ├── SmsAuthenticatorFactory.java       # Factory class
│   ├── SmsConstants.java                  # Constants
│   ├── gateway/
│   │   ├── SmsService.java                # SMS service interface
│   │   ├── SmsServiceFactory.java         # SMS service factory
│   │   ├── TSmsService.java               # XML-based SMS gateway
│   │   └── TRestSmsService.java           # REST/JSON-based SMS gateway
│   └── directgrant/
│       ├── SmsDirectGrantAuthenticator.java
│       ├── SmsDirectGrantAuthenticatorFactory.java
│       ├── SmsDirectGrantConstants.java
│       ├── cache/
│       │   ├── OtpStore.java              # OTP storage interface
│       │   └── CacheOtpStore.java         # Keycloak SingleUseObjectProvider (Infinispan) implementation
│       └── util/
│           └── IpBypassUtil.java          # Regex-based IP bypass utility
├── src/main/resources/theme-resources/
│   └── templates/login-sms.ftl           # SMS login template
├── pom.xml
└── README.md
```

---

## Prerequisites

- **Java:** 17 or higher
- **Maven:** 3.6+ (or use the provided `mvnw` wrapper)
- **Keycloak:** 24.0+ (Tested with 26.7.0)
- **Docker:** For container environment (optional)

---

## Building

### SMS Authenticator

```bash
# In the project root directory
mvn clean package -DskipTests

# Generated JAR file:
# target/keycloak-2fa-sms-authenticator-1.0.0.jar
```

---

## Deployment

### Method 1: Volume Mount (Recommended for Development)

Mount the JAR files as a volume when creating the container:

```bash
docker run -d \
  --name keycloak-test \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v "$(pwd)/target/keycloak-2fa-sms-authenticator-1.0.0.jar:/opt/keycloak/providers/keycloak-2fa-sms-authenticator-1.0.0.jar" \
  keycloak/keycloak:latest start-dev
```

---

## Configuration

### Keycloak Admin Console Settings

1. Go to **Authentication > Flows**
2. Copy the **Browser** flow (e.g., "Browser with SMS")
3. Click **Add executor** > select **SMS Authentication**
4. Set **Requirement** to **Required** or **Alternative**
5. Click the **Gear** icon to configure

### SMS Authenticator Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `User Mobile Number Attribute` | User attribute to fetch the phone number from | `mobile_number` |
| `length` | OTP code length | `6` |
| `ttl` | Code time-to-live (seconds) | `300` |
| `SMS Reuse Strategy` | SMS Quota: Reuse Strategy (none, user, ip, both) | `user` |
| `Use REST API` | Use REST API (JSON) | `true` |
| `smsApiUrl` | SMS API endpoint URL | `https://api.macedit.dev/sms` |
| `smsApiUsername` | API username | - |
| `smsApiPassword` | API password | - |
| `SenderId` | SMS sender name | `MACEDIT` |
| `App Name (REST)` | Application name for REST API | `{realm}/{client}` |
| `SMS Message Template` | SMS message template | `Your verification code is: %1$s. Valid for %2$d minutes.` |
| `API Body Template` | Custom JSON request body. (Optional) | `{"msgheader":"{senderId}","msg":"{message}","no":"{phone}","appname":"{appName}"}` |
| `Bypass Internal Network` | Is internal network bypass active? | `true` |
| `Internal IP (Regex)` | Regex rule for IP addresses to be bypassed | `^10\.243\..*` |
| `Simulation mode` | Simulation mode (Does not send SMS, writes to log and event) | `true` |

### Message Template Variables

- `%1$s` → OTP code
- `%2$d` → Remaining minutes

Example: `"MACEDIT Verification code: %1$s. Valid for %2$d min."`

---

## SMS Gateway Support

### XML API 

When `Use REST API = false`, the request is sent in XML format:

```xml
<?xml version='1.0' encoding='iso-8859-9'?>
<mainbody>
  <header/>
  <body>
    <msg><![CDATA[Your verification code: 123456]]></msg>
    <no>5XXXXXXXXX</no>
  </body>
</mainbody>
```

### REST API (JSON) - Default

When `Use REST API = true`, the request is sent in JSON format:

```json
{
  "msgheader": "MACEDIT",
  "msg": "Your verification code is: 123456",
  "no": "5XXXXXXXXX",
  "appname": "myapp/master/security-admin-console"
}
```

### Phone Number Sanitization

Numbers are automatically sanitized:
- `+90 5XX XXX XX XX` → `5XXXXXXXXX`
- `+9 5XXXXXXXXX` → `5XXXXXXXXX`
- `90 5XXXXXXXXX` → `5XXXXXXXXX`
- Spaces are removed

---

## Direct Grant (REST API) Flow

### Step 1: OTP Request

```bash
curl -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=your-client" \
  -d "username=user1" \
  -d "password=pass123"
```

** Response (OTP sent, returns an error):**

```json
{
  "error": "invalid_grant",
  "error_description": "otp_required"
}
```

> This is the expected behavior. On the first request, an OTP is generated and sent via SMS.

### Step 2: OTP Verification

```bash
curl -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=your-client" \
  -d "username=user1" \
  -d "password=pass123" \
  -d "otp=123456"
```

**Success Response:**

```json
{
  "access_token": "...",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "token_type": "Bearer",
  ...
}
```

---

## Cache OTP Storage

In all Direct Grant and Browser flows, OTPs are stored in Keycloak's internal Infinispan cache (`SingleUseObjectProvider`). No external database or Redis is needed. It automatically synchronizes in Cluster environments.

### Key Format

```
smsotp:{realm}:{clientId}:{username}
```
*(If IP-based SMS Reuse strategy is used, the IP address is also appended to the key)*

---

## SMS Quota and Brute-Force Protection

**1. Brute-Force Protection:** If a user enters an incorrect SMS password 3 times, the OTP code is immediately invalidated by the server, and the user is required to request a new SMS. Passwords cannot be cracked by trial and error.

**2. SMS Reuse Strategy (Rate Limiting):** To prevent malicious individuals from consuming the organization's SMS quota by sending consecutive SMS requests, you can use the **SMS Reuse Strategy** setting via the Keycloak Admin UI:
- `none`: A new SMS is sent every time.
- `user`: If the same user requests again before the SMS Time-To-Live (TTL) expires, a new SMS is not sent, and the old code is expected. (Recommended/Default)
- `ip`: Expected to enter the old code for requests coming from the same IP address. *(Ensure Keycloak server can read X-Forwarded-For with proxy=edge setting)*
- `both`: Protection kicks in when both user and IP match.

---

## Internal Network Bypass (Regex)

You can bypass internal IP addresses using Regex rules to log in without sending SMS, especially for development/testing environments or from secure internal company devices.

### How it Works

1. Set `Bypass Internal Network = true`
2. Enter Regex rules in the `Internal IP (Regex)` parameter (you can enter multiple rules separated by commas).
3. If the client IP address exactly matches one of the rules, OTP verification is skipped.

### Examples

```
^10\.243\..*                        # Any IP starting with 10.243.
^192\.168\.1\.50$                   # Only exactly 192.168.1.50 IP address
^172\.(16|17)\..*, ^127\.0\.0\.1$   # Comma-separated multiple rules
```

---

## Simulation Mode

For development and testing environments where you don't want SMS to be sent to real phones, you can enable the `Simulation mode` option.

When Simulation mode is on:
- SMS Gateway API is **not triggered**.
- The SMS content and Verification Code (OTP) are printed to the Keycloak **server logs** as a WARNING (WARN).
- At the same time, the `code: 123456` information is found in the details of the user's action (CUSTOM_REQUIRED_ACTION) on the **Events** page in the Keycloak Admin UI.

> **Warning:** Simulation mode must strictly be **off (false)** in Production environments so that passwords are not logged and real SMS are sent.

---

## Development

### Environment Setup

```bash
# Java 17+ must be installed
java -version

# Maven must be installed (or use mvnw wrapper)
mvn -version

# Clone Keycloak source code (optional, for reference)
git clone https://github.com/keycloak/keycloak.git
```

### Project Structure

- `SmsAuthenticator` → Main authenticator for Browser flows
- `SmsDirectGrantAuthenticator` → Authenticator for REST API flows
- `SmsServiceFactory` → SMS gateway selection (XML/REST/Simulation)
- `CacheOtpStore` → Keycloak Infinispan-based shared OTP storage and quota counter
- `IpBypassUtil` → Regex-based IP security shield

---

## Troubleshooting

### Plugin Not Loaded

**Issue:** SMS authenticator is not visible in the Console

**Solution:**
1. Check container logs: `docker logs keycloak-test`
2. Ensure the JAR file is in the `/opt/keycloak/providers/` directory
3. Restart the container: `docker restart keycloak-test`

### SMS Not Sent

**Issue:** Code is generated but SMS is not received

**Solution:**
1. Is `Simulation mode = true`? Check the logs. If you see the verification code in the logs, the SMS Gateway is not called. Turn it off for live use.
2. Is `smsApiUrl` correct?
3. Are `smsApiUsername` and `smsApiPassword` correct?
4. Check the API response code (should be 200)

### Direct Grant Error

**Issue:** `otp_store_failed` error

**Solution:**
1. Verify that Keycloak Infinispan cluster settings are working correctly.
2. Ensure server memory capacity is not full.

---

## Log Examples

```
# Successful SMS delivery
INFO  [macedit.keycloak.authenticator.gateway.TRestSmsService] REST SMS sent to 5XXXXXXXXX | Response: 200 | Body: ...

# Internal IP bypass
WARN  [macedit.keycloak.authenticator.SmsAuthenticator] Logged With Internal IP: 192.168.1.100

# Simulation mode
WARN  ***** SIMULATION MODE ***** 
Would send SMS to 5XXXXXXXXX with text: Your verification code is: 123456. Valid for 5 minutes.
Code: 123456

# OTP Brute-Force Protection
WARN  [macedit.keycloak.authenticator.SmsAuthenticator] Max OTP attempts reached | Key: user1
```
