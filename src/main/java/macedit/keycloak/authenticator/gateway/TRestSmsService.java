package macedit.keycloak.authenticator.gateway;

import macedit.keycloak.authenticator.SmsConstants;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.jboss.logging.Logger;

public class TRestSmsService implements SmsService {

    private static final Logger LOG = Logger.getLogger(TRestSmsService.class);

    private final String apiUrl;
    private final String apiUsername;
    private final String apiPassword;
    private final String senderId;
    private final String appNameTemplate;
    private final String realmName;
    private final String clientName;
    private final String bodyTemplate;
    private final String customHeaders;

    TRestSmsService(Map<String, String> config) {
        this.apiUrl = config.getOrDefault(SmsConstants.SMS_API_URL, "https://api.macedit.dev/sms");
        this.apiUsername = config.get(SmsConstants.SMS_API_USERNAME);
        this.apiPassword = config.get(SmsConstants.SMS_API_PASSWORD);
        this.senderId = config.getOrDefault(SmsConstants.SENDER_ID, "MACEDIT");
        this.appNameTemplate = config.getOrDefault(SmsConstants.SMS_APP_NAME, "{realm}/{client}");
        this.realmName = config.getOrDefault("realmName", "");
        this.clientName = config.getOrDefault("clientName", "");
        this.bodyTemplate = config.getOrDefault(SmsConstants.SMS_API_BODY_TEMPLATE, "");
        this.customHeaders = config.getOrDefault(SmsConstants.SMS_API_CUSTOM_HEADERS, "");
    }

    public void send(String phoneNumber, String message) throws Exception {
        String cleanedNumber = cleanPhoneNumber(phoneNumber);
        String resolvedAppName = resolveAppName();
        try {
            URL u = new URL(apiUrl);
            HttpURLConnection connection = (HttpURLConnection) u.openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");

            String auth = apiUsername + ":" + apiPassword;
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
            connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
            connection.setRequestProperty("Content-Type", "application/json");

            if (customHeaders != null && !customHeaders.isBlank()) {
                String[] lines = customHeaders.split("\n");
                for (String line : lines) {
                    if (line.contains(":")) {
                        String[] parts = line.split(":", 2);
                        connection.setRequestProperty(parts[0].trim(), parts[1].trim());
                    }
                }
            }

            String finalBody;
            if (bodyTemplate != null && !bodyTemplate.isBlank()) {
                finalBody = bodyTemplate
                        .replace("{phone}", escapeJson(cleanedNumber))
                        .replace("{message}", escapeJson(message))
                        .replace("{senderId}", escapeJson(senderId))
                        .replace("{appName}", escapeJson(resolvedAppName));
            } else {
                StringBuilder jsonBody = new StringBuilder();
                jsonBody.append("{");
                jsonBody.append("\"msgheader\":\"").append(escapeJson(senderId)).append("\"");
                jsonBody.append(",\"msg\":\"").append(escapeJson(message)).append("\"");
                jsonBody.append(",\"no\":\"").append(escapeJson(cleanedNumber)).append("\"");
                if (resolvedAppName != null && !resolvedAppName.isBlank()) {
                    jsonBody.append(",\"appname\":\"").append(escapeJson(resolvedAppName)).append("\"");
                }
                jsonBody.append("}");
                finalBody = jsonBody.toString();
            }

            OutputStream out = connection.getOutputStream();
            OutputStreamWriter wout = new OutputStreamWriter(out, StandardCharsets.UTF_8);
            wout.write(finalBody);
            wout.flush();
            wout.close();
            out.close();

            int responseCode = connection.getResponseCode();
            InputStream in = (responseCode >= 200 && responseCode < 300)
                    ? connection.getInputStream()
                    : connection.getErrorStream();

            StringBuilder sonuc = new StringBuilder();
            if (in != null) {
                int c;
                while ((c = in.read()) != -1) {
                    sonuc.append((char) c);
                }
                in.close();
            }
            connection.disconnect();

            if (responseCode < 200 || responseCode >= 300) {
                LOG.errorf("REST SMS failed! to %s | Response: %d | Body: %s", phoneNumber, responseCode, sonuc);
                throw new Exception("SMS Provider Error: " + responseCode + " - " + sonuc.toString());
            }

            LOG.infof("REST SMS sent to %s (cleaned: %s) | Response: %d | Body: %s", phoneNumber, cleanedNumber, responseCode, sonuc);
        } catch (IOException e) {
            LOG.errorf(e, "Failed to send REST SMS to %s", phoneNumber);
            throw new Exception("Failed to send REST SMS to " + phoneNumber, e);
        }
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    private String cleanPhoneNumber(String phone) {
        if (phone == null) return "";
        String cleaned = phone.replaceAll("\\s+", "");
        if (cleaned.startsWith("+90")) {
            cleaned = cleaned.substring(3);
        } else if (cleaned.startsWith("+9")) {
            cleaned = cleaned.substring(2);
        } else if (cleaned.startsWith("90") && cleaned.length() > 10) {
            cleaned = cleaned.substring(2);
        }
        return cleaned;
    }

    private String resolveAppName() {
        if (appNameTemplate == null || appNameTemplate.isBlank()) return "";
        return appNameTemplate
                .replace("{realm}", realmName)
                .replace("{client}", clientName);
    }
}
