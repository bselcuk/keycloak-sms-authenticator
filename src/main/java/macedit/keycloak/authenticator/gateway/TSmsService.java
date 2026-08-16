package macedit.keycloak.authenticator.gateway;

import macedit.keycloak.authenticator.SmsConstants;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.jboss.logging.Logger;

public class TSmsService implements SmsService {

    private static final Logger LOG = Logger.getLogger(TSmsService.class);

    private final String apiUrl;
    private final String apiUsername;
    private final String apiPassword;
    private final String bodyTemplate;
    private final String customHeaders;
    private final String senderId;
    private final String appNameTemplate;
    private final String realmName;
    private final String clientName;

    TSmsService(Map<String, String> config) {
        this.apiUrl = config.get(SmsConstants.SMS_API_URL);
        this.apiUsername = config.get(SmsConstants.SMS_API_USERNAME);
        this.apiPassword = config.get(SmsConstants.SMS_API_PASSWORD);
        this.bodyTemplate = config.getOrDefault(SmsConstants.SMS_API_BODY_TEMPLATE, "");
        this.customHeaders = config.getOrDefault(SmsConstants.SMS_API_CUSTOM_HEADERS, "");
        this.senderId = config.getOrDefault(SmsConstants.SENDER_ID, "MACEDIT");
        this.appNameTemplate = config.getOrDefault(SmsConstants.SMS_APP_NAME, "{realm}/{client}");
        this.realmName = config.getOrDefault("realmName", "");
        this.clientName = config.getOrDefault("clientName", "");
    }

    private String resolveAppName() {
        if (appNameTemplate == null || appNameTemplate.isBlank()) return "";
        return appNameTemplate.replace("{realm}", realmName).replace("{client}", clientName);
    }

    public void send(String phoneNumber, String message) throws Exception {
        try {
            URL u = new URL(apiUrl);
            URLConnection uc = u.openConnection();
            HttpURLConnection connection = (HttpURLConnection) uc;
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");

            String auth = apiUsername + ":" + apiPassword;
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
            connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
            connection.setRequestProperty("Content-Type", "application/xml");
            
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
                        .replace("{phone}", phoneNumber)
                        .replace("{message}", message)
                        .replace("{senderId}", senderId)
                        .replace("{appName}", resolveAppName());
            } else {
                finalBody = "<?xml version='1.0' encoding='iso-8859-9'?>"
                    + "<mainbody>"
                    + "<header/>"
                    + "<body>"
                    + "<msg><![CDATA[" + message + "]]></msg>"
                    + "<no>" + phoneNumber + "</no>"
                    + "</body>"
                    + "</mainbody>";
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
                LOG.errorf("XML SMS failed! to %s | Response: %d | Body: %s", phoneNumber, responseCode, sonuc);
                throw new Exception("SMS Provider Error: " + responseCode + " - " + sonuc.toString());
            }

            LOG.infof("Sending SMS to %s", phoneNumber);
        } catch (IOException e) {
            LOG.errorf(e, "Failed to send SMS to %s", phoneNumber);
            throw new Exception("Failed to send XML SMS to " + phoneNumber, e);
        }
    }
}
