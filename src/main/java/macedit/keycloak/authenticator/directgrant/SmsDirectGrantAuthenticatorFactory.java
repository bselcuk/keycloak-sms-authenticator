package macedit.keycloak.authenticator.directgrant;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

@AutoService(AuthenticatorFactory.class)
public class SmsDirectGrantAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sms-direct-grant-authenticator";

    private static final SmsDirectGrantAuthenticator SINGLETON = new SmsDirectGrantAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "SMS Direct Grant Authentication";
    }

    @Override
    public String getHelpText() {
        return "Validates an OTP sent via SMS for Direct Grant / token endpoint flows using Redis-backed state.";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                // 1. User Settings
                new ProviderConfigProperty(SmsDirectGrantConstants.MOBILE_NUMBER_ATTRIBUTE, "User Mobile Number Attribute", "The user attribute name that contains the mobile number.", ProviderConfigProperty.STRING_TYPE, "mobile_number"),
                
                // 2. OTP Settings
                new ProviderConfigProperty(SmsDirectGrantConstants.CODE_LENGTH, "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, "6"),
                new ProviderConfigProperty(SmsDirectGrantConstants.CODE_TTL, "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_REUSE_STRATEGY, "SMS Reuse Strategy", "How active SMS codes are reused. Options: 'none', 'user', 'ip', 'both'. Note: IP-based filtering requires X-Forwarded-For (XFF) proxy headers configured in Keycloak.", ProviderConfigProperty.LIST_TYPE, "user", "none", "user", "ip", "both"),
                
                // 3. API Settings
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_API_TYPE, "Use REST API", "If enabled, uses JSON/REST API (smsV2Rest). If disabled, uses XML API (otpSmsDmz).", ProviderConfigProperty.BOOLEAN_TYPE, true),
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_API_URL, "SMS API URL", "SMS API endpoint URL.", ProviderConfigProperty.STRING_TYPE, "https://api.macedit.dev/sms"),
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_API_USERNAME, "SMS API Username", "Username for SMS API Basic Auth.", ProviderConfigProperty.STRING_TYPE, ""),
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_API_PASSWORD, "SMS API Password", "Password for SMS API Basic Auth.", ProviderConfigProperty.PASSWORD, ""),
                new ProviderConfigProperty(SmsDirectGrantConstants.SENDER_ID, "SenderId", "Displayed sender id for SMS provider if applicable.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_APP_NAME, "App Name (REST)", "App name template for REST API. Use {realm} for realm name and {client} for client ID. Example: MyApp/{realm}/{client}", ProviderConfigProperty.STRING_TYPE, "{realm}/{client}"),
                
                // 4. API Templates
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_MESSAGE_TEMPLATE, "SMS Message Template", "Message template. Use %1$s for code and %2$d for minutes. Example: Doğrulama kodunuz: %1$s. Kod %2$d dakika geçerlidir.", ProviderConfigProperty.STRING_TYPE, "Doğrulama kodunuz: %1$s. Kod %2$d dakika boyunca geçerlidir."),
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_API_BODY_TEMPLATE, "API Body Template (Optional)", "Custom JSON/XML body template. Use variables: {phone}, {message}, {senderId}, {appName}. Leave empty for default.", ProviderConfigProperty.STRING_TYPE, "{\"msgheader\":\"{senderId}\",\"msg\":\"{message}\",\"no\":\"{phone}\",\"appname\":\"{appName}\"}"),
                new ProviderConfigProperty(SmsDirectGrantConstants.SMS_API_CUSTOM_HEADERS, "Custom HTTP Headers (Optional)", "Custom HTTP headers. Format: HeaderName: HeaderValue. One per line. (e.g. Content-Type: application/json)", ProviderConfigProperty.STRING_TYPE, ""),
                
                // 5. Security & Testing
                new ProviderConfigProperty(SmsDirectGrantConstants.INTERNAL_IP_BYPASS, "Bypass Internal Network", "If enabled, requests coming from configured internal IP regex skip OTP.", ProviderConfigProperty.BOOLEAN_TYPE, true),
                new ProviderConfigProperty(SmsDirectGrantConstants.INTERNAL_IP, "Internal IP (Regex)", "Regex rules for IPs that bypass OTP. Example: ^10\\.243\\..*", ProviderConfigProperty.STRING_TYPE, "^10\\.243\\..*"),
                new ProviderConfigProperty(SmsDirectGrantConstants.SIMULATION_MODE, "Simulation mode", "In simulation mode, SMS is not sent and is only printed to server logs.", ProviderConfigProperty.BOOLEAN_TYPE, true)
        );
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}