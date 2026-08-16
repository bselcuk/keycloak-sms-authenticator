package macedit.keycloak.authenticator;

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
public class SmsAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sms-authenticator";

    private static final SmsAuthenticator SINGLETON = new SmsAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "SMS Authentication";
    }

    @Override
    public String getHelpText() {
        return "Validates an OTP sent via SMS to the users mobile phone.";
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
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                // 1. User Settings
                new ProviderConfigProperty(SmsConstants.MOBILE_NUMBER_ATTRIBUTE, "User Mobile Number Attribute", "The user attribute name that contains the mobile number.", ProviderConfigProperty.STRING_TYPE, "mobile_number"),
                
                // 2. OTP Settings
                new ProviderConfigProperty(SmsConstants.CODE_LENGTH, "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
                new ProviderConfigProperty(SmsConstants.CODE_TTL, "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
                new ProviderConfigProperty(SmsConstants.SMS_REUSE_STRATEGY, "SMS Reuse Strategy", "How active SMS codes are reused. Options: 'none', 'user', 'ip', 'both'. Note: IP-based filtering requires X-Forwarded-For (XFF) proxy headers configured in Keycloak.", ProviderConfigProperty.LIST_TYPE, "user", "none", "user", "ip", "both"),
                
                // 3. API Settings
                new ProviderConfigProperty(SmsConstants.SMS_API_TYPE, "Use REST API", "If enabled, uses JSON/REST API (smsV2Rest). If disabled, uses XML API (otpSmsDmz).", ProviderConfigProperty.BOOLEAN_TYPE, true),
                new ProviderConfigProperty(SmsConstants.SMS_API_URL, "SMS API URL", "SMS API endpoint URL.", ProviderConfigProperty.STRING_TYPE, "https://api.macedit.dev/sms"),
                new ProviderConfigProperty(SmsConstants.SMS_API_USERNAME, "SMS API Username", "Username for SMS API Basic Auth.", ProviderConfigProperty.STRING_TYPE, ""),
                new ProviderConfigProperty(SmsConstants.SMS_API_PASSWORD, "SMS API Password", "Password for SMS API Basic Auth.", ProviderConfigProperty.PASSWORD, ""),
                new ProviderConfigProperty(SmsConstants.SENDER_ID, "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "MACEDIT"),
                new ProviderConfigProperty(SmsConstants.SMS_APP_NAME, "App Name (REST)", "App name template for REST API. Use {realm} for realm name and {client} for client ID. Example: MyApp/{realm}/{client}", ProviderConfigProperty.STRING_TYPE, "{realm}/{client}"),
                
                // 4. API Templates
                new ProviderConfigProperty(SmsConstants.SMS_MESSAGE_TEMPLATE, "SMS Message Template", "Message template. Use %1$s for code and %2$d for minutes. Example: Doğrulama kodunuz: %1$s. Kod %2$d dakika geçerlidir.", ProviderConfigProperty.STRING_TYPE, "Doğrulama kodunuz: %1$s. Kod %2$d dakika boyunca geçerlidir."),
                new ProviderConfigProperty(SmsConstants.SMS_API_BODY_TEMPLATE, "API Body Template (Optional)", "Custom JSON/XML body template. Use variables: {phone}, {message}, {senderId}, {appName}. Leave empty for default.", "Text", "{\"msgheader\":\"{senderId}\",\"msg\":\"{message}\",\"no\":\"{phone}\",\"appname\":\"{appName}\"}"),
                new ProviderConfigProperty(SmsConstants.SMS_API_CUSTOM_HEADERS, "Custom HTTP Headers (Optional)", "Custom HTTP headers. Format: HeaderName: HeaderValue. One per line. (e.g. Content-Type: application/json)", "Text", ""),
                
                // 5. Security & Testing
                new ProviderConfigProperty(SmsConstants.INTERNAL_IP_BYPASS, "Bypass Internal Network", "Bypass OTP for internal network requests", ProviderConfigProperty.BOOLEAN_TYPE, true),
                new ProviderConfigProperty(SmsConstants.INTERNAL_IP, "Internal IP (Regex)", "Bypass OTP for these IPs. Regex support is available. Example: ^10\\.243\\..*", ProviderConfigProperty.STRING_TYPE, "^10\\.243\\..*"),
                new ProviderConfigProperty(SmsConstants.SIMULATION_MODE, "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true)
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
