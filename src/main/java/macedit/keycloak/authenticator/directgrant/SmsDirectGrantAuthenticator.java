package macedit.keycloak.authenticator.directgrant;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import macedit.keycloak.authenticator.directgrant.cache.OtpStore;
import macedit.keycloak.authenticator.directgrant.cache.CacheOtpStore;
import macedit.keycloak.authenticator.directgrant.util.IpBypassUtil;
import macedit.keycloak.authenticator.gateway.SmsServiceFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.Map;


public class SmsDirectGrantAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(SmsDirectGrantAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();

        if (user == null) {
            fail(context, AuthenticationFlowError.UNKNOWN_USER, "invalid_user");
            context.getEvent().detail("USER_LOGIN", "Bilinmeyen Kullanıcı").error("Bilinmeyen Kullanıcı");
            return;
        }

        Map<String, String> config = configModel != null ? new HashMap<>(configModel.getConfig()) : new HashMap<>();
        String remoteIp = context.getConnection() != null ? context.getConnection().getRemoteAddr() : null;
        String realmName = context.getRealm() != null ? context.getRealm().getName() : "";
        String clientId = readFormParam(context, SmsDirectGrantConstants.CLIENT_ID_PARAM);
        String username = user.getUsername();
        String userIdString = user.getId();

        config.put("realmName", realmName);
        if (clientId != null && !clientId.isBlank()) {
            config.put("clientName", clientId);
        }

        LOG.warnf("[SmsDirectGrantAuthenticator] Remote IP: %s | Realm: %s | Client: %s | User: %s",
                remoteIp, realmName, clientId, username);

        if (clientId == null || clientId.isBlank()) {
            fail(context, AuthenticationFlowError.INVALID_CLIENT_SESSION, "invalid_client");
            context.getEvent().detail("CLIENT_ID", "Eksik").user(userIdString).error("Geçersiz İstemci");
            return;
        }

        if (IpBypassUtil.shouldBypass(config, remoteIp)) {
            LOG.warnf("[SmsDirectGrantAuthenticator] OTP bypassed for internal IP: %s | User: %s", remoteIp, username);
            context.getEvent().detail("OTP_BYPASS", remoteIp).user(userIdString).success();
            context.success();
            return;
        }

        String mobileAttr = config.getOrDefault(SmsDirectGrantConstants.MOBILE_NUMBER_ATTRIBUTE, "mobile_number");
        String mobileNumber = user.getFirstAttribute(mobileAttr);
        if (mobileNumber == null || mobileNumber.isBlank()) {
            LOG.warnf("[SmsDirectGrantAuthenticator] mobile_number missing for user: %s", username);
            fail(context, AuthenticationFlowError.INVALID_USER, SmsDirectGrantConstants.ERR_MOBILE_NUMBER_MISSING);
            context.getEvent().detail("MOBILE_NUMBER", "Eksik").user(userIdString).error("Kullanıcıda Mobil Numarası Yok");
            return;
        }

        OtpStore otpStore;
        try {
            otpStore = new CacheOtpStore(session);
        } catch (Exception ex) {
            LOG.errorf(ex, "[SmsDirectGrantAuthenticator] Failed to initialize Cache OTP store");
            fail(context, AuthenticationFlowError.INTERNAL_ERROR, SmsDirectGrantConstants.ERR_OTP_STORE_FAILED);
            context.getEvent().detail("OTP_STORE", "Failed").user(userIdString).error("OTP Depolama Başarısız");
            return;
        }

        String reuseStrategy = config.getOrDefault(SmsDirectGrantConstants.SMS_REUSE_STRATEGY, "none");
        String reuseKeyUsername = username;
        
        if ("ip".equals(reuseStrategy)) {
            reuseKeyUsername = remoteIp != null ? remoteIp : username;
        } else if ("both".equals(reuseStrategy)) {
            reuseKeyUsername = username + ":" + (remoteIp != null ? remoteIp : "");
        }

        String enteredOtp = readFormParam(context, SmsDirectGrantConstants.OTP_PARAM);

        if (enteredOtp == null || enteredOtp.isBlank()) {
            if (!"none".equals(reuseStrategy)) {
                String existingOtp = otpStore.get(realmName, clientId, reuseKeyUsername);
                if (existingOtp != null && !existingOtp.isBlank()) {
                    LOG.warnf("[SmsDirectGrantAuthenticator] Reusing existing SMS OTP | Strategy: %s | Key: %s", reuseStrategy, reuseKeyUsername);
                    
                    context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION)
                            .user(userIdString)
                            .detail("sms_action", "SMS Tekrar Gonderilmedi (Hafizadan Kullanim)")
                            .detail("strategy", reuseStrategy)
                            .success();
                            
                    fail(context, AuthenticationFlowError.INVALID_CREDENTIALS, SmsDirectGrantConstants.ERR_OTP_REQUIRED);
                    return;
                }
            }
            generateAndSendOtp(context, otpStore, config, realmName, clientId, reuseKeyUsername, mobileNumber , userIdString);
            return;
        }

        validateOtp(context, otpStore, realmName, clientId, reuseKeyUsername, enteredOtp,userIdString);
    }

    private void generateAndSendOtp(AuthenticationFlowContext context,
                                    OtpStore otpStore,
                                    Map<String, String> config,
                                    String realmName,
                                    String clientId,
                                    String username,
                                    String mobileNumber,
                                    String userIdString) {

        int length = parseInt(config.get(SmsDirectGrantConstants.CODE_LENGTH), 6);
        int ttlSeconds = parseInt(config.get(SmsDirectGrantConstants.CODE_TTL), 300);

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);

        try {
            otpStore.save(realmName, clientId, username, code, ttlSeconds );
        } catch (Exception ex) {
            LOG.errorf(ex, "[SmsDirectGrantAuthenticator] Failed to save OTP in Redis | User: %s", username);
            fail(context, AuthenticationFlowError.INTERNAL_ERROR, SmsDirectGrantConstants.ERR_OTP_STORE_FAILED);
            context.getEvent().detail("OTP_STORE", "Failed").user(userIdString).error("OTP Depolama Başarısız. Hata :" + ex.getMessage());
            return;
        }

        context.getEvent().event(EventType.CODE_TO_TOKEN).detail("OTP_GENERATION", "Başarılı").user(userIdString).success();
        try {
            String smsText = buildSmsText(code, ttlSeconds, config);
            boolean isSimulation = Boolean.parseBoolean(config.getOrDefault(SmsDirectGrantConstants.SIMULATION_MODE, "false"));
            if (isSimulation) {
                LOG.warnf("***** SIMULATION MODE *****\nWould send SMS to %s with text: %s\nCode: %s", mobileNumber, smsText, code);
                context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION)
                        .user(userIdString)
                        .detail("sms_action", "SMS (Simulasyon) Basariyla Gonderildi")
                        .detail("mobile", mobileNumber)
                        .detail("code", code)
                        .success();
            } else {
                SmsServiceFactory.get(config).send(mobileNumber, smsText);

                context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION)
                        .user(userIdString)
                        .detail("sms_action", "SMS Basariyla Gonderildi")
                        .detail("mobile", mobileNumber)
                        .success();
            }

            fail(context, AuthenticationFlowError.INVALID_CREDENTIALS, SmsDirectGrantConstants.ERR_OTP_REQUIRED);
        } catch (Exception ex) {
            try {
                otpStore.remove(realmName, clientId, username);
            } catch (Exception removeEx) {
                LOG.errorf(removeEx, "[SmsDirectGrantAuthenticator] Failed to cleanup OTP after SMS error | User: %s", username);
            }

            LOG.errorf(ex, "[SmsDirectGrantAuthenticator] SMS send failed | User: %s", username);
            fail(context, AuthenticationFlowError.INTERNAL_ERROR, SmsDirectGrantConstants.ERR_SMS_SEND_FAILED);
            context.getEvent().detail("SMS_SEND", "Failed").user(userIdString).error("SMS Gönderimi Başarısız : " + ex.getMessage());
        }
    }

    private void validateOtp(AuthenticationFlowContext context,
                             OtpStore otpStore,
                             String realmName,
                             String clientId,
                             String username,
                             String enteredOtp,
                            String userIdString) {

        UserModel user = context.getUser();
        String mobileAttr = context.getAuthenticatorConfig() != null 
                ? context.getAuthenticatorConfig().getConfig().getOrDefault(SmsDirectGrantConstants.MOBILE_NUMBER_ATTRIBUTE, "mobile_number")
                : "mobile_number";
        String mobileNumber = user != null ? user.getFirstAttribute(mobileAttr) : "unknown";
        String expectedOtp;
        try {
            expectedOtp = otpStore.get(realmName, clientId, username);
        } catch (Exception ex) {
            LOG.errorf(ex, "[SmsDirectGrantAuthenticator] Failed to read OTP from Redis | User: %s", username);
            fail(context, AuthenticationFlowError.INTERNAL_ERROR, SmsDirectGrantConstants.ERR_OTP_STORE_FAILED);
            context.getEvent().detail("OTP_STORE", "Failed").user(userIdString).error("OTP Depolama Başarısız");
            return;
        }

        if (expectedOtp == null || expectedOtp.isBlank()) {
            context.getEvent().clone().event(EventType.LOGIN_ERROR)
                    .user(userIdString)
                    .detail("sms_error", "OTP Suresi Dolmus veya Bulunamadi.")
                    .detail("mobile", mobileNumber)
                    .detail("username", username)
                    .error("invalid_sms_code");
            fail(context, AuthenticationFlowError.EXPIRED_CODE, SmsDirectGrantConstants.ERR_OTP_EXPIRED);
            return;
        }

        if (!expectedOtp.equals(enteredOtp)) {
            try {
                int ttlSeconds = parseInt(context.getAuthenticatorConfig().getConfig().get(SmsDirectGrantConstants.CODE_TTL), 300);
                long attempts = otpStore.incrementAttempts(realmName, clientId, username, ttlSeconds);
                if (attempts >= 3) {
                    otpStore.remove(realmName, clientId, username);
                    LOG.warnf("[SmsDirectGrantAuthenticator] Max OTP attempts reached, removing OTP | User: %s", username);
                    context.getEvent().clone().event(EventType.LOGIN_ERROR)
                            .user(userIdString)
                            .detail("sms_error", "SMS Kodu 3 kez hatali girildi, kod iptal edildi.")
                            .detail("mobile", mobileNumber)
                            .detail("username", username)
                            .error("invalid_sms_code");
                    fail(context, AuthenticationFlowError.INVALID_CREDENTIALS, SmsDirectGrantConstants.ERR_OTP_EXPIRED);
                    return;
                }
            } catch (Exception ex) {
                LOG.errorf(ex, "[SmsDirectGrantAuthenticator] Failed to increment attempts | User: %s", username);
            }

            context.getEvent().clone().event(EventType.LOGIN_ERROR)
                    .user(userIdString)
                    .detail("sms_error", "SMS Kodu hatali girildi.")
                    .detail("mobile", mobileNumber)
                    .detail("username", username)
                    .error("invalid_sms_code");
            fail(context, AuthenticationFlowError.INVALID_CREDENTIALS, SmsDirectGrantConstants.ERR_OTP_INVALID);
            return;
        }

        try {
            otpStore.remove(realmName, clientId, username);
        } catch (Exception ex) {
            LOG.errorf(ex, "[SmsDirectGrantAuthenticator] Failed to delete OTP from Redis after success | User: %s", username);
            context.getEvent().detail("sms_error", "OTP Silme Başarısız. Hata :" + ex.getMessage());
        }

        context.getEvent().detail("OTP_VALIDATION", "Başarılı").user(userIdString).success();
        context.success();
    }

    private String readFormParam(AuthenticationFlowContext context, String paramName) {
        try {
            return context.getHttpRequest()
                    .getDecodedFormParameters()
                    .getFirst(paramName);
        } catch (Exception ex) {
            LOG.errorf(ex, "[SmsDirectGrantAuthenticator] Failed to read form parameter: %s", paramName);
            return null;
        }
    }

    private int parseInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ex) {
            return defaultValue;
        }
    }

    private String buildSmsText(String code, int ttlSeconds, Map<String, String> config) {
        long minutes = Math.max(1, ttlSeconds / 60);
        String messageTemplate = config.get(SmsDirectGrantConstants.SMS_MESSAGE_TEMPLATE);
        if (messageTemplate == null || messageTemplate.isBlank()) {
            messageTemplate = "Doğrulama kodunuz: %1$s. Kod %2$d dakika boyunca geçerlidir.";
        }
        return String.format(messageTemplate, code, minutes);
    }

    private void fail(AuthenticationFlowContext context, AuthenticationFlowError error, String errorDescription) {
        Response response = oauthError(Response.Status.BAD_REQUEST, "invalid_grant", errorDescription);
        context.failureChallenge(error, response);
    }

    private Response oauthError(Response.Status status, String error, String description) {
        String json = "{"
                + "\"error\":\"" + escapeJson(error) + "\","
                + "\"error_description\":\"" + escapeJson(description) + "\""
                + "}";

        return Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(json)
                .build();
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Direct Grant flow için kullanılmıyor.
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Dynamic config check
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Şimdilik gerek yok.
    }

    @Override
    public void close() {
    }
}