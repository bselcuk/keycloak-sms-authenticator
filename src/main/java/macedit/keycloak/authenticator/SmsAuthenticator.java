package macedit.keycloak.authenticator;

import macedit.keycloak.authenticator.directgrant.cache.CacheOtpStore;
import macedit.keycloak.authenticator.directgrant.cache.OtpStore;
import macedit.keycloak.authenticator.directgrant.util.IpBypassUtil;
import macedit.keycloak.authenticator.gateway.SmsServiceFactory;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SmsAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(SmsAuthenticator.class);
    private static final String TPL_CODE = "login-sms.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();

        String remoteIp = context.getConnection().getRemoteAddr();
        
        LOG.warnf("Remote IP address: %s | User Name: %s", remoteIp, user.getUsername());
        
        if (IpBypassUtil.shouldBypass(config.getConfig(), remoteIp)) {

            LOG.warnf("Logged With Internal IP: %s", remoteIp);
            context.getEvent().event(EventType.LOGIN).detail("INTERNAL_IP_BYPASS", "Etkin").user(user.getId())
                    .success();
            context.setUser(user);
            context.success();
            return;
        }

        // === SETUP REUSE STRATEGY ===
        String reuseStrategy = config.getConfig().getOrDefault(SmsConstants.SMS_REUSE_STRATEGY, "none");
        String username = user.getUsername();
        String reuseKeyUsername = username;

        if ("none".equals(reuseStrategy)) {
            reuseKeyUsername = authSession.getAuthNote("sms_cache_key");
            if (reuseKeyUsername == null) {
                reuseKeyUsername = "none:" + UUID.randomUUID().toString();
            }
        } else if ("ip".equals(reuseStrategy)) {
            reuseKeyUsername = remoteIp != null ? remoteIp : username;
        } else if ("both".equals(reuseStrategy)) {
            reuseKeyUsername = username + ":" + (remoteIp != null ? remoteIp : "");
        }
        
        authSession.setAuthNote("sms_cache_key", reuseKeyUsername);
        
        String realmName = context.getRealm().getName();
        String clientId = authSession.getClient() != null ? authSession.getClient().getClientId() : "browser";

        OtpStore otpStore;
        try {
            otpStore = new CacheOtpStore(session);
        } catch (Exception ex) {
            LOG.errorf(ex, "Failed to initialize CacheOtpStore");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsAuthSmsNotSent", "").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        String existingOtp = otpStore.get(realmName, clientId, reuseKeyUsername);

        if (existingOtp != null && !existingOtp.isBlank()) {
            LOG.warnf("[SmsAuthenticator] Reusing SMS OTP | Strategy: %s | Key: %s", reuseStrategy, reuseKeyUsername);
            context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION)
                    .user(user.getId())
                    .detail("sms_action", "SMS Tekrar Gonderilmedi (Hafizadan Kullanim)")
                    .detail("strategy", reuseStrategy)
                    .success();
            context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
        } else {
            sendCode(context, authSession, config, session, user, otpStore, realmName, clientId, reuseKeyUsername);
        }
    }

    private void sendCode(AuthenticationFlowContext context, AuthenticationSessionModel authSession,
            AuthenticatorConfigModel config, KeycloakSession session, UserModel user, 
            OtpStore otpStore, String realmName, String clientId, String reuseKeyUsername) {
            
        String mobileAttr = config.getConfig().getOrDefault(SmsConstants.MOBILE_NUMBER_ATTRIBUTE, "mobile_number");
        String mobileNumber = user.getFirstAttribute(mobileAttr);
        if (mobileNumber == null || mobileNumber.isEmpty()) {
            context.getEvent().detail("sms_error", "Kullanici icin mobil numara bulunamadi.");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsAuthSmsNoNumberSent", "")
                            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            LOG.warnf("mobile_number is missing for user: %s", user.getUsername());
            return;
        }

        int length = Integer.parseInt(config.getConfig().getOrDefault(SmsConstants.CODE_LENGTH, "6"));
        int ttl = Integer.parseInt(config.getConfig().getOrDefault(SmsConstants.CODE_TTL, "300"));
        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);

        try {
            otpStore.save(realmName, clientId, reuseKeyUsername, code, ttl);
        } catch (Exception ex) {
            LOG.errorf(ex, "Failed to save OTP to cache");
            context.getEvent().detail("sms_error", "OTP Cache'e kaydedilemedi.");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsAuthSmsNotSent", "").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        try {
            String messageTemplate = config.getConfig().get(SmsConstants.SMS_MESSAGE_TEMPLATE);
            if (messageTemplate == null || messageTemplate.isBlank()) {
                messageTemplate = "Doğrulama kodunuz: %1$s. Kod %2$d dakika boyunca geçerlidir.";
            }
            String smsText = String.format(messageTemplate, code, Math.floorDiv(ttl, 60));
            Map<String, String> smsConfig = new HashMap<>(config.getConfig());
            smsConfig.put("realmName", realmName);
            smsConfig.put("clientName", clientId);
            boolean isSimulation = Boolean.parseBoolean(config.getConfig().getOrDefault(SmsConstants.SIMULATION_MODE, "false"));
            if (isSimulation) {
                LOG.warnf("***** SIMULATION MODE *****\nWould send SMS to %s with text: %s\nCode: %s", mobileNumber, smsText, code);
                context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION)
                        .user(user.getId())
                        .detail("sms_action", "SMS (Simulasyon) Basariyla Gonderildi")
                        .detail("mobile", mobileNumber)
                        .detail("code", code)
                        .success();
            } else {
                SmsServiceFactory.get(smsConfig).send(mobileNumber, smsText);
                
                context.getEvent().clone().event(EventType.CUSTOM_REQUIRED_ACTION)
                        .user(user.getId())
                        .detail("sms_action", "SMS Basariyla Gonderildi")
                        .detail("mobile", mobileNumber)
                        .success();
            }
                    
            context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
        } catch (Exception e) {
            try {
                otpStore.remove(realmName, clientId, reuseKeyUsername);
            } catch (Exception ex) {}
            
            context.getEvent().detail("sms_error", "SMS Saglayici Hatasi: " + e.getMessage());
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsAuthSmsNotSent", e.getMessage())
                            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst(SmsConstants.CODE);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String reuseKeyUsername = authSession.getAuthNote("sms_cache_key");
        UserModel user = context.getUser();
        String mobileAttr = context.getAuthenticatorConfig().getConfig().getOrDefault(SmsConstants.MOBILE_NUMBER_ATTRIBUTE, "mobile_number");
        String mobileNumber = user != null ? user.getFirstAttribute(mobileAttr) : "unknown";
        String username = user != null ? user.getUsername() : "unknown";
        
        if (reuseKeyUsername == null) {
            context.getEvent().detail("sms_error", "Cache Key bulunamadi.");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        String realmName = context.getRealm().getName();
        String clientId = authSession.getClient() != null ? authSession.getClient().getClientId() : "browser";
        
        OtpStore otpStore;
        try {
            otpStore = new CacheOtpStore(context.getSession());
        } catch (Exception ex) {
            context.getEvent().detail("sms_error", "Cache erisimi saglanamadi.");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        String expectedOtp = otpStore.get(realmName, clientId, reuseKeyUsername);

        if (expectedOtp == null || expectedOtp.isBlank()) {
            context.getEvent().clone().event(EventType.LOGIN_ERROR)
                    .user(context.getUser().getId())
                    .detail("sms_error", "OTP Suresi Dolmus veya Bulunamadi.")
                    .detail("mobile", mobileNumber)
                    .detail("username", username)
                    .error("invalid_sms_code");
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
            return;
        }

        if (enteredCode.equals(expectedOtp)) {
            otpStore.remove(realmName, clientId, reuseKeyUsername);
            authSession.removeAuthNote("sms_cache_key");
            context.success();
        } else {
            int ttl = Integer.parseInt(context.getAuthenticatorConfig().getConfig().getOrDefault(SmsConstants.CODE_TTL, "300"));
            long attempts = otpStore.incrementAttempts(realmName, clientId, reuseKeyUsername, ttl);
            if (attempts >= 3) {
                otpStore.remove(realmName, clientId, reuseKeyUsername);
                LOG.warnf("[SmsAuthenticator] Max OTP attempts reached | Key: %s", reuseKeyUsername);
                context.getEvent().clone().event(EventType.LOGIN_ERROR)
                        .user(context.getUser().getId())
                        .detail("sms_error", "SMS Kodu 3 kez hatali girildi, kod iptal edildi.")
                        .detail("mobile", mobileNumber)
                        .detail("username", username)
                        .error("invalid_sms_code");
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
                return;
            }
            
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.getEvent().clone().event(EventType.LOGIN_ERROR)
                        .user(context.getUser().getId())
                        .detail("sms_error", "SMS Kodu hatali girildi (Deneme: " + attempts + "/3)")
                        .detail("mobile", mobileNumber)
                        .detail("username", username)
                        .error("invalid_sms_code");
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setAttribute("realm", context.getRealm())
                                .setError("smsAuthCodeInvalid").createForm(TPL_CODE));
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Dynamic config requires access to context, but this method does not have it.
        // As a fallback, check the default "mobile_number" or assume true if we can't be sure.
        // The flow will fail properly in authenticate() if missing.
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
