package macedit.keycloak.authenticator.directgrant.util;

import java.util.Arrays;
import java.util.Map;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.jboss.logging.Logger;

import macedit.keycloak.authenticator.directgrant.SmsDirectGrantConstants;

public final class IpBypassUtil {

    private static final Logger LOG = Logger.getLogger(IpBypassUtil.class);

    private IpBypassUtil() {
    }

    public static boolean shouldBypass(Map<String, String> config, String remoteIp) {
        if (config == null || remoteIp == null || remoteIp.isBlank()) {
            return false;
        }

        boolean bypassEnabled = Boolean.parseBoolean(
                config.getOrDefault(SmsDirectGrantConstants.INTERNAL_IP_BYPASS, "false")
        );

        if (!bypassEnabled) {
            return false;
        }

        String configured = config.getOrDefault(SmsDirectGrantConstants.INTERNAL_IP, "").trim();
        if (configured.isBlank()) {
            return false;
        }

        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .anyMatch(regex -> {
                    try {
                        return Pattern.compile(regex).matcher(remoteIp).matches();
                    } catch (PatternSyntaxException e) {
                        LOG.errorf("Invalid IP Regex Pattern configured: %s", regex);
                        return false;
                    }
                });
    }
}