package macedit.keycloak.authenticator.gateway;

import macedit.keycloak.authenticator.SmsConstants;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
public class SmsServiceFactory {

	public static SmsService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault(SmsConstants.SIMULATION_MODE, "false"))) {
			return (phoneNumber, message) ->
				log.warn(String.format("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message));
		} else if (Boolean.parseBoolean(config.getOrDefault(SmsConstants.SMS_API_TYPE, "false"))) {
			return new TRestSmsService(config);
		} else {
			return new TSmsService(config);
		}
	}

}
