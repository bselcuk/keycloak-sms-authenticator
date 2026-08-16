package macedit.keycloak.authenticator.directgrant;

import lombok.experimental.UtilityClass;

@UtilityClass
public class SmsDirectGrantConstants {

    // Request params
    public String OTP_PARAM = "otp";
    public String CLIENT_ID_PARAM = "client_id";

    // User attribute
    public String MOBILE_NUMBER_FIELD = "mobile_number";
    public String MOBILE_NUMBER_ATTRIBUTE = "mobileNumberAttribute";

    // Existing config keys
    public String CODE_LENGTH = "length";
    public String CODE_TTL = "ttl";
    public String SENDER_ID = "senderId";
    public String SIMULATION_MODE = "simulation";
    public String INTERNAL_IP = "internalIp";
    public String INTERNAL_IP_BYPASS = "internalIpBypass";

    // Reuse Strategy
    public String SMS_REUSE_STRATEGY = "smsReuseStrategy";


    // SMS API config keys
    public String SMS_API_URL = "smsApiUrl";
    public String SMS_API_USERNAME = "smsApiUsername";
    public String SMS_API_PASSWORD = "smsApiPassword";
    public String SMS_MESSAGE_TEMPLATE = "smsMessageTemplate";
    public String SMS_API_TYPE = "smsApiType";
    public String SMS_APP_NAME = "smsAppName";
    public String SMS_API_BODY_TEMPLATE = "smsApiBodyTemplate";
    public String SMS_API_CUSTOM_HEADERS = "smsApiCustomHeaders";

    // Error descriptions
    public String ERR_OTP_REQUIRED = "otp_required";
    public String ERR_OTP_INVALID = "otp_invalid";
    public String ERR_OTP_EXPIRED = "otp_expired";
    public String ERR_MOBILE_NUMBER_MISSING = "mobile_number_missing";
    public String ERR_SMS_SEND_FAILED = "sms_send_failed";
    public String ERR_OTP_STORE_FAILED = "otp_store_failed";
}