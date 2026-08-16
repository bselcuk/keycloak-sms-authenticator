package macedit.keycloak.authenticator.directgrant.cache;

public interface OtpStore {
    void save(String realm, String clientId, String username, String code, long ttlSeconds);
    String get(String realm, String clientId, String username);
    long incrementAttempts(String realm, String clientId, String username, int ttlSeconds);
    void remove(String realm, String clientId, String username);
}
