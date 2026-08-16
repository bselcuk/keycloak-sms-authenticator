package macedit.keycloak.authenticator.directgrant.cache;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.Map;

public class CacheOtpStore implements OtpStore {

    private static final Logger LOG = Logger.getLogger(CacheOtpStore.class);
    
    private final KeycloakSession session;
    private final String keyPrefix;

    public CacheOtpStore(KeycloakSession session) {
        this.session = session;
        this.keyPrefix = "smsotp";
    }

    @Override
    public void save(String realm, String clientId, String username, String code, long ttlSeconds) {
        String key = buildKey(realm, clientId, username);
        SingleUseObjectProvider provider = session.singleUseObjects();
        
        Map<String, String> notes = new HashMap<>();
        notes.put("code", code);
        notes.put("attempts", "0");
        
        provider.put(key, ttlSeconds, notes);
    }

    @Override
    public String get(String realm, String clientId, String username) {
        String key = buildKey(realm, clientId, username);
        SingleUseObjectProvider provider = session.singleUseObjects();
        
        Map<String, String> notes = provider.get(key);
        if (notes != null) {
            return notes.get("code");
        }
        return null;
    }

    @Override
    public long incrementAttempts(String realm, String clientId, String username, int ttlSeconds) {
        String key = buildKey(realm, clientId, username);
        SingleUseObjectProvider provider = session.singleUseObjects();
        
        Map<String, String> notes = provider.get(key);
        if (notes != null) {
            long currentAttempts = 0;
            String attemptStr = notes.get("attempts");
            if (attemptStr != null) {
                try {
                    currentAttempts = Long.parseLong(attemptStr);
                } catch (NumberFormatException ignored) {}
            }
            long newAttempts = currentAttempts + 1;
            
            // The notes map from provider.get() may be immutable. We must copy it.
            Map<String, String> newNotes = new HashMap<>(notes);
            newNotes.put("attempts", String.valueOf(newAttempts));
            provider.put(key, ttlSeconds, newNotes);
            return newAttempts;
        }
        return 0;
    }

    @Override
    public void remove(String realm, String clientId, String username) {
        String key = buildKey(realm, clientId, username);
        SingleUseObjectProvider provider = session.singleUseObjects();
        provider.remove(key);
    }

    private String buildKey(String realm, String clientId, String username) {
        return keyPrefix + ":" + safe(realm) + ":" + safe(clientId) + ":" + safe(username);
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
