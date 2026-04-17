package com.platform.keycloak.hash;

import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

public class SberpdiMurmurIdpMapper extends AbstractIdentityProviderMapper {
    private static final Logger LOG = Logger.getLogger(SberpdiMurmurIdpMapper.class);

    public static final String PROVIDER_ID = "sberpdi-murmur-idp-mapper";

    private static final String CFG_STATIC_WORD = "staticWord";
    private static final String CFG_INCLUDE_STATIC_WORD = "includeStaticWord";
    private static final String CFG_TARGET_ATTRIBUTE = "targetAttribute";
    private static final String CFG_CUSTOM_CLAIMS = "customClaims";
    private static final String CFG_LOG_DEBUG = "logDebug";
    private static final String CFG_USE_USERINFO = "useUserInfo";
    private static final String CTX_USERINFO_JSON = "sberpdi.userinfo.json";
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    private static final List<ClaimOption> CLAIM_OPTIONS = List.of(
        new ClaimOption("useClaimSberpdi", "sberpdi", "Use claim: sberpdi", true),
        new ClaimOption("useClaimSberPDI", "sberPDI", "Use claim: sberPDI", false),
        new ClaimOption("useClaimPreferredUsername", "preferred_username", "Use claim: preferred_username", false),
        new ClaimOption("useClaimEmail", "email", "Use claim: email", false),
        new ClaimOption("useClaimGivenName", "given_name", "Use claim: given_name", false),
        new ClaimOption("useClaimFamilyName", "family_name", "Use claim: family_name", false),
        new ClaimOption("useClaimPatronymic", "patronymic", "Use claim: patronymic", false),
        new ClaimOption("useClaimName", "name", "Use claim: name", false),
        new ClaimOption("useClaimTbCode", "tbcode", "Use claim: tbcode", false),
        new ClaimOption("useClaimBranchCode", "branchcode", "Use claim: branchcode", false),
        new ClaimOption("useClaimSubbranchCode", "subbranchcode", "Use claim: subbranchcode", false),
        new ClaimOption("useClaimDepartmentNumber", "departmentnumber", "Use claim: departmentnumber", false),
        new ClaimOption("useClaimEmployeeNumber", "employeenumber", "Use claim: employeenumber", false),
        new ClaimOption("useClaimBusinessCategory", "businesscategory", "Use claim: businesscategory", false),
        new ClaimOption("useClaimHcmCode", "hcmcode", "Use claim: hcmcode", false),
        new ClaimOption("useClaimPosition", "position", "Use claim: position", false),
        new ClaimOption("useClaimSapLogin", "saplogin", "Use claim: saplogin", false),
        new ClaimOption("useClaimLastAccessDate", "lastaccessdate", "Use claim: lastaccessdate", false),
        new ClaimOption("useClaimLastFailAccessDate", "lastfailaccessdate", "Use claim: lastfailaccessdate", false),
        new ClaimOption("useClaimGroups", "groups", "Use claim: groups (array)", false),
        new ClaimOption("useClaimAccessList", "accesslist", "Use claim: accesslist (array)", false),
        new ClaimOption("useClaimInsiderTypes", "insidertypes", "Use claim: insidertypes (array)", false),
        new ClaimOption("useClaimCertIssuer", "cert_issuer", "Use claim: cert_issuer", false),
        new ClaimOption("useClaimCertSubject", "cert_subject", "Use claim: cert_subject", false),
        new ClaimOption("useClaimCertSn", "cert_sn", "Use claim: cert_sn", false)
    );

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        List<ProviderConfigProperty> props = new ArrayList<>();
        props.add(stringProperty(
            CFG_TARGET_ATTRIBUTE,
            "Target user attribute",
            "Куда сохранять вычисленный murmurhash3",
            "profileHash"
        ));
        props.add(boolProperty(
            CFG_INCLUDE_STATIC_WORD,
            "Include static word",
            "Добавлять static word в формулу хэша",
            true
        ));
        props.add(stringProperty(
            CFG_STATIC_WORD,
            "Static word",
            "Статичное слово для формулы (по ТЗ: scim-adapter)",
            "scim-adapter"
        ));
        props.add(stringProperty(
            CFG_CUSTOM_CLAIMS,
            "Custom claims",
            "Дополнительные claim через запятую (например: tbcode,azp,aud)",
            ""
        ));
        props.add(boolProperty(
            CFG_LOG_DEBUG,
            "Log debug",
            "Включает диагностические логи выбранных claim и источника значений",
            true
        ));
        props.add(boolProperty(
            CFG_USE_USERINFO,
            "Use userInfo endpoint",
            "Если claim нет в токене, запрашивать userInfo endpoint и брать значения оттуда",
            true
        ));

        for (ClaimOption option : CLAIM_OPTIONS) {
            props.add(boolProperty(option.configKey(), option.label(), "Включить claim в расчет хэша", option.enabledByDefault()));
        }
        CONFIG_PROPERTIES = Collections.unmodifiableList(props);
    }

    @Override
    public String[] getCompatibleProviders() {
        return new String[] {"oidc"};
    }

    @Override
    public String getDisplayCategory() {
        return "Token Importer";
    }

    @Override
    public String getDisplayType() {
        return "SberPDI Murmur3 Hash Mapper";
    }

    @Override
    public String getHelpText() {
        return "Считает murmurhash3 по выбранным claim из токена внешнего IdP и пишет в user attribute";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel,
                              BrokeredIdentityContext context) {
        applyHash(user, mapperModel, context, true);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
                                   IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        applyHash(user, mapperModel, context, false);
    }

    @Override
    public void updateBrokeredUserLegacy(KeycloakSession session, RealmModel realm, UserModel user,
                                         IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        applyHash(user, mapperModel, context, false);
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
                                            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        boolean logDebug = Boolean.parseBoolean(getConfig(mapperModel, CFG_LOG_DEBUG, "true"));
        boolean useUserInfo = Boolean.parseBoolean(getConfig(mapperModel, CFG_USE_USERINFO, "true"));

        TokenBundle tokens = extractTokenBundle(context.getToken());
        JsonNode userInfo = useUserInfo ? resolveUserInfo(context, tokens.accessToken(), logDebug) : null;

        if (logDebug) {
            LOG.infof(
                "IdP mapper incoming user before mapping realm=%s brokerUserId=%s username=%s email=%s firstName=%s lastName=%s attributes=%s accessTokenPayload=%s idTokenPayload=%s userInfo=%s tokenResponse=%s",
                realm == null ? "" : realm.getName(),
                safe(context.getId()),
                safe(context.getUsername()),
                safe(context.getEmail()),
                safe(context.getFirstName()),
                safe(context.getLastName()),
                context.getAttributes(),
                tokens.accessPayload() == null ? "null" : tokens.accessPayload().toString(),
                tokens.idPayload() == null ? "null" : tokens.idPayload().toString(),
                userInfo == null ? "null" : userInfo.toString(),
                tokens.tokenResponse() == null ? "null" : tokens.tokenResponse().toString()
            );
        }
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    private void applyHash(UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context,
                           boolean isNewUser) {
        String staticWord = getConfig(mapperModel, CFG_STATIC_WORD, "scim-adapter");
        boolean includeStaticWord = Boolean.parseBoolean(getConfig(mapperModel, CFG_INCLUDE_STATIC_WORD, "true"));
        String targetAttribute = getConfig(mapperModel, CFG_TARGET_ATTRIBUTE, "profileHash");
        boolean logDebug = Boolean.parseBoolean(getConfig(mapperModel, CFG_LOG_DEBUG, "true"));
        boolean useUserInfo = Boolean.parseBoolean(getConfig(mapperModel, CFG_USE_USERINFO, "true"));

        TokenBundle tokens = extractTokenBundle(context.getToken());
        JsonNode userInfo = useUserInfo ? resolveUserInfo(context, tokens.accessToken(), logDebug) : null;
        List<String> selectedClaims = collectSelectedClaims(mapperModel);
        if (selectedClaims.isEmpty()) {
            LOG.warnf("Mapper '%s' has no selected claims. Nothing to hash for userId=%s", PROVIDER_ID, user.getId());
            return;
        }

        List<String> parts = new ArrayList<>();
        List<String> valueParts = new ArrayList<>();
        List<String> usedSources = new ArrayList<>();
        for (String claim : selectedClaims) {
            ClaimValue value = resolveClaimValue(context, tokens.accessPayload(), tokens.idPayload(), userInfo, claim);
            if (value == null || value.value().isBlank()) {
                continue;
            }
            parts.add(claim + "=" + value.value());
            valueParts.add(value.value());
            usedSources.add(claim + ":" + value.source());
        }
        if (includeStaticWord && !staticWord.isBlank()) {
            parts.add("staticWord=" + staticWord);
            valueParts.add(staticWord);
        }

        if (valueParts.isEmpty()) {
            LOG.warnf("Cannot build murmurhash3 for userId=%s. None of selected claims has value", user.getId());
            return;
        }

        String source = String.join("", valueParts);
        String hash = Murmur3Hasher.hashUuid(source);
        user.setSingleAttribute(targetAttribute, hash);

        if (logDebug) {
            LOG.infof("IdP mapper hash updated userId=%s attr=%s hash=%s selectedClaims=%s used=%s parts=%s valueParts=%s source=%s mode=%s",
                user.getId(), targetAttribute, hash, selectedClaims, usedSources, parts, valueParts, source,
                isNewUser ? "import" : "update");
        }
    }

    private List<String> collectSelectedClaims(IdentityProviderMapperModel mapperModel) {
        Set<String> selected = new LinkedHashSet<>();
        for (ClaimOption option : CLAIM_OPTIONS) {
            boolean enabled = Boolean.parseBoolean(getConfig(
                mapperModel,
                option.configKey(),
                String.valueOf(option.enabledByDefault())
            ));
            if (enabled) {
                selected.add(option.claimName());
            }
        }
        String customClaims = getConfig(mapperModel, CFG_CUSTOM_CLAIMS, "");
        if (!customClaims.isBlank()) {
            for (String claim : customClaims.split(",")) {
                String normalized = claim == null ? "" : claim.trim();
                if (!normalized.isBlank()) {
                    selected.add(normalized);
                }
            }
        }
        return new ArrayList<>(selected);
    }

    private ClaimValue resolveClaimValue(
        BrokeredIdentityContext context,
        JsonNode accessPayload,
        JsonNode idPayload,
        JsonNode userInfo,
        String claim
    ) {
        String fromContext = context.getUserAttribute(claim);
        if (isNotBlank(fromContext)) {
            return new ClaimValue(fromContext, claim, "context-attribute");
        }
        String fromAccessPayload = jsonTextValue(accessPayload, claim);
        if (isNotBlank(fromAccessPayload)) {
            return new ClaimValue(fromAccessPayload, claim, "access-token-payload");
        }
        String fromIdPayload = jsonTextValue(idPayload, claim);
        if (isNotBlank(fromIdPayload)) {
            return new ClaimValue(fromIdPayload, claim, "id-token-payload");
        }
        String fromUserInfo = jsonTextValue(userInfo, claim);
        if (isNotBlank(fromUserInfo)) {
            return new ClaimValue(fromUserInfo, claim, "user-info");
        }
        return null;
    }

    private TokenBundle extractTokenBundle(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return new TokenBundle(rawToken, null, null, null, null, null);
        }
        String trimmed = rawToken.trim();
        if (trimmed.startsWith("{")) {
            try {
                JsonNode tokenResponse = JsonSerialization.readValue(trimmed, JsonNode.class);
                String accessToken = jsonTextValue(tokenResponse, "access_token");
                String idToken = jsonTextValue(tokenResponse, "id_token");
                return new TokenBundle(
                    rawToken,
                    accessToken,
                    idToken,
                    decodeJwtPayload(accessToken),
                    decodeJwtPayload(idToken),
                    tokenResponse
                );
            } catch (Exception e) {
                LOG.warnf("Cannot parse token response JSON: %s", e.getMessage());
            }
        }
        return new TokenBundle(rawToken, trimmed, null, decodeJwtPayload(trimmed), null, null);
    }

    private JsonNode decodeJwtPayload(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return null;
        }
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
            String jsonPayload = new String(decoded, StandardCharsets.UTF_8);
            return JsonSerialization.readValue(jsonPayload, JsonNode.class);
        } catch (Exception e) {
            return null;
        }
    }

    private JsonNode resolveUserInfo(BrokeredIdentityContext context, String accessToken, boolean logDebug) {
        Map<String, Object> ctx = ensureContextDataMap(context);
        Object cached = ctx.get(CTX_USERINFO_JSON);
        if (cached instanceof JsonNode cachedNode) {
            return cachedNode;
        }

        if (accessToken == null || accessToken.isBlank()) {
            if (logDebug) {
                LOG.info("userInfo fetch skipped: access token is missing");
            }
            return null;
        }
        IdentityProviderModel idpModel = context.getIdpConfig();
        if (idpModel == null) {
            if (logDebug) {
                LOG.info("userInfo fetch skipped: idp config is missing");
            }
            return null;
        }
        OAuth2IdentityProviderConfig idpConfig = new OAuth2IdentityProviderConfig(idpModel);
        String userInfoUrl = idpConfig.getUserInfoUrl();
        if (userInfoUrl == null || userInfoUrl.isBlank()) {
            if (logDebug) {
                LOG.infof("userInfo fetch skipped: userInfoUrl is empty for idp=%s", idpModel.getAlias());
            }
            return null;
        }

        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(userInfoUrl))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();
            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() / 100 != 2) {
                LOG.warnf("userInfo request failed status=%d body=%s", response.statusCode(), response.body());
                return null;
            }
            JsonNode userInfo = JsonSerialization.readValue(response.body(), JsonNode.class);
            ctx.put(CTX_USERINFO_JSON, userInfo);
            if (logDebug) {
                LOG.infof("userInfo response status=%d body=%s", response.statusCode(), userInfo.toString());
            }
            return userInfo;
        } catch (Exception e) {
            LOG.warnf("userInfo request failed: %s", e.getMessage());
            return null;
        }
    }

    private Map<String, Object> ensureContextDataMap(BrokeredIdentityContext context) {
        Map<String, Object> existing = context.getContextData();
        if (existing != null && existing.getClass() == HashMap.class) {
            return existing;
        }
        Map<String, Object> copy = existing == null ? new HashMap<>() : new HashMap<>(existing);
        context.setContextData(copy);
        return copy;
    }

    private String jsonTextValue(JsonNode node, String fieldName) {
        if (node == null || fieldName == null || fieldName.isBlank() || !node.has(fieldName) || node.get(fieldName).isNull()) {
            return null;
        }
        JsonNode value = node.get(fieldName);
        if (value.isArray()) {
            StringJoiner joiner = new StringJoiner(",");
            for (JsonNode item : value) {
                if (item == null || item.isNull()) {
                    continue;
                }
                if (item.isTextual() || item.isNumber() || item.isBoolean()) {
                    joiner.add(item.asText());
                } else {
                    joiner.add(item.toString());
                }
            }
            return joiner.toString();
        }
        if (value.isTextual() || value.isNumber() || value.isBoolean()) {
            return value.asText();
        }
        return value.toString();
    }

    private boolean isNotBlank(String value) {
        return value != null && !value.isBlank();
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private String getConfig(IdentityProviderMapperModel mapperModel, String key, String fallback) {
        Map<String, String> config = mapperModel == null ? Collections.emptyMap() : mapperModel.getConfig();
        if (config == null) {
            return fallback;
        }
        String value = config.get(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static ProviderConfigProperty stringProperty(String name, String label, String helpText, String defaultValue) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setHelpText(helpText);
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(defaultValue);
        return property;
    }

    private static ProviderConfigProperty boolProperty(String name, String label, String helpText, boolean defaultValue) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setHelpText(helpText);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(defaultValue);
        return property;
    }

    private record ClaimValue(String value, String claimName, String source) {
    }

    private record ClaimOption(String configKey, String claimName, String label, boolean enabledByDefault) {
    }

    private record TokenBundle(
        String rawToken,
        String accessToken,
        String idToken,
        JsonNode accessPayload,
        JsonNode idPayload,
        JsonNode tokenResponse
    ) {
    }
}
