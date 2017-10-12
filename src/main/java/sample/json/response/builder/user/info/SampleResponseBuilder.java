package sample.json.response.builder.user.info;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.claim.mgt.ClaimManagerHandler;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class represents a sample userinfo response builder which filters the claims based on service provider's
 * requested claims.
 */
public class SampleResponseBuilder implements UserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(SampleResponseBuilder.class);
    private static final String SP_DIALECT = "http://wso2.org/oidc/claim";
    private static final String INBOUND_AUTH2_TYPE = "oauth2";

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {

        Map<ClaimMapping, String> userAttributes = getUserAttributesFromCache(tokenResponse);
        Map<String, Object> claims;

        if (userAttributes == null || userAttributes.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache. Trying to retrieve from user store.");
            }
            claims = getClaimsFromUserStore(tokenResponse);
        } else {
            claims = getClaimsMap(userAttributes);
        }
        if (claims == null) {
            claims = new HashMap<>();
        }
        if (!claims.containsKey("sub") || StringUtils.isBlank((String) claims.get("sub"))) {
            claims.put("sub", tokenResponse.getAuthorizedUser());
        }
        return JSONUtils.buildJSON(claims);
    }

    private Map<ClaimMapping, String> getUserAttributesFromCache(OAuth2TokenValidationResponseDTO tokenResponse) {
        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(tokenResponse
                                                             .getAuthorizationContextToken().getTokenString());
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                                                                         .getValueFromCacheByToken(cacheKey);
        if (cacheEntry == null) {
            return new HashMap<>();
        }

        return cacheEntry.getUserAttributes();
    }

    private Map<String, Object> getClaimsFromUserStore(OAuth2TokenValidationResponseDTO tokenResponse) throws
            UserInfoEndpointException {

        Map<String, Object> mappedAppClaims = new HashMap<>();
        String username = tokenResponse.getAuthorizedUser();
        String tenantDomain = MultitenantUtils.getTenantDomain(tokenResponse.getAuthorizedUser());
        UserRealm realm;
        List<String> claimURIList = new ArrayList<>();

        try {
            realm = IdentityTenantUtil.getRealm(tenantDomain, username);

            if (realm == null) {
                log.warn("No valid tenant domain provider. Empty claim returned back");
                return new HashMap<>();
            }

            Map<String, String> spToLocalClaimMappings;

            UserStoreManager userstore = realm.getUserStoreManager();
            TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();

            AccessTokenDO accessTokenDO = tokenMgtDAO.retrieveAccessToken(tokenResponse.getAuthorizationContextToken()
                                                                               .getTokenString(), false);
            ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder
                    .getApplicationMgtService();
            String clientId = null;
            if (accessTokenDO != null) {
                clientId = accessTokenDO.getConsumerKey();
            }

            String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, INBOUND_AUTH2_TYPE,
                                                                                   tenantDomain);
            ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName,
                                                                                                        tenantDomain);
            if (serviceProvider == null) {
                return mappedAppClaims;
            }

            // Retrieve requested claim of the service provider.
            ClaimMapping[] requestedLocalClaimMap = serviceProvider.getClaimConfig().getClaimMappings();

            if (requestedLocalClaimMap != null && requestedLocalClaimMap.length > 0) {

                for (ClaimMapping claimMapping : requestedLocalClaimMap) {
                    claimURIList.add(claimMapping.getLocalClaim().getClaimUri());
                }
                if (log.isDebugEnabled()) {
                    log.debug("Requested number of local claims: " + claimURIList.size());
                }
                spToLocalClaimMappings = ClaimManagerHandler.getInstance().getMappingsMapFromOtherDialectToCarbon
                        (SP_DIALECT, null, tenantDomain, true);

                Map<String, String> userClaims = userstore.getUserClaimValues(MultitenantUtils.getTenantAwareUsername
                        (username), claimURIList.toArray(new String[claimURIList.size()]), null);

                if (log.isDebugEnabled()) {
                    log.debug("User claims retrieved from user store: " + userClaims.size());
                }

                if (MapUtils.isEmpty(userClaims)) {
                    return new HashMap<>();
                }

                for (Map.Entry<String, String> entry : userClaims.entrySet()) {
                    String value = spToLocalClaimMappings.get(entry.getKey());
                    if (value != null) {
                        mappedAppClaims.put(value, entry.getValue());
                        if (log.isDebugEnabled() &&
                            IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                            log.debug("Mapped claim: key -  " + value + " value -" + entry.getValue());
                        }
                    }
                }
            }
        } catch (Exception e) {
            if(e instanceof UserStoreException){
                if (e.getMessage().contains("UserNotFound")) {
                    if (log.isDebugEnabled()) {
                        log.debug("User " + username + " not found in user store");
                    }
                }
            } else {
                log.error("Error while retrieving the claims from user store for " + username, e);
                throw new UserInfoEndpointException("Error while retrieving the claims from user store for " + username);
            }
        }
        return mappedAppClaims;
    }

    private Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes) {
        Map<String, Object> claims = new HashMap<String, Object>();
        if (userAttributes != null && !userAttributes.isEmpty()) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()){
                if (IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR.equals(entry.getKey().getRemoteClaim()
                                                                                .getClaimUri())){
                    continue;
                }
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }
}
