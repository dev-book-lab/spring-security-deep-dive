# ClientRegistration과 InMemoryClientRegistrationRepository — 설정 필드와 HTTP 요청 매핑

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `ClientRegistration`의 각 필드(`clientId`, `redirectUri`, `scopes`, `authorizationGrantType`)가 실제 HTTP 요청에서 어떻게 사용되는가?
- `InMemoryClientRegistrationRepository`와 `JdbcClientRegistrationRepository`의 차이와 선택 기준은?
- Spring Security가 기본으로 제공하는 `CommonOAuth2Provider`에 무엇이 포함되어 있는가?
- `redirectUri` 템플릿(`{baseUrl}`, `{registrationId}`)은 런타임에 어떻게 해석되는가?
- 여러 소셜 로그인 제공자를 동시에 지원할 때 각 `registrationId`는 어떻게 구분되는가?
- Google과 카카오 설정의 핵심 차이는 무엇인가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### ClientRegistration이 필요한 이유

```
OAuth2 로그인 흐름에서 필요한 정보들:
  → 어떤 인가 서버를 사용하는가? (Google, Kakao, GitHub...)
  → 클라이언트 식별자는? (client_id)
  → 클라이언트 인증 비밀키는? (client_secret)
  → 어떤 권한을 요청하는가? (scope: email, profile...)
  → 콜백 URL은? (redirect_uri)
  → 인가 URI는? (authorization_uri)
  → Token URI는? (token_uri)
  → 사용자 정보 URI는? (userinfo_uri)

ClientRegistration:
  이 모든 정보를 하나의 객체로 캡슐화
  registrationId로 식별 (google, kakao, github...)
  Spring Security의 모든 OAuth2 컴포넌트가 ClientRegistration을 참조

ClientRegistrationRepository:
  여러 ClientRegistration을 관리하는 저장소
  registrationId로 조회
  기본: InMemoryClientRegistrationRepository (application.yml에서 로드)
```

---

## 😱 흔한 보안 실수

### Before: client_secret을 application.yml에 하드코딩

```yaml
# ❌ Git에 노출되면 즉시 모든 환경 위험
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-secret: "AIzaSyXXXXXXXXXXXX"  # ← 절대 금지

# ✅ 환경 변수 참조
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-secret: ${GOOGLE_CLIENT_SECRET}  # 환경 변수
            # 또는
            client-secret: ${vcap.services.google.credentials.secret} # Cloud Foundry
```

### Before: redirectUri를 하드코딩

```yaml
# ❌ 환경별(dev/prod) 다른 URL을 하드코딩
spring.security.oauth2.client.registration.google.redirect-uri:
  "https://myapp.com/login/oauth2/code/google"
# → 로컬 개발 시 localhost와 불일치

# ✅ {baseUrl} 템플릿 사용
spring.security.oauth2.client.registration.google.redirect-uri:
  "{baseUrl}/login/oauth2/code/{registrationId}"
# → 로컬: http://localhost:8080/login/oauth2/code/google
# → 운영: https://myapp.com/login/oauth2/code/google
# 자동으로 현재 환경의 baseUrl 사용
```

---

## ✨ 올바른 보안 구현

### 다중 소셜 로그인 제공자 설정

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          # ── Google (CommonOAuth2Provider 기본 포함) ───────────
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid, profile, email
            # 기본 redirect-uri: {baseUrl}/login/oauth2/code/{registrationId}
            # provider: CommonOAuth2Provider.GOOGLE 자동 적용

          # ── GitHub (CommonOAuth2Provider 기본 포함) ───────────
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: read:user, user:email

          # ── Kakao (커스텀 provider 필요) ──────────────────────
          kakao:
            client-id: ${KAKAO_CLIENT_ID}
            client-secret: ${KAKAO_CLIENT_SECRET}
            client-authentication-method: client_secret_post
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: profile_nickname, account_email
            client-name: Kakao

          # ── Naver (커스텀 provider 필요) ──────────────────────
          naver:
            client-id: ${NAVER_CLIENT_ID}
            client-secret: ${NAVER_CLIENT_SECRET}
            client-authentication-method: client_secret_post
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: name, email, profile_image
            client-name: Naver

        provider:
          kakao:
            authorization-uri: https://kauth.kakao.com/oauth/authorize
            token-uri: https://kauth.kakao.com/oauth/token
            user-info-uri: https://kapi.kakao.com/v2/user/me
            user-name-attribute: id

          naver:
            authorization-uri: https://nid.naver.com/oauth2.0/authorize
            token-uri: https://nid.naver.com/oauth2.0/token
            user-info-uri: https://openapi.naver.com/v1/nid/me
            user-name-attribute: response
```

### 프로그래밍 방식 ClientRegistration 생성

```java
@Configuration
public class OAuth2ClientConfig {

    // 동적 ClientRegistration 생성 (DB에서 설정 로드 등)
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
            googleRegistration(),
            kakaoRegistration()
        );
    }

    private ClientRegistration googleRegistration() {
        return CommonOAuth2Provider.GOOGLE.getBuilder("google")
            .clientId(System.getenv("GOOGLE_CLIENT_ID"))
            .clientSecret(System.getenv("GOOGLE_CLIENT_SECRET"))
            .scope("openid", "profile", "email")
            .build();
    }

    private ClientRegistration kakaoRegistration() {
        return ClientRegistration.withRegistrationId("kakao")
            .clientId(System.getenv("KAKAO_CLIENT_ID"))
            .clientSecret(System.getenv("KAKAO_CLIENT_SECRET"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("profile_nickname", "account_email")
            .authorizationUri("https://kauth.kakao.com/oauth/authorize")
            .tokenUri("https://kauth.kakao.com/oauth/token")
            .userInfoUri("https://kapi.kakao.com/v2/user/me")
            .userNameAttributeName("id")
            .clientName("Kakao")
            .build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. ClientRegistration 필드와 HTTP 요청 매핑

```java
// ClientRegistration 각 필드가 실제로 사용되는 위치:

ClientRegistration {
    registrationId:       "google"
    // → URL 경로에 사용: /oauth2/authorization/google
    //                     /login/oauth2/code/google

    clientId:             "client-id-value"
    // → 인가 요청 파라미터: ?client_id=client-id-value
    // → Token 요청 Basic Auth: BASE64(client-id:client-secret)

    clientSecret:         "secret"
    // → Token 요청 인증에만 사용 (브라우저 미전달)

    clientAuthenticationMethod: CLIENT_SECRET_BASIC
    // → Token 요청 방식:
    //   BASIC: Authorization: Basic BASE64(id:secret)
    //   POST:  Body: client_id=id&client_secret=secret

    authorizationGrantType: AUTHORIZATION_CODE
    // → Token 요청 파라미터: grant_type=authorization_code

    redirectUri:          "{baseUrl}/login/oauth2/code/{registrationId}"
    // → 인가 요청: ?redirect_uri=http://localhost:8080/login/oauth2/code/google
    // → Token 요청: redirect_uri=http://localhost:8080/login/oauth2/code/google
    // {baseUrl}: 현재 요청의 scheme + host + port
    // {registrationId}: "google"

    scopes:               ["openid", "profile", "email"]
    // → 인가 요청: ?scope=openid+profile+email

    providerDetails {
        authorizationUri: "https://accounts.google.com/o/oauth2/v2/auth"
        // → 인가 요청 기본 URL

        tokenUri:         "https://oauth2.googleapis.com/token"
        // → Token 교환 POST 대상

        userInfoEndpoint {
            uri: "https://openidconnect.googleapis.com/v1/userinfo"
            // → UserInfo GET 대상

            userNameAttributeName: "sub"
            // → OAuth2User.getName() 반환 값의 기준 필드
        }

        jwkSetUri:        "https://www.googleapis.com/oauth2/v3/certs"
        // → OIDC: ID Token 서명 검증용 JWK Set URL
    }
}
```

### 2. CommonOAuth2Provider — 기본 제공 설정

```java
// CommonOAuth2Provider.java
// Spring Security가 기본 제공하는 Google, GitHub, Facebook, Okta

public enum CommonOAuth2Provider {

    GOOGLE {
        @Override
        public Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(registrationId,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, DEFAULT_REDIRECT_URL);
            builder.scope("openid", "profile", "email");
            builder.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth");
            builder.tokenUri("https://www.googleapis.com/oauth2/v4/token");
            builder.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs");
            builder.issuerUri("https://accounts.google.com");
            builder.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo");
            builder.userNameAttributeName(IdTokenClaimNames.SUB);
            builder.clientName("Google");
            return builder;
        }
    },

    GITHUB {
        @Override
        public Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = ...;
            builder.scope("read:user");
            builder.authorizationUri("https://github.com/login/oauth/authorize");
            builder.tokenUri("https://github.com/login/oauth/access_token");
            builder.userInfoUri("https://api.github.com/user");
            builder.userNameAttributeName("id");
            builder.clientName("GitHub");
            return builder;
        }
    };
    // Facebook, Okta도 포함
}

// application.yml에서 registrationId가 "google"이면 CommonOAuth2Provider.GOOGLE 자동 적용
// provider 섹션 없이 registrationId만 설정해도 동작:
// registration.google.client-id/client-secret만 필요
```

### 3. redirectUri 템플릿 해석 과정

```java
// DefaultOAuth2AuthorizationRequestResolver.java
private String expandRedirectUri(HttpServletRequest request,
                                  ClientRegistration clientRegistration) {
    Map<String, String> uriVariables = new HashMap<>();
    uriVariables.put("registrationId", clientRegistration.getRegistrationId());

    // {baseUrl} 계산:
    UriComponents uriComponents = UriComponentsBuilder.fromHttpRequest(
        new ServletServerHttpRequest(request))
        .replacePath(request.getContextPath())
        .replaceQuery(null)
        .fragment(null)
        .build();
    // → http://localhost:8080 (로컬)
    // → https://myapp.com (운영, X-Forwarded-Proto 헤더 고려)

    uriVariables.put("baseUrl", uriComponents.toUriString());

    // {baseUrl}/login/oauth2/code/{registrationId} 치환
    return UriComponentsBuilder.fromUriString(
            clientRegistration.getRedirectUri())
        .buildAndExpand(uriVariables)
        .toUriString();
    // → http://localhost:8080/login/oauth2/code/google
}
// 주의: 리버스 프록시 뒤에서 X-Forwarded-Proto 미설정 시
//       http:// 로 잘못 계산될 수 있음
// server.forward-headers-strategy=native 또는 framework 설정 필요
```

### 4. InMemoryClientRegistrationRepository vs JdbcClientRegistrationRepository

```java
// InMemoryClientRegistrationRepository (기본):
// → application.yml에서 로드 → 메모리에 Map으로 저장
// → 런타임 변경 불가
// → 소규모 서비스, 고정 소셜 로그인에 적합

public class InMemoryClientRegistrationRepository
        implements ClientRegistrationRepository, Iterable<ClientRegistration> {

    private final Map<String, ClientRegistration> registrations;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        return registrations.get(registrationId);
        // registrationId가 없으면 null → IllegalArgumentException
    }
}

// JdbcClientRegistrationRepository (DB 저장):
// → DB에서 동적 로드 (런타임 추가/변경 가능)
// → 다중 테넌트, 관리 UI로 소셜 로그인 추가 시 적합
// → Spring Authorization Server 제공 (별도 의존성)

@Bean
public JdbcClientRegistrationRepository jdbcClientRegistrationRepository(
        JdbcTemplate jdbcTemplate) {
    return new JdbcClientRegistrationRepository(jdbcTemplate);
}
// DB 테이블: oauth2_registered_client (Spring Authorization Server 스키마)
```

---

## 💻 실험으로 확인하기

### 실험 1: 등록된 ClientRegistration 조회

```java
@RestController
@RequiredArgsConstructor
public class OAuth2DebugController {

    private final ClientRegistrationRepository registrations;

    @GetMapping("/debug/oauth2/registrations")
    public List<Map<String, Object>> listRegistrations() {
        List<Map<String, Object>> result = new ArrayList<>();
        ((InMemoryClientRegistrationRepository) registrations)
            .forEach(reg -> result.add(Map.of(
                "registrationId", reg.getRegistrationId(),
                "clientName", reg.getClientName(),
                "scopes", reg.getScopes(),
                "authorizationUri", reg.getProviderDetails().getAuthorizationUri(),
                "userNameAttribute",
                    reg.getProviderDetails().getUserInfoEndpoint()
                       .getUserNameAttributeName()
            )));
        return result;
    }
}
```

### 실험 2: redirectUri 템플릿 해석 확인

```java
@Test
void redirectUriTemplate_resolved_correctly() {
    ClientRegistration google = registrations.findByRegistrationId("google");
    String templateUri = google.getRedirectUri();
    // "{baseUrl}/login/oauth2/code/{registrationId}"

    // 실제 요청에서 해석된 URI:
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setScheme("https");
    request.setServerName("myapp.com");
    request.setServerPort(443);

    String resolvedUri = UriComponentsBuilder.fromUriString(templateUri)
        .buildAndExpand(Map.of(
            "baseUrl", "https://myapp.com",
            "registrationId", "google"
        )).toUriString();

    assertThat(resolvedUri)
        .isEqualTo("https://myapp.com/login/oauth2/code/google");
}
```

### 실험 3: Google vs Kakao 인가 요청 URL 비교

```
Google:
  https://accounts.google.com/o/oauth2/v2/auth
    ?response_type=code
    &client_id={GOOGLE_CLIENT_ID}
    &scope=openid+profile+email
    &state=abc123
    &redirect_uri=http://localhost:8080/login/oauth2/code/google
    &nonce=xyz789           ← OIDC ID Token 재사용 방지
    &code_challenge=SHA256_HASH
    &code_challenge_method=S256

Kakao:
  https://kauth.kakao.com/oauth/authorize
    ?response_type=code
    &client_id={KAKAO_CLIENT_ID}
    &scope=profile_nickname+account_email
    &state=def456
    &redirect_uri=http://localhost:8080/login/oauth2/code/kakao
    # nonce 없음 (OIDC 미지원)
    # code_challenge 없음 (기본 설정, PKCE 미지원 시)
```

---

## 🔒 보안 체크리스트

```
client_secret 관리
  ☐ 환경 변수 또는 Secrets Manager로 주입
  ☐ application.yml, application.properties에 하드코딩 금지
  ☐ Git 히스토리 검색으로 노출 여부 확인

redirectUri 설정
  ☐ {baseUrl} 템플릿 사용 (환경별 URL 하드코딩 방지)
  ☐ 리버스 프록시 뒤: server.forward-headers-strategy 설정
  ☐ 인가 서버에 등록된 URI와 정확히 일치 확인

scope 최소화
  ☐ 필요한 scope만 요청 (openid, profile, email 외 불필요)
  ☐ 카카오: profile_nickname, account_email (친구 목록 등 불필요)
```

---

## 🤔 트레이드오프

```
InMemoryClientRegistrationRepository vs JdbcClientRegistrationRepository:
  InMemory:
    장점  설정 단순, 성능 최적 (메모리 직접 조회)
    단점  런타임 변경 불가, 재배포 필요

  Jdbc:
    장점  런타임 추가/변경, 관리 UI 연동 가능
    단점  DB 의존성, 쿼리 비용
    → 다중 테넌트 SaaS, 소셜 로그인 동적 추가 시

CommonOAuth2Provider vs 커스텀 provider:
  CommonOAuth2Provider:
    장점  Google, GitHub, Facebook, Okta 자동 설정
    단점  카카오, 네이버 등 국내 제공자 미포함

  커스텀 provider:
    장점  어떤 OAuth2/OIDC 서버도 지원 가능
    단점  authorization-uri, token-uri 등 직접 설정 필요
```

---

## 📌 핵심 정리

```
ClientRegistration 주요 필드와 HTTP 매핑
  clientId       → 인가 요청 ?client_id=, Token 요청 인증
  clientSecret   → Token 요청 인증에만 사용 (브라우저 미전달)
  scope          → 인가 요청 ?scope=openid+profile+email
  redirectUri    → 인가/Token 요청 redirect_uri 파라미터
  authorizationUri → 인가 요청 기본 URL
  tokenUri       → Token 교환 POST URL
  userInfoUri    → UserInfo GET URL

redirectUri 템플릿
  {baseUrl}: 현재 요청의 scheme+host+port 자동 계산
  {registrationId}: "google", "kakao" 등 registrationId 자동 치환

CommonOAuth2Provider
  Google, GitHub, Facebook, Okta 자동 설정 포함
  registrationId가 "google"이면 자동 적용
  카카오, 네이버는 provider 섹션에서 직접 설정 필요

userNameAttributeName
  Google: "sub" (OIDC Subject)
  GitHub: "id" (Integer)
  Kakao:  "id" (Long)
  Naver:  "response" (중첩 객체, 추가 파싱 필요)
```

---

## 🤔 생각해볼 문제

**Q1.** 카카오의 `userNameAttributeName`을 `"id"`로 설정하면 `OAuth2User.getName()`은 `String.valueOf(kakao_id)`를 반환합니다. 이 값이 `SecurityContext`에서 `authentication.getName()`으로 사용됩니다. 같은 사람이 Google과 Kakao로 각각 로그인하면 두 개의 별개 계정으로 처리됩니다. 이를 하나의 계정으로 통합(소셜 계정 연결)하는 설계 방법은?

**Q2.** `redirectUri`에 `{baseUrl}` 템플릿을 사용할 때 AWS ALB, Nginx 리버스 프록시 뒤에서 `http://` 로 잘못 계산되어 인가 서버에서 `redirect_uri_mismatch` 오류가 발생합니다. `{baseUrl}`이 HTTPS가 되도록 설정하는 방법은?

**Q3.** 한 Spring 앱에서 동일 제공자(Google)로 여러 용도의 소셜 로그인을 지원해야 합니다. 예를 들어 일반 사용자 Google 로그인과 관리자용 Google 로그인에서 각각 다른 scope와 다른 redirect_uri를 사용해야 한다면 어떻게 설정하는가?

> 💡 **해설**
>
> **Q1.** 소셜 계정 통합(Account Linking)은 이메일 기반 매칭이 가장 일반적입니다. `CustomOAuth2UserService`에서 소셜 로그인 성공 후 이메일을 추출해 DB에서 같은 이메일을 가진 기존 계정을 조회합니다. 찾으면 해당 계정에 소셜 제공자 정보를 추가(`user_social_accounts` 테이블에 `provider`, `provider_id` 저장)하고 기존 계정으로 로그인 처리합니다. 찾지 못하면 새 계정을 생성합니다. 단, 이메일 검증 없이 이메일만으로 계정을 자동 연결하면 이메일을 동일하게 사용하는 다른 사람의 계정이 연결되는 보안 취약점이 있습니다. 이메일이 `verified`인 경우에만 자동 연결하거나, 사용자에게 확인 후 연결하는 명시적 흐름을 사용합니다.
>
> **Q2.** 리버스 프록시가 `X-Forwarded-Proto: https` 헤더를 전달하는 경우 `server.forward-headers-strategy=native`를 설정하면 Spring Boot가 이 헤더를 신뢰해 `{baseUrl}`을 `https://`로 계산합니다. 또는 `server.forward-headers-strategy=framework`로 `ForwardedHeaderFilter`를 활성화합니다. AWS ALB의 경우 기본적으로 `X-Forwarded-Proto` 헤더를 포함합니다. Nginx는 `proxy_set_header X-Forwarded-Proto $scheme;`를 설정합니다. 신뢰할 수 없는 프록시에서 이 헤더가 조작되지 않도록 `server.tomcat.remote-ip-header`와 `internal-proxies`를 함께 설정합니다.
>
> **Q3.** 같은 제공자라도 다른 `registrationId`로 여러 번 등록하면 됩니다. 예를 들어 `google-user`와 `google-admin`으로 각각 등록합니다. `google-user`에는 `scope: openid, profile, email`과 `redirect-uri: {baseUrl}/login/oauth2/code/google-user`, `google-admin`에는 `scope: openid, profile, email, admin-scope`와 `redirect-uri: {baseUrl}/login/oauth2/code/google-admin`을 설정합니다. Google Console에도 두 가지 redirect_uri를 모두 등록해야 합니다. 인가 요청 URL은 각각 `/oauth2/authorization/google-user`, `/oauth2/authorization/google-admin`이 됩니다. `CustomOAuth2UserService`에서 `registrationId`를 확인해 역할을 다르게 부여합니다.

---

<div align="center">

**[← 이전: OAuth2LoginAuthenticationFilter 동작](./03-oauth2-login-filter.md)** | **[홈으로 🏠](../README.md)** | **[다음: OAuth2AuthorizedClient 관리 ➡️](./05-oauth2-authorized-client.md)**

</div>
