# Authorization Code Flow 완전 분석 — 10단계 전 과정과 state 파라미터

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `/oauth2/authorization/{registrationId}` 요청부터 로그인 완료까지 내부에서 일어나는 10단계는?
- `state` 파라미터가 세션에 저장되고 콜백에서 검증되는 정확한 코드 경로는?
- `OAuth2AuthorizationRequest`가 어떻게 생성되어 `AuthorizationRequestRepository`에 저장되는가?
- Token Endpoint 호출이 브라우저가 아닌 서버 간 통신으로 이루어지는 이유는?
- `DefaultAuthorizationCodeTokenResponseClient`는 내부적으로 어떻게 Token 교환을 수행하는가?
- 카카오, 네이버처럼 비표준 사용자 정보 API를 가진 제공자를 어떻게 설정하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### Authorization Code Flow 10단계 전체 그림

```
브라우저(사용자)           Spring 앱(클라이언트)          인가 서버(Google 등)
     │                          │                              │
     │ GET /oauth2/authorization/google                        │
     │ ────────────────────────>│                              │
     │                          │ ① OAuth2AuthorizationRequest 생성
     │                          │   state, code_challenge 생성
     │                          │   세션에 저장                   │
     │ 302 Redirect             │                              │
     │ <────────────────────────│                              │
     │                          │                              │
     │ GET /authorize?response_type=code&state=...&code_challenge=...
     │ ─────────────────────────────────────────────────────>  │
     │                          │              ② 로그인 페이지 표시
     │ ────────────── 사용자가 ID/PW 입력, 권한 동의 ────────       │
     │                          │                              │
     │ ③ GET /callback?code=XXX&state=YYY                      │
     │ <─────────────────────────────────────────────────────  │
     │                          │                              │
     │ GET /login/oauth2/code/google?code=XXX&state=YYY        │
     │ ────────────────────────>│                              │
     │                          │ ④ state 검증 (세션과 비교)       │
     │                          │ ⑤ POST /oauth2/token         │
     │                          │   code + code_verifier       │
     │                          │ ─────────────────────────>   │
     │                          │              ⑥ Access Token 반환
     │                          │ <─────────────────────────   │
     │                          │ ⑦ GET /userinfo (Access Token)
     │                          │ ─────────────────────────>   │
     │                          │              ⑧ 사용자 정보 반환
     │                          │ <─────────────────────────   │
     │                          │ ⑨ OAuth2User 생성
     │                          │   SecurityContext에 저장       │
     │ ⑩ 302 Redirect → /home  │                               │
     │ <────────────────────────│                              │
```

---

## 😱 흔한 보안 실수

### Before: redirect_uri를 와일드카드로 등록

```java
// ❌ 인가 서버(Google, Kakao)에서 redirect_uri 와일드카드 등록
// 인가 서버 설정: https://myapp.com/callback/*
// → 공격자: https://myapp.com/callback/../../evil 같은 경로로 code 탈취 가능

// ✅ 정확한 redirect_uri만 등록
// Google Console: https://myapp.com/login/oauth2/code/google
// Spring 설정:
spring.security.oauth2.client.registration.google.redirect-uri:
  "{baseUrl}/login/oauth2/code/{registrationId}"
// → 정확히 일치하는 URI만 허용
```

### Before: code를 재사용할 수 있도록 방치

```java
// Authorization Code는 1회용 단기 토큰
// 사용된 code를 다시 사용하려 하면 인가 서버가 거부해야 함
// 일부 취약한 구현에서 code를 여러 번 사용 가능한 경우:
// → 공격자가 code를 가로채서 사용 가능

// Spring Security는 code 수신 후 즉시 Token 교환 (OAuth2LoginAuthenticationFilter)
// → code를 저장하지 않음 → 재사용 공격면 최소화
// 추가 방어: code 수명 5~10분 설정 (인가 서버에서)
```

---

## ✨ 올바른 보안 구현

### 카카오 OAuth2 설정 예시 (비표준 제공자)

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          kakao:
            client-id: ${KAKAO_CLIENT_ID}
            client-secret: ${KAKAO_CLIENT_SECRET}
            client-authentication-method: client_secret_post
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/kakao"
            scope: profile_nickname, account_email
            client-name: Kakao

        provider:
          kakao:
            authorization-uri: https://kauth.kakao.com/oauth/authorize
            token-uri: https://kauth.kakao.com/oauth/token
            user-info-uri: https://kapi.kakao.com/v2/user/me
            user-name-attribute: id  # 카카오 응답에서 사용자 식별자 필드

# Google (Spring Security 기본 제공자)
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid, profile, email
            # provider는 CommonOAuth2Provider.GOOGLE으로 자동 설정
```

---

## 🔬 내부 동작 원리

### 1. 단계 ①: OAuth2AuthorizationRequestRedirectFilter

```java
// OAuth2AuthorizationRequestRedirectFilter.java
// /oauth2/authorization/{registrationId} 요청 처리

public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
    private AuthorizationRequestRepository<OAuth2AuthorizationRequest>
        authorizationRequestRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, ...) {
        OAuth2AuthorizationRequest authorizationRequest =
            // ① OAuth2AuthorizationRequest 생성
            this.authorizationRequestResolver.resolve(request);
            // → ClientRegistration 조회
            // → state 생성 (SecureRandom UUID)
            // → PKCE: code_verifier 생성, code_challenge 계산
            // → 인가 URI 파라미터 조합

        if (authorizationRequest != null) {
            // ② 세션에 저장 (state와 요청 정보)
            this.authorizationRequestRepository.saveAuthorizationRequest(
                authorizationRequest, request, response);
            // HttpSessionOAuth2AuthorizationRequestRepository:
            // → HttpSession.setAttribute("SPRING_SECURITY_2_0_REQUEST_ATTR_NAME", request)

            // ③ 인가 URI로 리다이렉트
            sendRedirectForAuthorization(request, response, authorizationRequest);
            // → response.sendRedirect(authorizationRequest.getAuthorizationRequestUri())
        }
    }
}

// DefaultOAuth2AuthorizationRequestResolver가 생성하는 URI 예시:
// https://accounts.google.com/o/oauth2/auth
//   ?response_type=code
//   &client_id={clientId}
//   &scope=openid+profile+email
//   &state={randomState}               ← CSRF 방어
//   &redirect_uri=http://app/callback
//   &code_challenge={sha256Challenge}  ← PKCE (Public Client)
//   &code_challenge_method=S256
```

### 2. 단계 ④⑤⑥: OAuth2LoginAuthenticationFilter (콜백 처리)

```java
// OAuth2LoginAuthenticationFilter.java
// /login/oauth2/code/{registrationId} 처리

public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request, HttpServletResponse response) {

        // ④ state 검증
        OAuth2AuthorizationRequest authorizationRequest =
            this.authorizationRequestRepository
                .removeAuthorizationRequest(request, response);
        // → 세션에서 저장된 OAuth2AuthorizationRequest 꺼냄 (삭제)
        // → 세션의 state와 요청 파라미터의 state 비교
        // → 불일치 → OAuth2AuthenticationException("invalid_state_parameter")

        // Authorization Code 추출
        String code = request.getParameter("code");
        OAuth2AuthorizationExchange exchange = new OAuth2AuthorizationExchange(
            authorizationRequest,           // 저장된 요청 (state, code_verifier 포함)
            new OAuth2AuthorizationResponse(code, state, ...)); // 받은 응답

        // ⑤⑥ Provider에게 인증 위임
        // OAuth2LoginAuthenticationToken(unauthenticated)
        OAuth2LoginAuthenticationToken authToken =
            new OAuth2LoginAuthenticationToken(
                clientRegistration, exchange);

        return this.getAuthenticationManager()
            .authenticate(authToken);
        // → OAuth2LoginAuthenticationProvider.authenticate()
        //   → Token 교환 (서버 → 서버)
        //   → UserInfo 조회
    }
}
```

### 3. 단계 ⑤⑥: DefaultAuthorizationCodeTokenResponseClient

```java
// OAuth2AuthorizationCodeAuthenticationProvider.java
public Authentication authenticate(Authentication authentication) {

    OAuth2AuthorizationCodeAuthenticationToken authCodeToken = ...;

    // ⑤ Token Endpoint 호출 (서버 간 통신, 브라우저 아님)
    OAuth2AccessTokenResponse tokenResponse =
        this.accessTokenResponseClient.getTokenResponse(
            new OAuth2AuthorizationCodeGrantRequest(
                clientRegistration, authorizationExchange));
    // DefaultAuthorizationCodeTokenResponseClient:
    // POST {token_uri}
    //   grant_type=authorization_code
    //   &code={authCode}
    //   &redirect_uri={redirectUri}
    //   &code_verifier={verifier}  ← PKCE verifier
    //   + Authorization: Basic {clientId:clientSecret} (또는 Form)

    // ⑥ Access Token 수신
    // tokenResponse.getAccessToken().getTokenValue()

    // ⑦⑧ UserInfo 조회
    OAuth2User oauth2User = this.userService.loadUser(
        new OAuth2UserRequest(clientRegistration, tokenResponse.getAccessToken()));

    return new OAuth2LoginAuthenticationToken(
        clientRegistration, authorizationExchange,
        oauth2User, authorities, tokenResponse.getAccessToken());
}
```

### 4. 단계 ⑦⑧: DefaultOAuth2UserService

```java
// DefaultOAuth2UserService.java
public OAuth2User loadUser(OAuth2UserRequest userRequest) {

    // ⑦ UserInfo Endpoint 호출
    // GET {userinfo_uri}
    //   Authorization: Bearer {accessToken}
    String userInfoUri = userRequest.getClientRegistration()
        .getProviderDetails().getUserInfoEndpoint().getUri();

    // ⑧ 사용자 정보 수신 → OAuth2User 생성
    Map<String, Object> userAttributes = restOperations.exchange(
        userInfoUri, GET, request, Map.class).getBody();

    String userNameAttributeName = userRequest.getClientRegistration()
        .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
    // 카카오: "id", 구글: "sub", 깃허브: "login"

    return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
}
```

### 5. state 파라미터와 CSRF 방어 상세

```java
// HttpSessionOAuth2AuthorizationRequestRepository.java

// 저장 (단계 ①):
public void saveAuthorizationRequest(OAuth2AuthorizationRequest request,
                                      HttpServletRequest httpRequest, ...) {
    String state = request.getState(); // 랜덤 UUID
    // HttpSession에 state → OAuth2AuthorizationRequest 매핑으로 저장
    // 세션 속성명: "org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.AUTHORIZATION_REQUEST"
    Map<String, OAuth2AuthorizationRequest> savedRequests = getRequests(httpRequest);
    savedRequests.put(state, request);
}

// 조회 및 검증 (단계 ④):
public OAuth2AuthorizationRequest removeAuthorizationRequest(
        HttpServletRequest request, HttpServletResponse response) {
    String state = request.getParameter(OAuth2ParameterNames.STATE);
    Map<String, OAuth2AuthorizationRequest> savedRequests = getRequests(request);
    OAuth2AuthorizationRequest savedRequest = savedRequests.remove(state);
    // state가 세션에 없으면 null 반환 → Filter가 예외 처리
    return savedRequest;
}
// → 세션에 저장된 state와 콜백의 state가 다르면 null → 인증 실패
```

---

## 💻 실험으로 확인하기

### 실험 1: Authorization Code Flow 전체 로그 관찰

```yaml
logging:
  level:
    org.springframework.security.oauth2: DEBUG
    org.springframework.security.web.authentication: DEBUG
```

```
# 기대 로그 (단계별):
DEBUG OAuth2AuthorizationRequestRedirectFilter - Initiating OAuth2 login
DEBUG OAuth2AuthorizationRequestRedirectFilter - Redirecting to Authorization Endpoint:
  https://accounts.google.com/o/oauth2/auth?...&state=abc123&code_challenge=xyz

# 콜백 수신 후:
DEBUG OAuth2LoginAuthenticationFilter - Request matches pattern
DEBUG OAuth2LoginAuthenticationFilter - Attempting authentication
DEBUG OAuth2AuthorizationCodeAuthenticationProvider - Exchanging code for Access Token
DEBUG DefaultOAuth2UserService - Loading user from UserInfo endpoint
DEBUG OAuth2LoginAuthenticationFilter - Authentication success
```

### 실험 2: state 불일치 시 동작 확인

```bash
# 정상 state로 시작
GET /oauth2/authorization/google → 세션에 state=abc123 저장

# 다른 state로 콜백 위조 (CSRF 공격 시뮬레이션)
GET /login/oauth2/code/google?code=validCode&state=wrong123

# 결과: 401 또는 인증 실패
# 로그: "State parameter doesn't match"
# → CSRF 방어 동작 확인
```

### 실험 3: 카카오 UserInfo 응답 구조 확인

```json
// 카카오 /v2/user/me 응답 예시
{
  "id": 1234567890,                    // user-name-attribute: id
  "kakao_account": {
    "email": "kim@kakao.com",
    "email_needs_agreement": false,
    "profile": {
      "nickname": "김철수",
      "profile_image_url": "http://..."
    }
  }
}
// Spring Security: OAuth2User.getAttribute("kakao_account")로 접근
```

---

## 🔒 보안 체크리스트

```
redirect_uri 설정
  ☐ 인가 서버에 정확한 URI만 등록 (와일드카드 금지)
  ☐ Spring 설정과 인가 서버 등록 URI 일치 확인
  ☐ HTTP(비HTTPS) redirect_uri 개발 환경에서만 허용

state 파라미터
  ☐ Spring Security 자동 처리 (직접 구현 불필요)
  ☐ 세션 기반 → STATELESS 환경에서는 쿠키 기반으로 전환 필요
  ☐ state 검증 비활성화 코드 금지

PKCE
  ☐ Public Client(SPA, 모바일)에 자동 적용됨 (Spring Security 6.x)
  ☐ code_challenge_method: S256만 허용

Authorization Code 보안
  ☐ code 1회용 보장 (사용 후 즉시 교환)
  ☐ code 수명 5~10분 (인가 서버 설정)
  ☐ redirect_uri로 반환된 code를 클라이언트 로그에 기록 금지
```

---

## 🤔 트레이드오프

```
Authorization Code vs 직접 UserInfo 조회:
  Authorization Code (표준):
    장점  보안성 높음, Token이 브라우저 미노출
    단점  2번의 왕복 (Token 교환 + UserInfo) 필요
          구현 복잡도 높음

  브라우저에서 직접 Access Token 수신 (Implicit):
    장점  구현 단순, 1번의 왕복
    단점  Token이 URL에 노출 → 탈취 가능
    → deprecated, 사용 금지

세션 기반 state vs 쿠키 기반 state (STATELESS 환경):
  세션 기반 (기본):
    장점  구현 단순, Spring Security 기본 지원
    단점  STATELESS 아키텍처에서 사용 불가
          분산 환경에서 세션 공유 필요

  쿠키 기반:
    장점  세션 없이 동작 → STATELESS 환경 가능
    단점  쿠키 크기 제한, HttpOnly 설정 필요
          CookieOAuth2AuthorizationRequestRepository 구현 필요
```

---

## 📌 핵심 정리

```
10단계 Authorization Code Flow
  ① OAuth2AuthorizationRequestRedirectFilter: state, PKCE 생성 → 세션 저장 → 인가 URI로 리다이렉트
  ②③ 사용자: 인가 서버 로그인 → 동의 → code 반환
  ④ OAuth2LoginAuthenticationFilter: state 검증 (세션 vs 파라미터)
  ⑤⑥ OAuth2AuthorizationCodeAuthenticationProvider: Token 교환 (서버 간 POST)
  ⑦⑧ DefaultOAuth2UserService: UserInfo 조회 (Bearer Token)
  ⑨ OAuth2User → SecurityContext 저장
  ⑩ 성공 핸들러 → 리다이렉트

Token이 브라우저에 미노출인 이유
  ⑤⑥ Token 교환은 Spring 앱 서버 → 인가 서버 (서버 간)
  브라우저는 code만 보고, Token은 서버만 수신

state 검증
  세션에 저장된 state == 콜백 파라미터의 state
  불일치 → 인증 실패 (CSRF 방어)
```

---

## 🤔 생각해볼 문제

**Q1.** Spring Security의 `HttpSessionOAuth2AuthorizationRequestRepository`는 state를 HttpSession에 저장합니다. 다중 서버(로드 밸런서) 환경에서 사용자가 인가 요청은 서버 A에서 보내고 콜백은 서버 B에서 받으면 state 검증이 실패합니다. 이를 해결하는 방법은?

**Q2.** Authorization Code Flow의 단계 ⑤에서 Token Endpoint 호출 시 Spring 앱이 `client_secret`을 함께 전송합니다. `client_secret`이 노출됐다면 어떤 공격이 가능하고, 이를 완화하는 방법은?

**Q3.** 카카오의 UserInfo 응답에서 이메일이 `kakao_account.email` 중첩 구조로 반환됩니다. Spring Security의 `DefaultOAuth2UserService`는 이 중첩 구조를 자동으로 처리하는가, 처리하지 않는다면 어떻게 접근하는가?

> 💡 **해설**
>
> **Q1.** 다중 서버 환경에서 세션 공유 문제를 해결하는 방법은 세 가지입니다. 첫째, Sticky Session(세션 고정 라우팅)으로 같은 사용자의 요청이 항상 같은 서버로 가도록 합니다. 단, 서버 장애 시 세션이 소실됩니다. 둘째, Redis 기반 공유 세션(Spring Session)으로 모든 서버가 같은 세션 저장소를 공유합니다. 셋째, `CookieOAuth2AuthorizationRequestRepository`를 구현해 state를 세션 대신 암호화된 쿠키에 저장합니다. 세션이 필요 없으므로 STATELESS 환경에서도 동작합니다. Spring Security는 이 인터페이스를 직접 구현하거나 상속해서 사용할 수 있습니다.
>
> **Q2.** `client_secret`이 노출되면 공격자가 Authorization Code를 가로채서 직접 Token Endpoint를 호출해 Access Token을 발급받을 수 있습니다. 단, PKCE가 적용된 경우 `code_verifier` 없이는 Token 교환이 불가합니다. 완화 방법으로는 즉시 `client_secret`을 회전(rotate)하고, `client_secret`을 환경 변수나 Secrets Manager에 저장해 코드베이스 노출을 방지합니다. 또한 인가 서버에서 IP 기반 Token Endpoint 접근 제한을 설정할 수 있습니다. 장기적으로는 `client_secret` 대신 `private_key_jwt` 방식으로 클라이언트를 인증하면 비밀키가 전송되지 않아 더 안전합니다.
>
> **Q3.** `DefaultOAuth2UserService`는 UserInfo 응답을 `Map<String, Object>` 형태로 파싱합니다. 중첩된 `kakao_account.email`은 자동으로 `kakao_account`라는 키에 `Map`으로 저장됩니다. 접근 방법은 `oauth2User.getAttribute("kakao_account")`로 내부 Map을 꺼낸 후 `.get("email")`로 이메일을 추출합니다. 더 편리하게 사용하려면 `CustomOAuth2UserService`에서 카카오 전용 처리 로직을 추가해 중첩 속성을 평탄화(flatten)하거나, 커스텀 `OAuth2User` 구현체에서 `getAttribute()` 오버라이드로 경로 기반 접근을 지원할 수 있습니다.

---

<div align="center">

**[← 이전: OAuth2 4가지 Grant Type](./01-oauth2-grant-types.md)** | **[홈으로 🏠](../README.md)** | **[다음: OAuth2LoginAuthenticationFilter 동작 ➡️](./03-oauth2-login-filter.md)**

</div>
