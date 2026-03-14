# OAuth2LoginAuthenticationFilter 동작 — Token 교환과 OAuth2User 로드 과정

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `OAuth2AuthorizationCodeAuthenticationProvider`가 Authorization Code를 Access Token으로 교환하는 정확한 과정은?
- `OAuth2UserService`를 호출해 `OAuth2User`를 로드하는 흐름에서 어떤 HTTP 요청이 발생하는가?
- `OAuth2LoginAuthenticationProvider`와 `OAuth2AuthorizationCodeAuthenticationProvider`는 어떻게 협력하는가?
- `OAuth2LoginAuthenticationToken`이 `authenticated` 상태가 되는 시점은?
- Token Endpoint 호출 시 `client_secret`을 어떤 방식으로 전달하는가 (`client_secret_basic` vs `client_secret_post`)?
- `OAuth2AuthorizedClient`는 어디서 생성되어 어떻게 저장되는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### OAuth2LoginAuthenticationFilter의 위치와 역할

```
OAuth2 로그인 필터 체인:

  OAuth2AuthorizationRequestRedirectFilter (/oauth2/authorization/*)
    → 인가 요청 시작, state/PKCE 생성, 인가 서버로 리다이렉트

  ★ OAuth2LoginAuthenticationFilter (/login/oauth2/code/*)
    → 콜백 처리 (code 수신)
    → AbstractAuthenticationProcessingFilter 상속
    → attemptAuthentication() → AuthenticationManager로 위임

  ProviderManager (AuthenticationManager)
    → OAuth2LoginAuthenticationProvider
       → OAuth2AuthorizationCodeAuthenticationProvider (Token 교환)
       → DefaultOAuth2UserService (UserInfo 조회)

  성공 → SecurityContext 저장 + OAuth2AuthorizedClient 저장
  실패 → OAuth2AuthenticationException
```

---

## 😱 흔한 보안 실수

### Before: client_secret을 URL 파라미터로 전송

```java
// ❌ client_secret이 URL에 포함 → 서버 로그, 프록시 로그에 노출
POST /oauth2/token?client_id=xxx&client_secret=yyy&code=zzz

// ✅ client_secret_basic: Authorization 헤더로 전송 (기본값)
// Authorization: Basic BASE64(clientId:clientSecret)
spring.security.oauth2.client.registration.google.client-authentication-method:
  client_secret_basic

// 또는 client_secret_post: Form body에 전송 (일부 서버 요구)
spring.security.oauth2.client.registration.kakao.client-authentication-method:
  client_secret_post
// POST /oauth2/token
// Body: client_id=xxx&client_secret=yyy&code=zzz (HTTPS 통신이면 안전)
```

### Before: 성공 핸들러 없이 기본 리다이렉트 사용

```java
// ❌ 로그인 성공 후 적절한 처리 없이 기본 "/" 리다이렉트
// → 관리자가 로그인해도 일반 사용자 홈으로 이동
// → 소셜 로그인 후 회원가입 미완료 상태로 진행 가능

// ✅ 커스텀 성공 핸들러로 역할별 처리
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.oauth2Login(oauth2 -> oauth2
        .successHandler(new OAuth2SuccessHandler(userService))
        .failureHandler(new OAuth2FailureHandler())
    );
    return http.build();
}

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                         HttpServletResponse response,
                                         Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oauthToken =
            (OAuth2AuthenticationToken) authentication;
        String provider = oauthToken.getAuthorizedClientRegistrationId();
        OAuth2User oauth2User = oauthToken.getPrincipal();

        // DB에서 기존 회원 여부 확인
        User user = userService.findOrCreate(oauth2User, provider);

        if (!user.isProfileComplete()) {
            // 추가 정보 입력 필요
            response.sendRedirect("/complete-profile");
        } else {
            response.sendRedirect("/dashboard");
        }
    }
}
```

---

## ✨ 올바른 보안 구현

### OAuth2 로그인 완전 설정

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                // 로그인 페이지: 제공자 선택 화면
                .loginPage("/login")
                // 인가 요청 커스터마이징 (추가 파라미터 등)
                .authorizationEndpoint(endpoint -> endpoint
                    .authorizationRequestRepository(
                        new HttpSessionOAuth2AuthorizationRequestRepository())
                )
                // 콜백 처리 설정
                .redirectionEndpoint(endpoint -> endpoint
                    .baseUri("/login/oauth2/code/*")
                )
                // UserInfo 로드 커스터마이징
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oAuth2UserService) // 커스텀 UserService
                )
                // 성공/실패 핸들러
                .successHandler(successHandler)
                .failureHandler((req, res, ex) -> {
                    res.sendRedirect("/login?error=" + ex.getMessage());
                })
            );
        return http.build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. OAuth2LoginAuthenticationFilter.attemptAuthentication()

```java
// OAuth2LoginAuthenticationFilter.java
// AbstractAuthenticationProcessingFilter 상속

@Override
public Authentication attemptAuthentication(
        HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {

    // ① 오류 응답 확인 (사용자가 동의 거부 등)
    OAuth2Error error = this.authorizationResponseConverter.convert(request).getError();
    if (error != null) {
        throw new OAuth2AuthenticationException(error);
    }

    // ② 세션에서 저장된 OAuth2AuthorizationRequest 조회 (state 검증)
    OAuth2AuthorizationRequest authorizationRequest =
        this.authorizationRequestRepository
            .removeAuthorizationRequest(request, response);
    if (authorizationRequest == null) {
        throw new OAuth2AuthenticationException("invalid_state_parameter");
    }

    // ③ ClientRegistration 조회 (registrationId로)
    String registrationId = this.resolveRegistrationId(request);
    ClientRegistration clientRegistration =
        this.clientRegistrationRepository.findByRegistrationId(registrationId);

    // ④ 인증 토큰 생성 (unauthenticated)
    OAuth2LoginAuthenticationToken authenticationRequest =
        new OAuth2LoginAuthenticationToken(
            clientRegistration,
            new OAuth2AuthorizationExchange(authorizationRequest,
                parseAuthorizationResponse(request)));

    // ⑤ AuthenticationManager로 위임
    OAuth2LoginAuthenticationToken authenticationResult =
        (OAuth2LoginAuthenticationToken) this.getAuthenticationManager()
            .authenticate(authenticationRequest);

    // ⑥ OAuth2AuthorizedClient 생성 및 저장
    OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
        authenticationResult.getClientRegistration(),
        authenticationResult.getName(),
        authenticationResult.getAccessToken(),
        authenticationResult.getRefreshToken());

    this.authorizedClientRepository.saveAuthorizedClient(
        authorizedClient, authenticationResult, request, response);

    return authenticationResult;
}
```

### 2. OAuth2LoginAuthenticationProvider — 전체 인증 흐름

```java
// OAuth2LoginAuthenticationProvider.java
public Authentication authenticate(Authentication authentication) {

    OAuth2LoginAuthenticationToken loginToken =
        (OAuth2LoginAuthenticationToken) authentication;

    // ① Authorization Code → Access Token 교환
    // OAuth2AuthorizationCodeAuthenticationProvider에게 위임
    OAuth2AuthorizationCodeAuthenticationToken codeToken =
        (OAuth2AuthorizationCodeAuthenticationToken)
        this.authorizationCodeAuthenticationProvider.authenticate(
            new OAuth2AuthorizationCodeAuthenticationToken(
                loginToken.getClientRegistration(),
                loginToken.getAuthorizationExchange()));
    // → POST {token_uri}
    //     grant_type=authorization_code
    //     &code={authCode}
    //     &redirect_uri={redirectUri}
    //     &code_verifier={pkceVerifier}
    //   Authorization: Basic {clientId:clientSecret}

    // ② Access Token으로 UserInfo 조회
    OAuth2UserRequest userRequest = new OAuth2UserRequest(
        loginToken.getClientRegistration(),
        codeToken.getAccessToken(),
        codeToken.getAdditionalParameters());

    OAuth2User oauth2User = this.userService.loadUser(userRequest);
    // → GET {userinfo_uri}
    //   Authorization: Bearer {accessToken}

    // ③ 권한 매핑
    Collection<? extends GrantedAuthority> mappedAuthorities =
        this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

    // ④ authenticated 상태의 Token 반환
    return new OAuth2LoginAuthenticationToken(
        loginToken.getClientRegistration(),
        loginToken.getAuthorizationExchange(),
        oauth2User,
        mappedAuthorities,
        codeToken.getAccessToken(),
        codeToken.getRefreshToken());
    // isAuthenticated() = true
}
```

### 3. DefaultAuthorizationCodeTokenResponseClient — Token 교환 상세

```java
// DefaultAuthorizationCodeTokenResponseClient.java
public OAuth2AccessTokenResponse getTokenResponse(
        OAuth2AuthorizationCodeGrantRequest grantRequest) {

    ClientRegistration clientRegistration = grantRequest.getClientRegistration();

    // 요청 파라미터 구성
    MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
    formParameters.add("grant_type", "authorization_code");
    formParameters.add("code", grantRequest.getAuthorizationExchange()
        .getAuthorizationResponse().getCode());
    formParameters.add("redirect_uri", clientRegistration.getRedirectUri());

    // PKCE: code_verifier 추가
    OAuth2AuthorizationRequest authRequest = grantRequest.getAuthorizationExchange()
        .getAuthorizationRequest();
    if (authRequest.getAttribute("code_verifier") != null) {
        formParameters.add("code_verifier",
            authRequest.getAttribute("code_verifier"));
    }

    // client_authentication_method 처리
    HttpHeaders headers = new HttpHeaders();
    ClientAuthenticationMethod method =
        clientRegistration.getClientAuthenticationMethod();

    if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)) {
        // Authorization: Basic BASE64(clientId:clientSecret)
        headers.setBasicAuth(clientRegistration.getClientId(),
            clientRegistration.getClientSecret());
    } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) {
        // Form body에 client_id, client_secret 포함
        formParameters.add("client_id", clientRegistration.getClientId());
        formParameters.add("client_secret", clientRegistration.getClientSecret());
    }

    // HTTP POST 요청 실행
    ResponseEntity<Map<String, Object>> response = restOperations.exchange(
        clientRegistration.getProviderDetails().getTokenUri(),
        HttpMethod.POST,
        new HttpEntity<>(formParameters, headers),
        new ParameterizedTypeReference<>() {});

    // 응답 파싱 → OAuth2AccessTokenResponse
    return convert(response.getBody());
}
```

### 4. OAuth2AuthorizedClient — 저장 구조

```java
// OAuth2AuthorizedClient: 인증 완료된 클라이언트 정보 묶음
public class OAuth2AuthorizedClient implements Serializable {
    private final ClientRegistration clientRegistration; // 등록 정보
    private final String principalName;                  // 사용자 이름
    private final OAuth2AccessToken accessToken;         // 발급된 Access Token
    private final OAuth2RefreshToken refreshToken;       // Refresh Token (있는 경우)
}

// 저장소: OAuth2AuthorizedClientRepository
// 기본: HttpSessionOAuth2AuthorizedClientRepository
// → HttpSession.setAttribute("OAuth2AuthorizedClients", Map{registrationId → authorizedClient})

// InMemoryOAuth2AuthorizedClientService도 제공 (비세션)
// OAuth2AuthorizedClientService: 서비스 레이어용 (세션과 무관)

// 저장 시점:
// OAuth2LoginAuthenticationFilter.attemptAuthentication() 성공 후
// → authorizedClientRepository.saveAuthorizedClient()
```

---

## 💻 실험으로 확인하기

### 실험 1: Provider 체인 확인 (DEBUG 로그)

```yaml
logging:
  level:
    org.springframework.security.oauth2.client.authentication: DEBUG
```

```
DEBUG OAuth2LoginAuthenticationProvider - Retrieved authorized client for principal 'kim@gmail.com'
DEBUG OAuth2AuthorizationCodeAuthenticationProvider - Exchanging code for Access Token
DEBUG DefaultAuthorizationCodeTokenResponseClient - POST https://oauth2.googleapis.com/token
DEBUG DefaultOAuth2UserService - GET https://openidconnect.googleapis.com/v1/userinfo
DEBUG OAuth2LoginAuthenticationProvider - Authenticated 'kim@gmail.com'
```

### 실험 2: OAuth2AuthorizedClient 접근

```java
@GetMapping("/api/oauth2-info")
public Map<String, Object> oauth2Info(
        @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {
    return Map.of(
        "accessToken", client.getAccessToken().getTokenValue().substring(0, 20) + "...",
        "expiresAt", client.getAccessToken().getExpiresAt(),
        "scopes", client.getAccessToken().getScopes(),
        "principalName", client.getPrincipalName()
    );
}
```

### 실험 3: client_authentication_method 차이 확인 (네트워크 로그)

```yaml
logging:
  level:
    org.springframework.web.client.RestTemplate: DEBUG
    org.apache.http.headers: DEBUG
```

```
# client_secret_basic:
> POST https://kauth.kakao.com/oauth/token
> Authorization: Basic a2FrYW8taWQ6a2FrYW8tc2VjcmV0  ← BASE64
> Content-Type: application/x-www-form-urlencoded
> grant_type=authorization_code&code=...

# client_secret_post:
> POST https://kauth.kakao.com/oauth/token
> Content-Type: application/x-www-form-urlencoded
> grant_type=authorization_code&code=...&client_id=kakao-id&client_secret=kakao-secret
```

---

## 🔒 보안 체크리스트

```
Token 교환
  ☐ client_authentication_method: client_secret_basic 우선 (헤더 방식)
  ☐ client_secret_post 사용 시 반드시 HTTPS
  ☐ client_secret URL 파라미터 전송 절대 금지

OAuth2AuthorizedClient 저장
  ☐ 세션 기반 저장 → STATELESS JWT 환경에서는 별도 저장소 필요
  ☐ Access Token을 DB에 저장 시 암호화 필수
  ☐ Refresh Token 보안 저장 (HttpOnly 쿠키 또는 암호화 DB)

성공 핸들러
  ☐ 소셜 로그인 후 기존 회원 여부 확인
  ☐ 신규 회원 → 추가 정보 입력 페이지
  ☐ 역할별 리다이렉트 (관리자 → /admin, 일반 → /dashboard)
```

---

## 🤔 트레이드오프

```
client_secret_basic vs client_secret_post:
  client_secret_basic (Authorization 헤더):
    장점  표준 방식, 로그에 Body가 기록돼도 secret 미노출
    단점  일부 구형 서버 미지원

  client_secret_post (Body):
    장점  모든 서버 지원
    단점  Body 로깅 시 secret 노출 위험
    → HTTPS 필수, 로깅 레벨 주의

DefaultOAuth2UserService vs 커스텀 UserService:
  Default:
    장점  설정 없이 동작, 표준 UserInfo 자동 처리
    단점  DB 저장, 사용자 연결, 비표준 응답 처리 불가

  커스텀:
    장점  DB 저장, 소셜 계정 연결, 비표준 응답 파싱 가능
    단점  직접 구현 필요
    → 실무에서는 거의 항상 커스텀 UserService 필요
```

---

## 📌 핵심 정리

```
OAuth2LoginAuthenticationFilter 흐름
  콜백 수신 → state 검증 → OAuth2AuthorizationCodeAuthenticationProvider
  → Token 교환 (POST token_uri) → Access Token 수신
  → OAuth2UserService.loadUser() (GET userinfo_uri)
  → OAuth2LoginAuthenticationToken (authenticated)
  → SecurityContext 저장 + OAuth2AuthorizedClient 저장

Provider 협력 구조
  OAuth2LoginAuthenticationProvider
  └─ OAuth2AuthorizationCodeAuthenticationProvider (Token 교환)
  └─ DefaultOAuth2UserService (UserInfo 조회)

client_authentication_method
  client_secret_basic: Authorization: Basic BASE64(id:secret) [권장]
  client_secret_post:  Form body에 포함 [일부 서버 요구]

OAuth2AuthorizedClient
  OAuth2LoginAuthenticationFilter에서 생성
  HttpSession 또는 InMemory에 저장
  @RegisteredOAuth2AuthorizedClient로 Controller 주입
```

---

## 🤔 생각해볼 문제

**Q1.** `OAuth2LoginAuthenticationProvider`는 `OAuth2AuthorizationCodeAuthenticationProvider`를 내부적으로 호출합니다. 그런데 `ProviderManager`에 두 Provider가 모두 등록되어 있다면 같은 `OAuth2AuthorizationCodeAuthenticationToken`에 대해 중복 처리가 발생할 수 있는가?

**Q2.** `DefaultAuthorizationCodeTokenResponseClient`는 Token Endpoint에 HTTP POST를 보낼 때 내부적으로 `RestTemplate`을 사용합니다. 이 `RestTemplate`에 커스텀 인터셉터를 추가해 Token 요청/응답을 로깅하고 싶은데, 어떻게 커스터마이징하는가? 단, 로그에 `client_secret`이 노출되지 않도록 해야 한다.

**Q3.** 사용자가 소셜 로그인에 성공했지만 `OAuth2UserService.loadUser()` 내부에서 DB 저장 중 예외가 발생했습니다. 이때 Spring Security의 인증 흐름은 어떻게 되는가? 사용자에게는 어떤 응답이 전달되는가?

> 💡 **해설**
>
> **Q1.** 중복 처리는 발생하지 않습니다. `ProviderManager`는 각 Provider의 `supports()` 메서드를 확인해 처리 가능한 Provider를 선택합니다. `OAuth2LoginAuthenticationProvider.supports()`는 `OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication)`을 검사하고, `OAuth2AuthorizationCodeAuthenticationProvider.supports()`는 `OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom()`을 검사합니다. `OAuth2LoginAuthenticationFilter`가 생성하는 토큰은 `OAuth2LoginAuthenticationToken`이므로 `OAuth2LoginAuthenticationProvider`가 처리합니다. 내부에서 `OAuth2AuthorizationCodeAuthenticationProvider`를 직접 호출할 때는 `OAuth2AuthorizationCodeAuthenticationToken`을 생성해서 사용하며, 이는 `ProviderManager` 체인이 아닌 직접 호출입니다.
>
> **Q2.** 커스터마이징 방법: `DefaultAuthorizationCodeTokenResponseClient`의 `setRestOperations()`로 커스텀 `RestTemplate`을 주입합니다. 인터셉터에서 `Authorization` 헤더를 `[REDACTED]`로 교체하고, 요청 Body에서 `client_secret` 파라미터를 마스킹합니다. `ClientHttpRequestInterceptor`를 구현해 `request.getBody()`를 읽고 `client_secret` 값을 `***`으로 치환한 후 로깅합니다. Spring Security 6.x에서는 `OAuth2AccessTokenResponseClient`를 `@Bean`으로 등록하면 자동으로 적용됩니다.
>
> **Q3.** `OAuth2UserService.loadUser()`에서 발생한 예외는 `OAuth2LoginAuthenticationProvider.authenticate()` 내부에서 전파됩니다. Spring Security는 `OAuth2AuthenticationException`이 아닌 일반 `RuntimeException`도 `AbstractAuthenticationProcessingFilter`의 `unsuccessfulAuthentication()`으로 전달합니다. 기본 `SimpleUrlAuthenticationFailureHandler`는 `/login?error`로 리다이렉트합니다. 커스텀 `failureHandler`를 설정했다면 해당 핸들러가 호출됩니다. 사용자는 로그인 실패 페이지를 보게 됩니다. DB 저장 중 예외이므로 소셜 로그인 자체는 성공했지만 내부 처리 실패로 인해 인증이 완료되지 않은 상태입니다.

---

<div align="center">

**[← 이전: Authorization Code Flow 완전 분석](./02-authorization-code-flow.md)** | **[홈으로 🏠](../README.md)** | **[다음: ClientRegistration과 InMemoryClientRegistrationRepository ➡️](./04-client-registration.md)**

</div>
