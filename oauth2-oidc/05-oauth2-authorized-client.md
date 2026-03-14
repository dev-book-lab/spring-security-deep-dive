# OAuth2AuthorizedClient 관리 — 토큰 저장, 주입, 자동 갱신

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `OAuth2AuthorizedClientRepository`가 Access Token을 세션에 저장하는 방식과 조회 흐름은?
- `@RegisteredOAuth2AuthorizedClient`로 Controller에서 토큰을 주입받는 내부 동작은?
- `OAuth2AuthorizedClientManager`가 Access Token 만료를 감지하고 자동 갱신하는 과정은?
- `OAuth2AuthorizedClientService`와 `OAuth2AuthorizedClientRepository`의 역할 차이는?
- WebClient와 `OAuth2AuthorizedClientManager`를 연동해 자동으로 Bearer 토큰을 첨부하는 방법은?
- `JdbcOAuth2AuthorizedClientService`로 Access Token을 DB에 영속하는 방법은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### OAuth2AuthorizedClient가 필요한 이유

```
소셜 로그인 후 Access Token을 사용해야 하는 경우:
  → Google Calendar API 호출: 사용자의 캘린더 읽기
  → GitHub API 호출: 사용자의 저장소 목록
  → Kakao API 호출: 사용자의 친구 목록

문제: 로그인 성공 후 Access Token을 어디서 꺼내는가?
  ❌ 잘못된 방법: SecurityContext에서 직접 캐스팅
     OAuth2AuthenticationToken auth = (OAuth2AuthenticationToken) authentication;
     // Access Token 없음! OAuth2AuthenticationToken에는 토큰이 포함 안 됨

  ✅ 올바른 방법: OAuth2AuthorizedClient 사용
     OAuth2AuthorizedClient client = repository.loadAuthorizedClient(
         "google", authentication, request);
     String accessToken = client.getAccessToken().getTokenValue();

OAuth2AuthorizedClient:
  로그인 성공 후 발급된 Access Token + Refresh Token을 보관
  ClientRegistration + principalName + AccessToken + RefreshToken 묶음
  OAuth2AuthorizedClientRepository 또는 OAuth2AuthorizedClientService에서 관리
```

---

## 😱 흔한 보안 실수

### Before: Access Token을 HTTP 응답 바디에 노출

```java
// ❌ Access Token을 클라이언트에 전달 → 클라이언트가 직접 API 호출
@GetMapping("/api/google-token")
public String getGoogleToken(
        @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {
    return client.getAccessToken().getTokenValue(); // ← 절대 금지
}
// → Access Token이 브라우저에 노출
// → XSS, 로그 등으로 탈취 가능
// → 서버가 API를 프록시해야 함 (BFF 패턴)

// ✅ 서버에서 직접 외부 API 호출 후 필요한 데이터만 반환
@GetMapping("/api/google-calendar")
public List<CalendarEvent> getCalendar(
        @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {
    // 서버가 직접 Google API 호출 (BFF 패턴)
    return googleCalendarClient.getEvents(client.getAccessToken().getTokenValue());
    // → 클라이언트는 Access Token을 알 수 없음
}
```

### Before: 만료된 Access Token 사용 시 예외 미처리

```java
// ❌ Access Token이 만료됐을 때 OAuth2AuthorizationException 미처리
@GetMapping("/api/calendar")
public List<Event> getCalendar(
        @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {
    // Access Token 만료 → Google API가 401 반환 → 예외 미처리
    return googleApi.getEvents(client.getAccessToken().getTokenValue());
}

// ✅ OAuth2AuthorizedClientManager로 자동 갱신 처리
@Service
@RequiredArgsConstructor
public class GoogleCalendarService {

    private final OAuth2AuthorizedClientManager clientManager;

    public List<Event> getCalendarEvents(Authentication authentication,
                                          HttpServletRequest request,
                                          HttpServletResponse response) {
        // clientManager가 만료 시 자동 갱신
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
            .withClientRegistrationId("google")
            .principal(authentication)
            .attributes(attrs -> {
                attrs.put(HttpServletRequest.class.getName(), request);
                attrs.put(HttpServletResponse.class.getName(), response);
            })
            .build();

        OAuth2AuthorizedClient client =
            clientManager.authorize(authorizeRequest);
        // → Access Token 만료 시 Refresh Token으로 자동 갱신
        // → 갱신된 Token으로 OAuth2AuthorizedClient 반환

        return googleApi.getEvents(client.getAccessToken().getTokenValue());
    }
}
```

---

## ✨ 올바른 보안 구현

### WebClient + OAuth2 자동 토큰 첨부

```java
@Configuration
@RequiredArgsConstructor
public class WebClientConfig {

    private final OAuth2AuthorizedClientManager authorizedClientManager;

    @Bean
    public WebClient googleApiClient() {
        // 모든 요청에 Bearer 토큰 자동 첨부 (만료 시 자동 갱신)
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(
                authorizedClientManager);

        return WebClient.builder()
            .baseUrl("https://www.googleapis.com")
            .apply(oauth2Client.oauth2Configuration())
            .build();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientRepository clients) {

        // 지원할 인증 방식 설정
        OAuth2AuthorizedClientProvider provider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()      // Authorization Code
                .refreshToken()           // Access Token 만료 시 자동 갱신
                .clientCredentials()      // Client Credentials
                .build();

        DefaultOAuth2AuthorizedClientManager manager =
            new DefaultOAuth2AuthorizedClientManager(registrations, clients);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }
}

// 사용:
@RestController
@RequiredArgsConstructor
public class CalendarController {

    private final WebClient googleApiClient;

    @GetMapping("/api/calendar")
    public Flux<CalendarEvent> getCalendar(
            @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {

        return googleApiClient.get()
            .uri("/calendar/v3/calendars/primary/events")
            // @RegisteredOAuth2AuthorizedClient로 이미 토큰 지정
            .attributes(oauth2AuthorizedClient(client))
            .retrieve()
            .bodyToFlux(CalendarEvent.class);
    }
}
```

---

## 🔬 내부 동작 원리

### 1. OAuth2AuthorizedClientRepository vs OAuth2AuthorizedClientService

```java
// OAuth2AuthorizedClientRepository (웹 요청 범위):
// → HTTP 요청/응답에서 토큰 로드/저장 (주로 세션)
// → Controller, Filter에서 HttpServletRequest/Response 사용 시

// 기본 구현: HttpSessionOAuth2AuthorizedClientRepository
public class HttpSessionOAuth2AuthorizedClientRepository
        implements OAuth2AuthorizedClientRepository {

    private static final String SESSION_KEY = "SPRING_SECURITY_AUTHORIZED_CLIENTS";

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(
            String clientRegistrationId, Authentication principal,
            HttpServletRequest request) {

        Map<String, OAuth2AuthorizedClient> map =
            (Map) request.getSession(false)
                         ?.getAttribute(SESSION_KEY);

        if (map == null) return null;
        return (T) map.get(clientRegistrationId + "." + principal.getName());
        // 키: "google.kim@gmail.com"
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient client,
                                      Authentication principal,
                                      HttpServletRequest request, ...) {
        Map<String, OAuth2AuthorizedClient> map = ...;
        map.put(clientRegistrationId + "." + principal.getName(), client);
        request.getSession().setAttribute(SESSION_KEY, map);
    }
}

// OAuth2AuthorizedClientService (비웹 컨텍스트, 배치, 스케줄러):
// → HttpServletRequest 없이 사용 가능
// → 배치 처리, 백그라운드 스케줄러에서 특정 사용자 토큰 조회 시

OAuth2AuthorizedClient client =
    authorizedClientService.loadAuthorizedClient("google", "kim@gmail.com");
```

### 2. @RegisteredOAuth2AuthorizedClient 내부 동작

```java
// OAuth2AuthorizedClientArgumentResolver.resolveArgument() 내부:
// Controller 메서드 파라미터 처리

public Object resolveArgument(MethodParameter parameter, ...) {

    // ① @RegisteredOAuth2AuthorizedClient 어노테이션에서 registrationId 추출
    RegisteredOAuth2AuthorizedClient annotation = ...;
    String clientRegistrationId = annotation.value(); // "google"

    // ② 현재 Authentication 추출
    Authentication principal = SecurityContextHolder
        .getContext().getAuthentication();

    // ③ 세션에서 OAuth2AuthorizedClient 로드
    OAuth2AuthorizedClient authorizedClient =
        this.authorizedClientRepository.loadAuthorizedClient(
            clientRegistrationId, principal, request);

    if (authorizedClient == null) {
        // 로그인 안 된 상태 or 해당 소셜 로그인 안 함
        return null;
    }

    // ④ 자동 갱신 시도 (OAuth2AuthorizedClientManager가 있는 경우)
    // Access Token 만료 + Refresh Token 있음 → 자동 갱신
    if (isExpired(authorizedClient.getAccessToken()) &&
            authorizedClient.getRefreshToken() != null) {
        authorizedClient = this.clientManager.authorize(
            OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient)
                .principal(principal)
                .build());
    }

    return authorizedClient;
}
```

### 3. OAuth2AuthorizedClientProvider — 자동 갱신 체인

```java
// OAuth2AuthorizedClientProviderBuilder 설정 시 체인 구성:
// RefreshTokenOAuth2AuthorizedClientProvider → Access Token 만료 감지 + 갱신

public class RefreshTokenOAuth2AuthorizedClientProvider
        implements OAuth2AuthorizedClientProvider {

    @Override
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
        OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();

        // 조건: Access Token 만료 + Refresh Token 존재
        if (!hasTokenExpired(authorizedClient.getAccessToken())
                || hasRefreshToken(authorizedClient)) {
            return null; // 갱신 불필요 → null 반환
        }

        // Refresh Token으로 새 Access Token 발급
        OAuth2RefreshTokenGrantRequest refreshRequest =
            new OAuth2RefreshTokenGrantRequest(
                authorizedClient.getClientRegistration(),
                authorizedClient.getAccessToken(),
                authorizedClient.getRefreshToken(),
                context.getAuthorizedScopes());

        OAuth2AccessTokenResponse tokenResponse =
            this.accessTokenResponseClient.getTokenResponse(refreshRequest);
        // → POST {token_uri}
        //     grant_type=refresh_token
        //     &refresh_token={refreshToken}
        //   Authorization: Basic {clientId:clientSecret}

        // 새 OAuth2AuthorizedClient 생성 및 저장
        OAuth2AuthorizedClient refreshed = new OAuth2AuthorizedClient(
            authorizedClient.getClientRegistration(),
            context.getPrincipal().getName(),
            tokenResponse.getAccessToken(),
            tokenResponse.getRefreshToken() != null
                ? tokenResponse.getRefreshToken()
                : authorizedClient.getRefreshToken()); // Refresh Token이 없으면 기존 유지

        context.getAttributes().put(OAuth2AuthorizationContext.REQUEST_ATTRIBUTE_NAME,
            request);
        this.authorizedClientRepository.saveAuthorizedClient(
            refreshed, context.getPrincipal(), request, response);

        return refreshed;
    }
}
```

### 4. JdbcOAuth2AuthorizedClientService — DB 영속

```java
// Access Token을 DB에 저장 (세션이 아닌 영속 저장)
@Configuration
public class OAuth2AuthorizedClientConfig {

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcTemplate jdbcTemplate,
            ClientRegistrationRepository registrations) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, registrations);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService service) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(service);
    }
}

// DB 테이블: oauth2_authorized_client
// 스키마:
// CREATE TABLE oauth2_authorized_client (
//   client_registration_id  varchar(100) NOT NULL,
//   principal_name           varchar(200) NOT NULL,
//   access_token_type        varchar(100) NOT NULL,
//   access_token_value       blob         NOT NULL,  ← 암호화 필요
//   access_token_issued_at   timestamp    NOT NULL,
//   access_token_expires_at  timestamp    NOT NULL,
//   access_token_scopes      varchar(1000),
//   refresh_token_value      blob,                   ← 암호화 필요
//   refresh_token_issued_at  timestamp,
//   created_at               timestamp    DEFAULT CURRENT_TIMESTAMP,
//   PRIMARY KEY (client_registration_id, principal_name)
// );

// Access Token은 DB에 평문 저장 금지
// → 암호화 후 저장: application-level encryption
// → 또는 JdbcOAuth2AuthorizedClientService를 상속해 저장 전 암호화
```

---

## 💻 실험으로 확인하기

### 실험 1: @RegisteredOAuth2AuthorizedClient 주입 테스트

```java
@SpringBootTest
@AutoConfigureMockMvc
class OAuth2AuthorizedClientTest {

    @Test
    @WithMockOAuth2User(clientRegistrationId = "google")
    void registeredClient_injected_correctly() throws Exception {
        mockMvc.perform(get("/api/calendar"))
            .andExpect(status().isOk());
        // @RegisteredOAuth2AuthorizedClient("google")로 주입됨
    }
}
```

### 실험 2: Access Token 만료 후 자동 갱신 확인

```java
@Test
void expiredAccessToken_autoRefreshed() {
    // given: 만료된 Access Token을 가진 OAuth2AuthorizedClient
    OAuth2AuthorizedClient expiredClient = buildClientWithExpiredToken();
    authorizedClientRepository.saveAuthorizedClient(expiredClient, principal, request, response);

    // when: OAuth2AuthorizedClientManager.authorize() 호출
    OAuth2AuthorizedClient refreshedClient =
        clientManager.authorize(OAuth2AuthorizeRequest
            .withClientRegistrationId("google")
            .principal(principal)
            .build());

    // then: 새 Access Token 발급됨
    assertThat(refreshedClient.getAccessToken().getExpiresAt())
        .isAfter(Instant.now());
    // 자동 갱신 로그:
    // DEBUG RefreshTokenOAuth2AuthorizedClientProvider - Refreshing Access Token
}
```

### 실험 3: WebClient에 Bearer 토큰 자동 첨부 확인

```java
@Test
void webClient_automaticallyAddsBearer() {
    // given: Google 소셜 로그인 완료된 사용자
    // when: Google Calendar API 호출
    mockWebServer.enqueue(new MockResponse().setBody("[...]").setResponseCode(200));

    calendarController.getCalendar(authorizedClient);

    // then: 요청에 Bearer 토큰 첨부됨
    RecordedRequest recorded = mockWebServer.takeRequest();
    assertThat(recorded.getHeader("Authorization"))
        .startsWith("Bearer ");
}
```

---

## 🔒 보안 체크리스트

```
Access Token 관리
  ☐ Access Token을 HTTP 응답 바디에 노출 금지 (BFF 패턴)
  ☐ DB 저장 시 암호화 필수 (AES-256 등)
  ☐ 세션에 저장된 토큰 → 세션 만료 시 자동 소멸

자동 갱신 설정
  ☐ OAuth2AuthorizedClientProviderBuilder에 refreshToken() 포함
  ☐ Google 등은 Refresh Token이 최초 로그인에만 발급 (access_type=offline 설정 필요)
  ☐ Refresh Token 없는 경우 재로그인 유도

세션 vs DB 저장
  ☐ 단기 세션: HttpSessionOAuth2AuthorizedClientRepository (기본)
  ☐ 장기 보관, 배치 처리: JdbcOAuth2AuthorizedClientService
  ☐ 서버리스/STATELESS: 직접 암호화 저장 또는 클라이언트 측 안전 저장
```

---

## 🤔 트레이드오프

```
HttpSession 저장 vs DB 저장:
  Session:
    장점  구현 단순, 세션 만료 시 자동 정리
    단점  서버 재시작 시 토큰 소실, 분산 환경에서 공유 필요

  DB 저장:
    장점  영속적, 분산 환경에서 공유 가능, 배치 처리 가능
    단점  Access Token 암호화 필요, 만료된 토큰 주기적 정리 필요

@RegisteredOAuth2AuthorizedClient vs OAuth2AuthorizedClientManager:
  @RegisteredOAuth2AuthorizedClient:
    장점  Controller 파라미터로 간단하게 주입
    단점  Service 레이어에서 사용 불가, 자동 갱신 설정 복잡

  OAuth2AuthorizedClientManager:
    장점  어디서나 사용 가능, 자동 갱신 기능 내장
    단점  코드가 더 장황, HttpServletRequest 필요
```

---

## 📌 핵심 정리

```
OAuth2AuthorizedClient 구성
  ClientRegistration + principalName + AccessToken + RefreshToken
  로그인 성공 후 OAuth2LoginAuthenticationFilter에서 생성
  세션(기본) 또는 DB에 저장

저장소 종류
  OAuth2AuthorizedClientRepository: 웹 요청 범위 (HttpServletRequest 사용)
  OAuth2AuthorizedClientService:    비웹 컨텍스트 (배치, 스케줄러)

자동 갱신 흐름
  OAuth2AuthorizedClientManager.authorize()
  → RefreshTokenOAuth2AuthorizedClientProvider
  → Access Token 만료 + Refresh Token 존재 → POST {token_uri} (grant_type=refresh_token)
  → 새 OAuth2AuthorizedClient 생성 및 저장

Controller 주입
  @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client
  → OAuth2AuthorizedClientArgumentResolver → 세션에서 로드 + 자동 갱신
```

---

## 🤔 생각해볼 문제

**Q1.** `HttpSessionOAuth2AuthorizedClientRepository`는 Access Token을 세션에 저장합니다. JWT STATELESS 환경에서 Spring Security OAuth2 로그인을 함께 사용하면(소셜 로그인 후 자체 JWT 발급) Access Token이 세션에 저장되는 문제가 있습니다. 소셜 로그인의 Access Token이 세션에 저장되지 않도록 하면서 자체 JWT를 발급하는 흐름을 설계하라.

**Q2.** Google OAuth2의 Refresh Token은 최초 인가 시(`access_type=offline`, `prompt=consent`)에만 발급됩니다. 사용자가 이미 Google 로그인을 했고 Refresh Token이 없는 상태에서 Access Token이 만료되면 `RefreshTokenOAuth2AuthorizedClientProvider`는 어떻게 동작하는가?

**Q3.** `JdbcOAuth2AuthorizedClientService`로 Access Token을 DB에 저장할 때, 보안상 Access Token을 평문으로 저장하면 안 됩니다. Spring Security가 제공하는 암호화 저장 방법과 직접 구현하는 방법을 제안하라.

> 💡 **해설**
>
> **Q1.** 설계 패턴: 소셜 로그인 성공 후 `AuthenticationSuccessHandler`에서 자체 JWT를 발급하고, Google Access Token을 세션에 저장하지 않는 방법입니다. `NullOAuth2AuthorizedClientRepository`를 등록해 `saveAuthorizedClient()`가 아무것도 하지 않도록 합니다. 대신 성공 핸들러에서 Google Access Token이 필요한 경우 즉시 사용하고 DB에 암호화 저장합니다. 자체 JWT를 발급해 클라이언트에 반환하고, 이후 모든 API 호출은 자체 JWT로만 인증합니다. Google Access Token이 필요한 API는 DB에서 꺼내 사용합니다. 이 방식은 세션 의존성을 완전히 제거하면서 소셜 로그인과 JWT를 병행합니다.
>
> **Q2.** `RefreshTokenOAuth2AuthorizedClientProvider`는 Refresh Token이 없으면 `authorize()` 메서드에서 `null`을 반환합니다. `null`이 반환되면 `DefaultOAuth2AuthorizedClientManager`는 다음 Provider를 시도합니다. 결과적으로 갱신에 실패하고 `OAuth2AuthorizationException`이 발생합니다. 이를 처리하려면 `clientManager.authorize()` 호출 부분에서 예외를 catch해 사용자를 재인가(`/oauth2/authorization/google?access_type=offline&prompt=consent`)로 리다이렉트합니다. 실무에서는 최초 로그인 시 반드시 `access_type=offline` 파라미터를 포함해 Refresh Token을 발급받아야 합니다. Spring Security에서는 `authorizationRequestCustomizer`로 이 파라미터를 추가할 수 있습니다.
>
> **Q3.** Spring Security 방법: Spring Security는 `JdbcOAuth2AuthorizedClientService`의 `setLobHandler()`로 암호화를 지원하지 않으므로 직접 구현이 필요합니다. 구현 방법: `JdbcOAuth2AuthorizedClientService`를 상속하거나 `OAuth2AuthorizedClientService` 인터페이스를 직접 구현합니다. `saveAuthorizedClient()` 재정의 시 `AES-256-GCM`으로 Access Token과 Refresh Token 값을 암호화 후 저장합니다. `loadAuthorizedClient()` 재정의 시 복호화 후 반환합니다. 암호화 키는 환경 변수나 KMS(AWS KMS, HashiCorp Vault)에서 관리합니다. 또는 DB 컬럼 수준 암호화(Transparent Data Encryption)를 활용하는 방법도 있습니다.

---

<div align="center">

**[← 이전: ClientRegistration과 InMemoryClientRegistrationRepository](./04-client-registration.md)** | **[홈으로 🏠](../README.md)** | **[다음: Custom OAuth2UserService 작성 ➡️](./06-custom-oauth2-user-service.md)**

</div>
