# OAuth2 4가지 Grant Type — 사용 시나리오와 PKCE 확장

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- Authorization Code, Implicit, Resource Owner Password, Client Credentials — 각 Grant Type은 어떤 상황에 적합한가?
- Authorization Code Flow에서 Access Token이 브라우저에 직접 노출되지 않는 이유는?
- PKCE(Proof Key for Code Exchange)가 Authorization Code 가로채기 공격을 어떻게 방어하는가?
- `code_verifier`와 `code_challenge`의 수학적 관계는?
- Implicit Flow가 현재 deprecated된 이유와 대안은?
- Resource Owner Password Credentials가 여전히 사용 가능한 시나리오는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### OAuth2가 해결하는 문제: 제3자에게 권한을 위임

```
OAuth2 없이 제3자 앱이 사용자 데이터에 접근하려면:
  사용자 → "내 구글 비밀번호를 네이버에 알려줘"
  → 네이버가 구글 계정 완전 장악 가능
  → 비밀번호 변경 시 네이버 접근도 차단되지 않음
  → 어떤 권한을 줬는지 추적 불가

OAuth2로 해결:
  사용자 → 구글에서 직접 인증 → 네이버에는 Access Token(제한된 권한)만 발급
  → 네이버는 비밀번호를 절대 알 수 없음
  → 권한 범위(scope) 명시: 이메일만, 연락처만
  → Access Token 취소 → 접근 즉시 차단
  → 구글 계정 비밀번호 변경과 무관

핵심 참여자:
  Resource Owner:      사용자 (보호된 리소스의 주인)
  Client:              제3자 앱 (네이버 캘린더, Spring 앱 등)
  Authorization Server: 인증 서버 (Google, Kakao, GitHub)
  Resource Server:     API 서버 (Google API, Kakao API)
```

---

## 😱 흔한 보안 실수

### Before: Implicit Flow를 SPA에서 사용

```javascript
// ❌ Implicit Flow: Access Token이 URL Fragment에 노출
// https://app.com/callback#access_token=eyJ...&token_type=Bearer
// 문제:
// → URL Fragment는 브라우저 히스토리에 저장
// → Referer 헤더로 다른 사이트에 유출 가능
// → Token 탈취 공격(Token Leakage) 취약

// ✅ SPA에서도 Authorization Code + PKCE 사용 (RFC 9700 권장)
// PKCE로 시크릿 없이도 Code Injection 공격 방어
// Access Token이 URL에 절대 노출되지 않음
```

### Before: Resource Owner Password를 퍼스트파티 앱이라는 이유로 사용

```java
// ❌ Resource Owner Password Credentials 남용
// 사용자 아이디/비밀번호를 클라이언트가 직접 받음 → 신뢰 위험
POST /oauth/token
grant_type=password&username=kim&password=1234

// 문제:
// → 클라이언트 앱이 사용자 비밀번호를 알게 됨
// → 비밀번호를 메모리에 보관하는 동안 탈취 가능
// → MFA, CAPTCHA 등 인가 서버의 보안 정책 우회

// ✅ 자체 앱도 Authorization Code + PKCE로
// 사용자는 브라우저에서 직접 인증 서버에 자격증명 입력
// 클라이언트 앱은 자격증명에 절대 접근 불가
```

---

## ✨ 올바른 보안 구현

### Grant Type별 선택 가이드

```java
// ── Authorization Code Flow (+ PKCE) ─────────────────────────
// 대상: 웹 앱(서버사이드), SPA, 모바일 앱
// 특징: Code를 먼저 받고, 서버 간 Token 교환 (브라우저에 Token 미노출)
spring.security.oauth2.client.registration.google:
  authorization-grant-type: authorization_code
  # PKCE는 Spring Security 6.x에서 Public Client에 자동 적용

// ── Client Credentials Flow ───────────────────────────────────
// 대상: 서버 간 통신 (사용자 없는 백그라운드 서비스, 마이크로서비스)
// 특징: Resource Owner 없음, 클라이언트 자체 인증만
spring.security.oauth2.client.registration.internal-api:
  authorization-grant-type: client_credentials
  client-id: my-service
  client-secret: ${CLIENT_SECRET}

// ── Authorization Code + PKCE (공개 클라이언트) ───────────────
// SPA, 모바일에서 client_secret 없이 안전하게 사용
// code_verifier, code_challenge로 중간자 공격 방어
```

### PKCE 동작 구현 이해

```java
// PKCE 흐름 (Spring Security가 자동 처리):

// ① 클라이언트: 랜덤 code_verifier 생성
String codeVerifier = generateRandomString(43, 128); // 43~128자 랜덤 문자열

// ② code_challenge 계산
// code_challenge = BASE64URL(SHA256(code_verifier))
byte[] hash = MessageDigest.getInstance("SHA-256")
    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
String codeChallenge = Base64.getUrlEncoder().withoutPadding()
    .encodeToString(hash);

// ③ 인가 요청에 code_challenge 포함 (code_verifier는 서버에 안 보냄)
GET https://auth.example.com/oauth2/authorize
  ?response_type=code
  &client_id=my-client
  &code_challenge={codeChallenge}
  &code_challenge_method=S256  // SHA256 방식
  &state={randomState}

// ④ 인가 코드 수신
https://app.com/callback?code={authCode}&state={state}

// ⑤ Token 교환 시 code_verifier 포함
POST https://auth.example.com/oauth2/token
  grant_type=authorization_code
  &code={authCode}
  &code_verifier={codeVerifier}  // ③에서 보낸 challenge의 원본

// ⑥ 서버가 SHA256(code_verifier) == code_challenge 검증
// → 일치하면 Token 발급
// 공격자가 authCode를 가로채도 code_verifier 없으면 Token 교환 불가
```

---

## 🔬 내부 동작 원리

### 1. 4가지 Grant Type 비교

```
┌──────────────────────────────────────────────────────────────────┐
│ Authorization Code                                               │
│ 1. Client → Auth Server: 인가 요청 (code_challenge 포함)            │
│ 2. User: 인가 서버에서 직접 로그인 + 동의                               │
│ 3. Auth Server → Client: Authorization Code (짧은 수명, 1회용)      │
│ 4. Client → Auth Server: Code + code_verifier → Access Token     │
│ ✓ Token이 브라우저에 노출되지 않음 (서버→서버 교환)                        │
│ ✓ 웹 앱, SPA, 모바일에 적합                                          │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ Client Credentials                                               │
│ 1. Client → Auth Server: client_id + client_secret               │
│ 2. Auth Server → Client: Access Token                            │
│ ✓ Resource Owner(사용자) 없음                                       │
│ ✓ 서버 간 통신, 마이크로서비스 인증에 적합                                 │
│ ✗ 사용자 컨텍스트 없음 → 사용자 데이터 접근 불가                            │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ Resource Owner Password (DEPRECATED)                             │
│ 1. User → Client: username + password 직접 전달                    │
│ 2. Client → Auth Server: username + password                     │
│ 3. Auth Server → Client: Access Token                            │
│ ✗ 클라이언트가 비밀번호를 알게 됨 → 신뢰 문제                              │
│ ✗ MFA, CAPTCHA 등 인가 서버 보안 정책 우회                             │
│ → OAuth2.1에서 공식 제거됨                                           │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ Implicit (DEPRECATED)                                            │
│ 1. Client → Auth Server: 인가 요청                                 │
│ 2. Auth Server → Client: Access Token 즉시 반환 (URL Fragment)     │
│ ✗ Token이 URL에 노출됨 → 히스토리, Referer로 유출 가능                  │
│ → SPA에서도 Authorization Code + PKCE로 대체                        │
└──────────────────────────────────────────────────────────────────┘
```

### 2. PKCE — Code Injection 공격 방어

```
PKCE 없이 Code 가로채기 공격:
  공격자: 악성 앱 설치 (같은 redirect_uri 등록)
  사용자: 정상 앱에서 OAuth2 로그인 시작
  인가 서버: redirect_uri로 Authorization Code 반환
  공격자 앱: 같은 redirect_uri로 Code 가로채기
  공격자 앱: Code를 Token으로 교환 → 사용자 계정 탈취

PKCE로 방어:
  정상 앱: code_verifier 생성 → SHA256(verifier) = challenge 전송
  인가 서버: challenge를 세션에 저장
  공격자: Code 가로챔 (verifier는 모름)
  공격자: Code로 Token 교환 시도 → verifier 없음
  인가 서버: SHA256(verifier)가 challenge와 불일치 → Token 발급 거부
  → 공격자는 verifier 없이 Code를 사용할 수 없음

수학적 관계:
  code_verifier: 43~128자 랜덤 문자열 (A-Z, a-z, 0-9, -, ., _, ~)
  code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
  → SHA256은 단방향 → verifier 없이 challenge에서 verifier 역산 불가
```

### 3. Spring Security에서 Grant Type별 설정

```yaml
# application.yml

spring:
  security:
    oauth2:
      client:
        registration:
          # Authorization Code (소셜 로그인)
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid, profile, email
            authorization-grant-type: authorization_code

          # Client Credentials (서버 간 통신)
          internal-api:
            client-id: my-service-id
            client-secret: ${SERVICE_SECRET}
            authorization-grant-type: client_credentials
            token-uri: https://auth-server/oauth2/token

          # GitHub (Authorization Code 예시)
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: read:user, user:email
            authorization-grant-type: authorization_code

        provider:
          internal-api:
            token-uri: https://internal-auth.company.com/oauth2/token
```

### 4. Client Credentials Flow — 서버 간 API 호출

```java
// 마이크로서비스에서 다른 서비스 API 호출 시 Client Credentials 사용
@Configuration
public class OAuth2ClientConfig {

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientRepository clients) {

        // Client Credentials 전용 매니저
        OAuth2AuthorizedClientProvider provider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials() // Client Credentials 지원
                .build();

        DefaultOAuth2AuthorizedClientManager manager =
            new DefaultOAuth2AuthorizedClientManager(registrations, clients);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }
}

// Client Credentials로 외부 API 호출
@Service
@RequiredArgsConstructor
public class ExternalApiService {

    private final OAuth2AuthorizedClientManager clientManager;
    private final WebClient webClient;

    public ResponseData callExternalApi() {
        // Client Credentials 토큰 발급
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
            .withClientRegistrationId("internal-api")
            .principal("system") // 사용자 없으므로 시스템 식별자
            .build();

        OAuth2AuthorizedClient client = clientManager.authorize(request);
        String accessToken = client.getAccessToken().getTokenValue();

        return webClient.get()
            .uri("https://internal-api.company.com/data")
            .headers(h -> h.setBearerAuth(accessToken))
            .retrieve()
            .bodyToMono(ResponseData.class)
            .block();
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: PKCE code_verifier/challenge 수동 생성

```java
@Test
void pkce_codeVerifier_challenge_relationship() throws Exception {
    // code_verifier 생성 (43~128 ASCII 문자)
    SecureRandom random = new SecureRandom();
    byte[] verifierBytes = new byte[32];
    random.nextBytes(verifierBytes);
    String codeVerifier = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(verifierBytes);

    // code_challenge = BASE64URL(SHA256(verifier))
    byte[] hash = MessageDigest.getInstance("SHA-256")
        .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
    String codeChallenge = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(hash);

    // 검증: SHA256(verifier) == decode(challenge)
    assertThat(hash)
        .isEqualTo(Base64.getUrlDecoder().decode(codeChallenge));

    // 단방향 검증: challenge에서 verifier 역산 불가
    System.out.println("code_verifier:  " + codeVerifier);
    System.out.println("code_challenge: " + codeChallenge);
}
```

### 실험 2: Spring Security OAuth2 로그인 URL 확인

```bash
# Spring Security가 생성하는 인가 요청 URL (PKCE 포함)
curl -v http://localhost:8080/oauth2/authorization/google 2>&1 | grep "Location:"

# 기대 출력:
# Location: https://accounts.google.com/o/oauth2/auth
#   ?response_type=code
#   &client_id=<CLIENT_ID>
#   &redirect_uri=http://localhost:8080/login/oauth2/code/google
#   &scope=openid%20profile%20email
#   &state=<RANDOM_STATE>
#   &code_challenge=<SHA256_CHALLENGE>
#   &code_challenge_method=S256
```

### 실험 3: Client Credentials 토큰 발급 확인

```bash
# Client Credentials 토큰 직접 요청
curl -X POST https://auth-server/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=my-service" \
  -d "client_secret=my-secret" \
  -d "scope=read:data"

# 응답:
# {
#   "access_token": "eyJ...",
#   "token_type": "Bearer",
#   "expires_in": 3600,
#   "scope": "read:data"
# }
# → refresh_token 없음 (Resource Owner 없으므로)
```

---

## 🔒 보안 체크리스트

```
Grant Type 선택
  ☐ 웹 앱/SPA/모바일: Authorization Code + PKCE
  ☐ 서버 간 통신: Client Credentials
  ☐ Implicit Flow 절대 사용 금지 (deprecated)
  ☐ Resource Owner Password 사용 금지 (deprecated)

PKCE 설정
  ☐ code_challenge_method: S256 (plain 방식 금지)
  ☐ code_verifier: 최소 43자, 최대 128자
  ☐ SecureRandom 사용 (Math.random() 금지)

Client Credentials 보안
  ☐ client_secret을 환경 변수/Secrets Manager 저장
  ☐ scope 최소화 (필요한 권한만 요청)
  ☐ Access Token 캐시 (만료 전까지 재사용)

state 파라미터
  ☐ 인가 요청마다 랜덤 state 생성 (CSRF 방어)
  ☐ 콜백에서 state 검증 필수
  ☐ Spring Security가 자동 처리 (직접 구현 불필요)
```

---

## 🤔 트레이드오프

```
Authorization Code vs Client Credentials:
  Authorization Code:
    장점  사용자 컨텍스트 포함 (누구의 데이터인지 알 수 있음)
    단점  사용자가 브라우저에서 직접 동의해야 함 → 자동화 어려움

  Client Credentials:
    장점  사용자 개입 없이 완전 자동화 가능
    단점  사용자 컨텍스트 없음 → 사용자 데이터 접근 불가

PKCE code_challenge_method: S256 vs plain:
  S256:
    장점  SHA256으로 단방향 변환 → 네트워크에서 verifier 노출 없음
    단점  SHA256 계산 필요
  plain:
    장점  구현 단순 (challenge == verifier)
    단점  MITM이 challenge를 보면 verifier 알 수 있음
    → 무조건 S256 사용
```

---

## 📌 핵심 정리

```
4가지 Grant Type
  Authorization Code + PKCE: 웹/SPA/모바일 (현재 표준)
  Client Credentials:         서버 간 M2M 통신
  Resource Owner Password:    OAuth2.1에서 제거 (금지)
  Implicit:                   deprecated, SPA도 Authorization Code로

PKCE (Proof Key for Code Exchange)
  code_verifier: 랜덤 문자열 (클라이언트가 생성, 서버에 처음 보내지 않음)
  code_challenge = BASE64URL(SHA256(code_verifier))
  인가 요청: challenge 전송
  Token 교환: verifier 전송 → 서버가 SHA256(verifier) == challenge 검증
  → Code 가로채도 verifier 없으면 Token 교환 불가

Implicit가 deprecated된 이유
  Access Token이 URL Fragment에 노출
  → 브라우저 히스토리, Referer 헤더로 유출 가능
  → SPA도 Authorization Code + PKCE로 해결 가능

Client Credentials 특징
  Resource Owner 없음 → refresh_token 없음
  client_id + client_secret으로만 인증
  서비스 계정(Service Account) 개념
```

---

## 🤔 생각해볼 문제

**Q1.** PKCE에서 `code_verifier`는 클라이언트가 생성해서 Token 교환 시에만 서버로 전송합니다. 서버는 인가 요청 시점에 `code_challenge`만 받아서 저장합니다. 공격자가 인가 서버와 클라이언트 사이에서 `code_challenge` 전송을 가로채서 자신의 `code_verifier`에 맞는 `code_challenge`로 교체하는 공격은 가능한가?

**Q2.** Client Credentials Flow에서 발급된 Access Token에는 특정 사용자의 정보가 없습니다. 마이크로서비스 A가 Client Credentials로 발급한 토큰으로 마이크로서비스 B의 API를 호출할 때, B는 "이 요청이 정말 A에서 온 것인지" 어떻게 검증하는가?

**Q3.** Authorization Code Flow에서 `state` 파라미터가 CSRF를 방어하는 원리는? 공격자가 피해자 브라우저를 통해 악성 인가 코드를 피해자 계정에 바인딩하는 공격(OAuth2 CSRF)을 `state` 검증이 어떻게 방어하는가?

> 💡 **해설**
>
> **Q1.** 이 공격은 성립하지 않습니다. 공격자가 `code_challenge`를 교체하려면 HTTPS 통신을 중간에서 가로채야 하는데(MITM), 이 자체가 TLS 인증서 검증으로 방어됩니다. 또한 `code_challenge`를 자신의 `code_verifier`에 맞게 교체해도 인가 서버가 발급하는 `code`는 교체된 `challenge`와 묶입니다. 공격자는 이 `code`를 자신의 `code_verifier`로 Token 교환에 성공하지만, 이는 피해자의 계정이 아닌 공격자 자신이 보낸 인가 요청의 결과입니다. 즉, `code`를 발급받은 계정이 공격자이므로 다른 사용자의 토큰을 얻는 것이 불가능합니다.
>
> **Q2.** 마이크로서비스 B는 Access Token의 `client_id` 클레임(또는 `sub` 클레임)을 확인해 요청 출처를 검증합니다. Client Credentials 토큰의 `sub`는 보통 `client_id`와 동일합니다. B는 인가 서버의 JWKS로 서명을 검증하고, 토큰의 `aud` 클레임에 자신의 서비스 식별자가 포함됐는지, `scope`에 요청된 권한이 있는지를 확인합니다. 즉, "A에서 온 요청"의 검증은 인가 서버가 A에게 발급한 토큰에 A의 `client_id`가 포함되어 있고 그 서명이 유효한지로 이루어집니다.
>
> **Q3.** OAuth2 CSRF 공격 시나리오: 공격자가 자신의 계정으로 인가를 시작해 `code`를 받지만 교환하지 않습니다. 이 `code`를 URL로 만들어 피해자가 클릭하게 합니다. 피해자의 브라우저가 `?code=ATTACKER_CODE&state=???`로 콜백 엔드포인트를 호출합니다. 만약 `state`를 검증하지 않으면, 피해자 계정에 공격자의 소셜 계정이 연결됩니다. `state` 방어 원리: 피해자의 브라우저는 인가 요청을 보내지 않았으므로 세션에 `state`가 없습니다. 공격자가 만든 URL에 임의의 `state`를 붙여도 피해자의 세션에 저장된 `state`와 일치하지 않아 콜백 처리를 거부합니다. Spring Security는 `state`를 세션에 저장하고 콜백에서 자동으로 비교합니다.

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: Authorization Code Flow 완전 분석 ➡️](./02-authorization-code-flow.md)**

</div>
