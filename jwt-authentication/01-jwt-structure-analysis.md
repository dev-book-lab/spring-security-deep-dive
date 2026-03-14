# JWT 구조 완전 분석 — Header, Payload, Signature의 역할과 검증 순서

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- JWT의 세 파트(Header, Payload, Signature)는 각각 무엇을 인코딩하며 왜 Base64URL을 사용하는가?
- `alg` 헤더 필드가 `none`으로 설정된 토큰을 왜 반드시 거부해야 하는가?
- `iss`, `sub`, `exp`, `iat`, `jti` 표준 클레임의 검증 순서가 보안에 미치는 영향은?
- HS256(대칭키)과 RS256(비대칭키)의 차이가 마이크로서비스 환경에서 중요한 이유는?
- JWT는 암호화가 아닌 서명이므로 Payload 내용을 누구나 읽을 수 있다 — 어떤 데이터를 Payload에 넣어도 되는가?
- `nbf`(Not Before) 클레임은 어떤 시나리오에서 유용한가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 토큰 기반 인증의 핵심 문제: 위조 방지

```
서버가 발급한 토큰을 클라이언트가 보관하고 재사용하는 방식에서
핵심 문제: 클라이언트가 토큰 내용을 변조할 수 없어야 함

예시:
  서버 발급: {"userId": 1, "role": "USER"}
  공격자 변조: {"userId": 1, "role": "ADMIN"}
  → 서버가 이 변조를 감지할 수 없으면 보안 완전 붕괴

JWT 해결책:
  Payload의 내용 + SecretKey로 해시(Signature) 생성
  Payload 변조 → Signature 불일치 → 서버가 감지
  SecretKey를 모르면 유효한 Signature 생성 불가

구조:
  BASE64URL(Header) . BASE64URL(Payload) . BASE64URL(Signature)
  ──────────────────────────────────────────────────────────────
  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJraW0ifQ.abc123xyz
```

---

## 😱 흔한 보안 실수

### Before: alg=none 취약점 — 서명 검증 우회

```java
// ❌ 서명 알고리즘 검증 없이 토큰 파싱 (CVE-2015-9235 계열)
public Claims parseToken(String token) {
    return Jwts.parser()
        .setSigningKey(secretKey)
        .parseClaimsJws(token) // 취약한 구현은 alg=none 수용
        .getBody();
}

// 공격자: alg=none 토큰 수동 생성
// Header: {"alg":"none","typ":"JWT"}
// Payload: {"sub":"admin","roles":["ROLE_ADMIN"]}
// Signature: (없음)
// → 취약한 라이브러리는 서명 없이 통과

// ✅ jjwt 최신 버전은 기본으로 alg=none 거부
public Claims parseToken(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(getSecretKey())       // Key 명시 필수
        .requireIssuer("https://myapp.com") // iss 검증
        .build()
        .parseClaimsJws(token)
        .getBody();
    // alg=none → UnsupportedJwtException
}
```

### Before: Payload에 민감 정보 저장

```java
// ❌ JWT Payload는 누구나 Base64URL 디코딩으로 읽을 수 있음 (암호화 아님)
Map<String, Object> claims = Map.of(
    "password", "hashed_pw",    // ← 노출
    "ssn", "800101-1234567",    // ← 개인정보 노출
    "creditCard", "4111-..."    // ← 금융정보 노출
);

// ✅ 식별자와 권한 정보만 포함
Map<String, Object> claims = Map.of(
    "userId", 1L,
    "username", "kim",
    "roles", List.of("ROLE_USER") // 민감 정보는 userId로 DB 조회
);
```

---

## ✨ 올바른 보안 구현

### JWT 세 파트 완전 분석

```java
// ── Part 1: Header ─────────────────────────────────────────────────
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
// → Base64URL 디코딩
// {"alg":"HS256","typ":"JWT"}

// alg: 서명 알고리즘
//   HS256 = HMAC-SHA256 (대칭키: 서명/검증에 동일한 secretKey)
//   RS256 = RSA-SHA256  (비대칭: privateKey 서명, publicKey 검증)
//   ES256 = ECDSA-SHA256 (타원곡선, RS256보다 짧은 키)
//   none  = 서명 없음 → 절대 허용 금지
// kid: 키 ID (여러 키 순환 시 어떤 키로 서명했는지 식별)

// ── Part 2: Payload (Claims) ───────────────────────────────────────
// eyJzdWIiOiJraW0iLCJ1c2VySWQiOjEsInJvbGVzIjpbIlJPTEVfVVNFUiJdfQ
// → Base64URL 디코딩
// {
//   "iss": "https://myapp.com",  // Issuer: 발급자 (다른 서비스 토큰 혼용 방지)
//   "sub": "kim",               // Subject: 토큰 주체 (username 또는 userId)
//   "iat": 1699999999,          // Issued At: 발급 시각 (Unix timestamp)
//   "exp": 1700003599,          // Expiration: 만료 시각 (필수 검증)
//   "nbf": 1699999999,          // Not Before: 이 시각 이전 무효 (미래 예약 토큰)
//   "jti": "uuid-123",          // JWT ID: 고유 식별자 (Replay 공격 방지)
//   "userId": 1,                // 커스텀 클레임
//   "roles": ["ROLE_USER"]      // 커스텀 클레임
// }

// ── Part 3: Signature ──────────────────────────────────────────────
// HMAC_SHA256(
//   BASE64URL(Header) + "." + BASE64URL(Payload),
//   secretKey
// ) → Base64URL
// → Payload 변조 시 Signature 불일치 → 서버가 감지

// 알고리즘별 선택 기준:
@Configuration
public class JwtAlgorithmConfig {

    // HS256: 단일 서버, 빠름
    @Bean
    @ConditionalOnProperty("jwt.algorithm", havingValue = "HS256")
    public JwtTokenProvider hs256Provider(@Value("${jwt.secret}") String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret); // 최소 32바이트
        return new JwtTokenProvider(Keys.hmacShaKeyFor(keyBytes));
    }

    // RS256: 마이크로서비스, privateKey 서명 / publicKey 검증 분리
    // 인가 서버만 privateKey 보유 → 리소스 서버는 publicKey(공개)로 검증
    @Bean
    @ConditionalOnProperty("jwt.algorithm", havingValue = "RS256")
    public SecurityFilterChain rs256ResourceServer(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwkSetUri("https://auth-server/.well-known/jwks.json")
            )
        );
        return http.build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. Base64URL vs Base64 — URL 안전성

```java
// 표준 Base64: +, /, = 사용
//   URL에서 +는 공백, /는 경로 구분자 → URL에 넣으면 깨짐
// Base64URL: +→-, /→_, = 패딩 제거
//   URL 파라미터, HTTP 헤더에 안전하게 사용

String urlSafe = Base64.getUrlEncoder().withoutPadding()
    .encodeToString("{\"alg\":\"HS256\"}".getBytes());
// "eyJhbGciOiJIUzI1NiJ9"  (URL 안전)

// 디코딩:
new String(Base64.getUrlDecoder().decode("eyJhbGciOiJIUzI1NiJ9"));
// {"alg":"HS256"}
```

### 2. 표준 클레임 검증 순서 (jjwt DefaultJwtParser 내부)

```java
// parseClaimsJws() 단계별 처리:

// 단계 1: 형식 검사
//   token.split("\\.") → 3개 파트 여부
//   MalformedJwtException: 3파트 아닌 경우

// 단계 2: Header 파싱
//   BASE64URL 디코딩 → JSON → JwsHeader
//   alg 추출 → 서명 알고리즘 결정

// 단계 3: Signature 검증 ← 변조 여부를 가장 먼저 확인
//   signingInput = parts[0] + "." + parts[1]
//   expected = HMAC_SHA256(signingInput, secretKey)
//   actual = Base64URL.decode(parts[2])
//   MessageDigest.isEqual(expected, actual) → 상수 시간 비교
//   불일치 → SignatureException
//
//   MessageDigest.isEqual()를 쓰는 이유:
//   일반 Arrays.equals()는 첫 불일치 바이트에서 즉시 return
//   → 공격자가 응답 시간으로 몇 바이트가 일치하는지 추론 (타이밍 공격)
//   상수 시간 비교: 항상 동일 시간 소요 → 추론 불가

// 단계 4: Payload 파싱
//   BASE64URL 디코딩 → JSON → Claims

// 단계 5: Claims 검증 순서
//   5a. exp:  now > exp + clockSkew  → ExpiredJwtException
//   5b. nbf:  now < nbf - clockSkew  → PrematureJwtException
//   5c. iss:  requireIssuer() 설정 시 → IncorrectClaimException
//   5d. aud:  requireAudience() 설정 시 → IncorrectClaimException
//   5e. 커스텀 require*() 검증

// Signature를 exp보다 먼저 검증하는 이유:
// 공격자가 exp만 변조한 토큰이 통과하는 것을 막기 위해
// → 변조된 클레임 값 자체를 신뢰하지 않음
```

### 3. Clock Skew — 분산 환경 시계 불일치 처리

```java
// 문제: 발급 서버와 검증 서버의 시계가 다를 수 있음
// NTP를 써도 수십 ms ~ 수 초 오차 발생
// 컨테이너: 호스트-컨테이너 동기화 불완전
// VM 일시정지 후 재개: 큰 시계 오차 가능

Jwts.parserBuilder()
    .setSigningKey(key)
    .setAllowedClockSkewSeconds(60) // ±60초 오차 허용
    .build()
    .parseClaimsJws(token);

// 트레이드오프:
// 60초 허용 → 만료된 토큰을 60초 더 수락
// 0초 → 정확하지만 분산 환경에서 오검증 발생 가능
// 권장: 30~60초
```

### 4. JWS(서명) vs JWE(암호화)

```
JWS (JSON Web Signature) — 일반적인 JWT
  구조: header.payload.signature  (3파트)
  특성: Base64URL 디코딩으로 Payload 열람 가능
  보장: 무결성(변조 감지) O, 기밀성(내용 숨김) X
  용도: 대부분의 인증 토큰

JWE (JSON Web Encryption)
  구조: header.encKey.iv.ciphertext.tag  (5파트)
  특성: 복호화 키 없이 내용 열람 불가
  보장: 무결성 O, 기밀성 O
  용도: 토큰 안에 민감 데이터를 반드시 포함해야 하는 경우

실무 결론:
  민감 정보는 Payload에 넣지 않는다 → JWS(일반 JWT)로 충분
  userId, roles는 노출돼도 무방 → JWE 불필요
```

---

## 💻 실험으로 확인하기

### 실험 1: JWT 직접 디코딩

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJraW0iLCJleHAiOjE3MDAwMDM1OTl9.xxx"

# Header 디코딩
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null
# {"alg":"HS256","typ":"JWT"}

# Payload 디코딩 (URL-safe base64 패딩 처리)
python3 -c "
import base64, sys
p = '$TOKEN'.split('.')[1]
print(base64.urlsafe_b64decode(p + '=='*((4-len(p)%4)%4)).decode())
"
# {"sub":"kim","exp":1700003599}
```

### 실험 2: 변조 감지 확인

```java
@Test
void tamperedPayload_throwsSignatureException() {
    String valid = jwtTokenProvider.createAccessToken(
        1L, "kim", List.of(new SimpleGrantedAuthority("ROLE_USER")));

    // Payload만 변조 (ROLE_USER → ROLE_ADMIN)
    String[] parts = valid.split("\\.");
    String tampered = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(
            "{\"sub\":\"kim\",\"roles\":[\"ROLE_ADMIN\"]}".getBytes());
    String tamperedToken = parts[0] + "." + tampered + "." + parts[2];

    // Signature 불일치 → 예외
    assertThatThrownBy(() -> jwtTokenProvider.getClaims(tamperedToken))
        .isInstanceOf(SignatureException.class);
}
```

### 실험 3: alg=none 토큰 거부 확인

```java
@Test
void algNone_throwsUnsupportedJwtException() {
    String header = Base64.getUrlEncoder().withoutPadding()
        .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
    String payload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString("{\"sub\":\"admin\",\"roles\":[\"ROLE_ADMIN\"]}".getBytes());
    String noneToken = header + "." + payload + ".";

    // 최신 jjwt: alg=none 거부
    assertThatThrownBy(() -> jwtTokenProvider.getClaims(noneToken))
        .isInstanceOf(UnsupportedJwtException.class);
}
```

---

## 🔒 보안 체크리스트

```
알고리즘 선택
  ☐ alg=none 토큰 거부 (최신 jjwt 기본 거부)
  ☐ 단일 서버: HS256 + secretKey 최소 256비트(32바이트)
  ☐ 마이크로서비스: RS256 또는 ES256 (비대칭키)
  ☐ secretKey 환경 변수 또는 Secrets Manager 저장 (코드 하드코딩 금지)

Payload 내용
  ☐ 민감 정보 포함 금지 (비밀번호, SSN, 카드번호)
  ☐ 최소 필요 정보만 (userId, roles, exp)
  ☐ Payload 크기 최소화 (모든 요청 헤더에 포함됨)

클레임 검증
  ☐ exp 검증 필수 (만료 토큰 거부)
  ☐ iss 검증 설정 (다른 서비스의 토큰 혼용 방지)
  ☐ aud 검증 설정 (다른 서비스용 토큰 거부)
  ☐ allowedClockSkewSeconds 30~60초 (0은 너무 엄격)

jti 활용
  ☐ 로그아웃 시 jti를 Redis 블랙리스트에 추가 (TTL=토큰만료시각)
  ☐ 고보안 환경: 매 요청마다 jti Redis 조회로 재사용 방지
```

---

## 🤔 트레이드오프

```
HS256 vs RS256:
  HS256:
    장점  빠름 (대칭키 연산), 구현 단순
    단점  검증 서버도 secretKey 보유 필요
          마이크로서비스에서 secretKey 공유 → 노출 위험

  RS256:
    장점  privateKey는 인가 서버만 보유 → 공격 표면 최소화
          JWKS 엔드포인트로 publicKey 자동 배포
    단점  RSA 연산 HS256보다 수십 배 느림 (EC256이 대안)

  선택 기준:
    소규모 단일 서버 → HS256
    마이크로서비스, OAuth2 인가 서버 → RS256 또는 ES256

JWT 크기 vs 정보량:
  Payload 많을수록 → 모든 요청 헤더 크기 증가
  작은 토큰 → 모든 API에서 DB 조회 필요
  큰 토큰 → DB 조회 최소화, 네트워크 비용 증가
  → 핵심 식별/권한 정보만 포함이 실용적 균형
```

---

## 📌 핵심 정리

```
JWT 세 파트
  Header:    {"alg":"HS256","typ":"JWT"} → Base64URL 인코딩
  Payload:   클레임 JSON → Base64URL (누구나 디코딩 가능)
  Signature: HMAC(Header.Payload, secretKey) → 변조 감지

검증 순서 (jjwt)
  형식 → Signature(상수시간비교) → exp → nbf → iss/aud

alg=none 취약점
  서명 없는 토큰 수용 → 보안 완전 우회
  최신 jjwt 기본 거부 → UnsupportedJwtException

HS256 vs RS256
  HS256: 대칭키, 단일 서버에 적합
  RS256: privateKey 서명 / publicKey 검증, 마이크로서비스 적합

Payload 원칙
  암호화 아님 → 민감 정보 절대 금지
  식별자 + 권한 정보만 포함, 크기 최소화
```

---

## 🤔 생각해볼 문제

**Q1.** JWT의 `exp` 클레임을 Unix timestamp로 표현할 때 서버들의 시계가 다르면 어떤 문제가 생기는가? NTP(Network Time Protocol)를 사용하는 환경에서도 `setAllowedClockSkewSeconds()`가 필요한 이유는?

**Q2.** 마이크로서비스 A와 B가 모두 같은 인가 서버에서 발급한 JWT를 수신합니다. A용 JWT의 `aud` 클레임이 `"service-a"`이고 B가 이 JWT를 `aud` 검증 없이 수락하면 어떤 보안 문제가 생기는가?

**Q3.** `jti` 클레임으로 토큰 재사용을 방지하려면 모든 요청마다 Redis에서 `jti`를 조회해 이미 사용됐는지 확인해야 합니다. 이것이 JWT의 "Stateless" 장점을 사실상 없애는 것 아닌가? 어떤 시나리오에서 `jti` 검증이 필요하고 어떤 시나리오에서 불필요한가?

> 💡 **해설**
>
> **Q1.** NTP를 사용해도 수십 밀리초~수 초의 오차가 발생합니다. 컨테이너 환경에서는 호스트-컨테이너 간 시계 동기화가 불완전할 수 있으며, VM 일시 정지 후 재개 시 큰 시계 오차가 발생합니다. 인가 서버가 `exp = now + 1시간`으로 발급하는 순간과 리소스 서버가 검증하는 순간 사이에 수초 오차가 있으면 방금 발급한 토큰도 검증에 실패할 수 있습니다. `setAllowedClockSkewSeconds(60)`은 이 현실적인 오차를 수용하는 실용적 설정입니다. 오차 허용 범위가 클수록 만료된 토큰을 더 오래 수락하는 트레이드오프가 있으므로 30~60초가 적절합니다.
>
> **Q2.** `aud` 검증 없이 서비스 B가 A용 JWT를 수락하면 "토큰 혼용" 공격이 가능합니다. 공격자가 서비스 A에서 유효하게 획득한 JWT를 서비스 B로 전달하면 B는 이 토큰을 신뢰합니다. 각 서비스는 자신의 `aud` 값이 포함된 토큰만 수락해야 합니다. 인가 서버는 클라이언트(서비스)마다 다른 `aud`를 토큰에 포함시키고, 각 리소스 서버는 `.requireAudience("service-b")`처럼 자신의 식별자가 `aud`에 있는 토큰만 수락해야 합니다.
>
> **Q3.** `jti` 검증은 특수한 경우에만 필요합니다. 필요한 시나리오: 로그아웃한 사용자의 토큰을 즉시 무효화해야 하는 경우, 일회용 토큰(비밀번호 재설정, 이메일 인증), 고보안 금융 거래에서 재사용 방지. 불필요한 시나리오: 액세스 토큰 만료 시간이 매우 짧을 때(5~15분이면 탈취 후 악용 창이 좁음), 로그아웃 후 즉각 무효화보다 만료를 기다릴 수 있는 일반 서비스. 실용적으로는 짧은 액세스 토큰(15분) + 로그아웃 시 jti 블랙리스트(Redis, TTL=토큰만료시각)를 조합해 "로그아웃된 토큰만" Redis에서 조회하는 방식으로 대부분의 요청에서 Redis 조회를 생략합니다.

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: Custom JWT Authentication Filter ➡️](./02-custom-jwt-filter.md)**

</div>
