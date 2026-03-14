# JWT Token 발급 과정 (JwtTokenProvider) — 서명 과정과 SecretKey 관리 전략

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `io.jsonwebtoken` 라이브러리에서 토큰 서명 과정이 내부적으로 어떻게 동작하는가?
- `secretKey`를 `@Value`, 환경 변수, Secrets Manager 중 어떻게 관리해야 하는가?
- `Claims`에 `userId`와 `roles` 커스텀 클레임을 추가하는 올바른 방법은?
- HS256에서 SecretKey의 최소 길이가 256비트여야 하는 이유는?
- 토큰 발급 시 `iat`와 `exp`를 설정하는 올바른 방법과 타임존 이슈는?
- Access Token과 Refresh Token 발급 시 Claims를 어떻게 다르게 설정해야 하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### JwtTokenProvider의 역할

```
인증 성공 흐름:

  POST /api/auth/login
  → AuthenticationManager.authenticate() → 인증 성공
  → JwtTokenProvider.createAccessToken(userId, username, authorities)
     → Header + Payload 구성 → HMAC-SHA256 서명 → compact()
     → Access Token 문자열 반환
  → JwtTokenProvider.createRefreshToken(userId, username)
     → Refresh Token 반환
  → 응답: {"accessToken": "eyJ...", "refreshToken": "eyJ..."}

  이후 API 요청:
  → Authorization: Bearer <accessToken>
  → JwtAuthenticationFilter
  → JwtTokenProvider.validateToken(token) → 서명/만료 검증
  → JwtTokenProvider.getUsername(token) → SecurityContext 설정
```

---

## 😱 흔한 보안 실수

### Before: SecretKey를 코드에 하드코딩

```java
// ❌ 절대 금지: 코드에 SecretKey 하드코딩
@Component
public class JwtTokenProvider {
    private final String SECRET = "mySecretKey123"; // 8자 = 64비트 → 요구사항 미달
    // → Git에 영구 노출
    // → 모든 환경(개발/운영)이 같은 키 사용
    // → 256비트 미만 → WeakKeyException

    // ❌ Base64 인코딩을 암호화로 착각
    private final String SECRET_B64 = Base64.getEncoder()
        .encodeToString("mySecretKey".getBytes());
    // Base64는 인코딩일 뿐, 암호화 아님
}

// ✅ 환경 변수로 주입 + 최소 256비트 보장
@Value("${jwt.secret}")          // application.yml에서 주입
private String secretKeyBase64; // Base64 인코딩된 최소 32바이트 키

@PostConstruct
private void init() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKeyBase64);
    if (keyBytes.length < 32) {
        throw new IllegalArgumentException(
            "JWT secret key must be at least 256 bits (32 bytes)");
    }
    this.secretKey = Keys.hmacShaKeyFor(keyBytes);
}
```

### Before: Access Token과 Refresh Token을 동일하게 발급

```java
// ❌ 두 토큰이 완전히 동일한 구조 → Refresh Token을 Access Token으로 사용 가능
public String createToken(String username) {
    return Jwts.builder()
        .setSubject(username)
        .setExpiration(new Date(System.currentTimeMillis() + 3600_000))
        .signWith(secretKey)
        .compact();
}
// Refresh Token 탈취 → 직접 API 인증에 사용 가능

// ✅ tokenType 클레임으로 구분
public String createAccessToken(Long userId, String username, ...) {
    return Jwts.builder()
        .claim("tokenType", "ACCESS")   // ← 필수
        ...build();
}

public String createRefreshToken(Long userId, String username) {
    return Jwts.builder()
        .claim("tokenType", "REFRESH")  // ← 필수
        ...build();
}
// JwtAuthenticationFilter에서 tokenType="ACCESS"만 허용
```

---

## ✨ 올바른 보안 구현

### JwtTokenProvider 완전 구현

```java
@Component
@Slf4j
public class JwtTokenProvider {

    private SecretKey secretKey;
    private final long accessTokenValidityMs;
    private final long refreshTokenValidityMs;
    private final String issuer;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secretBase64,
            @Value("${jwt.access-token-validity-ms:900000}") long accessMs,  // 15분
            @Value("${jwt.refresh-token-validity-ms:604800000}") long refreshMs, // 7일
            @Value("${jwt.issuer:https://myapp.com}") String issuer) {

        byte[] keyBytes = Decoders.BASE64.decode(secretBase64);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes); // 256비트 미만 → WeakKeyException
        this.accessTokenValidityMs = accessMs;
        this.refreshTokenValidityMs = refreshMs;
        this.issuer = issuer;
    }

    // Access Token 발급 — 권한 정보 포함, 수명 짧음
    public String createAccessToken(Long userId, String username,
                                     Collection<? extends GrantedAuthority> authorities) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenValidityMs);

        List<String> roles = authorities.stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());

        return Jwts.builder()
            .setIssuer(issuer)                          // iss
            .setSubject(username)                       // sub
            .setIssuedAt(now)                           // iat (UTC 자동)
            .setExpiration(expiry)                      // exp
            .setId(UUID.randomUUID().toString())        // jti (블랙리스트 키)
            .claim("userId", userId)
            .claim("roles", roles)
            .claim("tokenType", "ACCESS")
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();
    }

    // Refresh Token 발급 — 최소 정보만, 수명 김, DB에 저장
    public String createRefreshToken(Long userId, String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + refreshTokenValidityMs);

        return Jwts.builder()
            .setIssuer(issuer)
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(expiry)
            .setId(UUID.randomUUID().toString())        // DB 저장 키
            .claim("userId", userId)
            .claim("tokenType", "REFRESH")              // Access 토큰 혼용 방지
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();
    }

    // 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .requireIssuer(issuer)
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.info("Token expired");
            throw e; // 호출자가 처리 (재발급 등)
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    // 클레임 추출 (유효한 토큰에서)
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    // 만료된 토큰에서도 클레임 추출 (Refresh 재발급 흐름에서 사용)
    public Claims getClaimsFromExpiredToken(String token) {
        try {
            return getClaims(token);
        } catch (ExpiredJwtException e) {
            return e.getClaims(); // 만료됐어도 클레임은 꺼낼 수 있음
        }
    }

    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    public Long getUserId(String token) {
        return getClaims(token).get("userId", Long.class);
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        return getClaims(token).get("roles", List.class);
    }

    public String getJti(String token) {
        return getClaims(token).getId();
    }
}
```

### SecretKey 초기 생성 방법

```java
// 방법 1: Keys.secretKeyFor() — 안전한 랜덤 키 자동 생성
public static void generateKey() {
    SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    String base64Key = Encoders.BASE64.encode(key.getEncoded());
    System.out.println("JWT_SECRET=" + base64Key);
    // → 이 값을 환경 변수에 저장
}
// 실행: java GenerateKey.java → 콘솔에 Base64 키 출력

// 방법 2: openssl 커맨드
// openssl rand -base64 32
// → 256비트 랜덤 Base64 키 생성
```

---

## 🔬 내부 동작 원리

### 1. jjwt 서명 내부 과정 (Jwts.builder().compact())

```java
// compact() 내부 단계:

// ① Header JSON 생성 + Base64URL 인코딩
// {"alg":"HS256","typ":"JWT"}
// → eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

// ② Payload(Claims) JSON 생성 + Base64URL 인코딩
// {"iss":"https://myapp.com","sub":"kim","iat":1699999999,...}
// → eyJpc3MiOiJodHRwczovL...

// ③ 서명 생성
// signingInput = Base64URL(header) + "." + Base64URL(payload)
// signature = HMAC_SHA256(signingInput.getBytes(UTF-8), secretKey)
// → Base64URL(signature)

// ④ 최종 조합
// compact = signingInput + "." + Base64URL(signature)

// Keys.hmacShaKeyFor() 내부:
// → 바이트 배열로 javax.crypto.spec.SecretKeySpec 생성
// → algorithm = "HmacSHA256"
// 최소 비트 요구사항:
// HS256 → 256비트(32바이트) 미달 시 WeakKeyException
// HS384 → 384비트(48바이트)
// HS512 → 512비트(64바이트)
```

### 2. Date 설정과 타임존 이슈

```java
// jjwt는 Date를 UTC Unix timestamp로 변환
// new Date() → JVM의 현재 시각 → UTC로 변환되어 토큰에 저장
// → 타임존 이슈 없음 (Date는 내부적으로 UTC)

// 단, 로컬 타임존으로 오해하는 코드:
Date expiry = new Date(2024, 1, 1, 0, 0, 0); // ← deprecated, 로컬 타임존 사용
// → 환경마다 다른 만료 시간

// 올바른 방법:
Date now = new Date(); // 현재 UTC 밀리초
Date expiry = new Date(now.getTime() + 900_000); // 지금으로부터 15분

// 또는 Instant 사용:
Instant now = Instant.now();
Date expiry = Date.from(now.plusSeconds(900));
```

### 3. Access Token vs Refresh Token 설계 비교

```
Access Token:
  목적: API 인증 (모든 요청에 첨부)
  수명: 15분 ~ 1시간 (짧음)
  포함 클레임: userId, username, roles, tokenType="ACCESS"
  저장: 클라이언트 메모리 또는 쿠키
  서버 저장: 불필요 (Stateless)
  탈취 시: 짧은 수명으로 피해 최소화

Refresh Token:
  목적: Access Token 재발급 전용
  수명: 7일 ~ 30일 (김)
  포함 클레임: userId, username, tokenType="REFRESH" (최소화)
  저장: 클라이언트 HttpOnly 쿠키 (JavaScript 접근 불가)
  서버 저장: DB 또는 Redis (유효성 관리, 탈취 감지)
  탈취 시: DB에서 무효화 가능 (RTR 전략)

tokenType 검증 위치:
  JwtAuthenticationFilter에서:
  String tokenType = claims.get("tokenType", String.class);
  if (!"ACCESS".equals(tokenType)) {
      throw new JwtException("Only access tokens accepted");
  }
```

### 4. 키 교체 전략 (Key Rotation)

```java
// kid (Key ID) 클레임을 활용한 키 교체
// 여러 키를 동시에 운용해 무중단 교체

@Component
public class JwtKeyManager {

    // 현재 활성 키
    private Map<String, SecretKey> keyStore = new ConcurrentHashMap<>();
    private String currentKeyId = "v1";

    // 발급: 현재 키 ID와 함께 서명
    public String createToken(String subject) {
        return Jwts.builder()
            .setHeaderParam("kid", currentKeyId) // kid 헤더 설정
            .setSubject(subject)
            ...
            .signWith(keyStore.get(currentKeyId))
            .compact();
    }

    // 검증: kid로 올바른 키 선택
    public Claims parseToken(String token) {
        // Header에서 kid 추출 (서명 검증 전)
        String kid = (String) Jwts.parserBuilder()
            .build()
            .parseClaimsJwt(withoutSignature(token))
            .getHeader()
            .get("kid");

        SecretKey key = keyStore.get(kid);
        if (key == null) throw new JwtException("Unknown key id: " + kid);

        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    // 키 교체: 새 키 추가 → 일정 기간 후 이전 키 제거
    public void rotateKey(String newKeyId, SecretKey newKey) {
        keyStore.put(newKeyId, newKey);
        currentKeyId = newKeyId;
        // 이전 키는 기존 토큰 만료 후 제거
        scheduleKeyRemoval(previousKeyId, Duration.ofHours(2));
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 키 강도 검증

```java
@Test
void weakKey_throwsWeakKeyException() {
    byte[] weakKey = "tooshort".getBytes(); // 8바이트 = 64비트
    assertThatThrownBy(() -> Keys.hmacShaKeyFor(weakKey))
        .isInstanceOf(WeakKeyException.class);
}

@Test
void properKey_256bits_works() {
    byte[] key = new byte[32]; // 32바이트 = 256비트
    new SecureRandom().nextBytes(key);
    assertDoesNotThrow(() -> Keys.hmacShaKeyFor(key));
}
```

### 실험 2: 발급 후 클레임 파싱 검증

```java
@Test
void createAccessToken_parsedClaimsCorrect() {
    String token = jwtTokenProvider.createAccessToken(
        1L, "kim", List.of(new SimpleGrantedAuthority("ROLE_USER")));

    Claims claims = jwtTokenProvider.getClaims(token);

    assertThat(claims.getSubject()).isEqualTo("kim");
    assertThat(claims.get("userId", Long.class)).isEqualTo(1L);
    assertThat(claims.get("roles", List.class)).contains("ROLE_USER");
    assertThat(claims.get("tokenType")).isEqualTo("ACCESS");
    assertThat(claims.getId()).isNotBlank(); // jti
    assertThat(claims.getExpiration()).isAfter(new Date());
}
```

### 실험 3: Refresh Token을 API에 사용 시도 차단 확인

```java
@Test
void refreshToken_usedForApi_returns401() throws Exception {
    String refreshToken = jwtTokenProvider.createRefreshToken(1L, "kim");

    mockMvc.perform(get("/api/orders")
            .header("Authorization", "Bearer " + refreshToken))
        .andExpect(status().isUnauthorized()); // tokenType 검증으로 차단
}
```

---

## 🔒 보안 체크리스트

```
SecretKey 관리
  ☐ 최소 256비트(32바이트) 이상 (Keys.hmacShaKeyFor가 WeakKeyException으로 강제)
  ☐ 환경 변수 또는 AWS Secrets Manager, Vault 저장
  ☐ Git, 코드, 설정 파일(application.yml)에 절대 하드코딩 금지
  ☐ 환경별(dev/staging/prod) 다른 키 사용

토큰 발급 설정
  ☐ exp 설정 필수 (무기한 토큰 발급 금지)
  ☐ iss 설정 및 검증
  ☐ jti 설정 (블랙리스트/Replay 방지 활용 시)
  ☐ tokenType 클레임으로 Access/Refresh 구분

Access/Refresh 분리
  ☐ Access Token: 15분~1시간 수명, 풍부한 클레임
  ☐ Refresh Token: 7~30일 수명, 최소 클레임 + DB 저장
  ☐ JwtAuthenticationFilter에서 tokenType="ACCESS"만 허용
```

---

## 🤔 트레이드오프

```
짧은 Access Token vs 긴 Access Token:
  짧음 (15분):
    장점  탈취 시 피해 시간 최소화, 계정 정지 빠르게 반영
    단점  Refresh Token 요청 빈번 → 인가 서버 부하

  긴 시간 (1시간~):
    장점  Refresh 빈도 감소, 사용자 경험 부드러움
    단점  탈취된 토큰의 악용 창이 넓음

DB 저장 vs Stateless:
  Access Token DB 저장:
    장점  즉시 무효화 가능
    단점  모든 API 요청에 DB 조회 → 확장성 저하 (JWT 장점 소멸)

  Refresh Token DB 저장 + Access Token Stateless:
    장점  Refresh 시에만 DB 조회 (빈도 낮음)
          Access 만료 시 즉시 무효화 효과 (짧은 수명으로 대체)
    단점  Access Token 탈취 후 수명 내 악용 가능
    → 가장 실용적인 균형점
```

---

## 📌 핵심 정리

```
jjwt 서명 과정 (compact())
  Header JSON → Base64URL
  Payload JSON → Base64URL
  HMAC_SHA256(header.payload, secretKey) → Base64URL
  → header.payload.signature 조합

SecretKey 생성
  Keys.secretKeyFor(HS256) → 안전한 랜덤 키
  Keys.hmacShaKeyFor(bytes) → 기존 키 복원
  최소 32바이트(256비트) — 미달 시 WeakKeyException

Access vs Refresh Token
  Access: 짧은 수명 + 풍부한 클레임 + Stateless
  Refresh: 긴 수명 + 최소 클레임 + DB 저장
  tokenType 클레임으로 혼용 방지

Date 설정
  new Date() → 내부적으로 UTC → 타임존 무관
  new Date(now.getTime() + ms) → 밀리초 단위로 만료 설정
```

---

## 🤔 생각해볼 문제

**Q1.** `@PostConstruct`에서 SecretKey를 초기화하는 방식과 생성자에서 초기화하는 방식의 차이는? 테스트 코드에서 `@MockBean`으로 `JwtTokenProvider`를 Mock 처리할 때 `@PostConstruct`가 호출되는가?

**Q2.** `Jwts.builder().setIssuedAt(new Date())`에서 `new Date()`는 JVM 로컬 시간을 사용합니다. 서버의 타임존이 UTC가 아닌 Asia/Seoul로 설정되어 있으면 `iat` 클레임에 어떤 값이 저장되며, 다른 서버(UTC 설정)에서 이 토큰을 검증할 때 문제가 생기는가?

**Q3.** `createRefreshToken()`에서 Refresh Token에 `roles` 클레임을 포함하지 않는 이유는? Refresh Token으로 Access Token을 재발급할 때 roles를 어디서 가져와야 하는가?

> 💡 **해설**
>
> **Q1.** 생성자에서 초기화하는 방식이 더 명확합니다. `@PostConstruct`는 Bean이 생성되고 의존성 주입이 완료된 후 실행됩니다. 생성자에서 `@Value`로 주입받으면 생성자 인수로 바로 처리할 수 있고, 불변 객체(`final`) 설계가 가능합니다. `@MockBean`으로 `JwtTokenProvider`를 목 처리하면 실제 인스턴스 생성이 일어나지 않으므로 `@PostConstruct`도 호출되지 않습니다. 반면 `@SpyBean`을 사용하면 실제 인스턴스에 Spy를 적용하므로 `@PostConstruct`가 호출됩니다.
>
> **Q2.** `new Date()`는 JVM의 `System.currentTimeMillis()`를 사용하며, 이는 항상 UTC 기준 Unix 타임스탬프(에포크 이후 밀리초)를 반환합니다. JVM 타임존 설정과 무관하게 동일한 밀리초 값이 사용됩니다. 따라서 Asia/Seoul 서버와 UTC 서버가 동일한 `new Date()` 값을 생성하고 `iat` 클레임에 동일한 Unix timestamp가 저장됩니다. 문제가 생기는 경우는 deprecated된 `new Date(year, month, day)` 생성자를 사용할 때인데, 이는 로컬 타임존을 사용하므로 서버마다 다른 값이 됩니다.
>
> **Q3.** Refresh Token에 `roles`를 포함하지 않는 이유는 두 가지입니다. 첫째, 보안상 Refresh Token이 탈취됐을 때 roles 정보까지 노출되는 것을 방지합니다. 둘째, Access Token 재발급 시 DB에서 최신 roles를 조회함으로써 권한 변경이 즉각 반영됩니다. Refresh Token만으로는 roles를 알 수 없으므로 재발급 엔드포인트에서 `userId`나 `username`으로 DB에서 `UserDetails.getAuthorities()`를 조회해 새 Access Token에 포함시킵니다. 이 방식이 "토큰에 roles를 넣고 DB 조회를 줄이는" 목표와 "항상 최신 roles를 반영"하는 목표를 균형있게 달성합니다.

---

<div align="center">

**[← 이전: Custom JWT Authentication Filter](./02-custom-jwt-filter.md)** | **[홈으로 🏠](../README.md)** | **[다음: JWT Token 검증과 SecurityContext 저장 ➡️](./04-jwt-validation-security-context.md)**

</div>
