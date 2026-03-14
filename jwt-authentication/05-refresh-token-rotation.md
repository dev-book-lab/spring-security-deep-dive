# Refresh Token 전략 (RTR — Refresh Token Rotation) — 탈취 감지와 Redis 저장소 구현

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- Access Token 만료 시 Refresh Token으로 재발급하는 전체 흐름은?
- RTR(Refresh Token Rotation) 전략이 Refresh Token 탈취를 어떻게 감지하는가?
- Redis 기반 Refresh Token 저장소를 구현할 때 키 구조와 TTL 설정 방법은?
- 이전 Refresh Token을 재사용했을 때 서버가 취해야 하는 보안 조치는?
- 여러 기기에서 동시 로그인을 지원하면서 RTR을 구현하는 방법은?
- Refresh Token을 클라이언트에서 어떻게 저장하는 것이 가장 안전한가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### Access Token만으로는 장기 세션을 안전하게 유지할 수 없다

```
문제: Access Token 수명 딜레마
  짧은 수명(15분): 보안 O, UX X (15분마다 로그인)
  긴 수명(24시간): UX O, 보안 X (탈취 시 24시간 악용 가능)

해결: Access Token(단기) + Refresh Token(장기) 분리
  Access Token:  15분 수명 → API 인증
  Refresh Token: 7일 수명  → Access Token 재발급 전용

  사용자 경험:
  → 백그라운드에서 15분마다 자동 재발급 (사용자 모름)
  → 7일 내에 한 번이라도 사용하면 세션 유지

Refresh Token 탈취 위험:
  RT 탈취 → 7일간 Access Token 무한 발급 가능

해결: RTR (Refresh Token Rotation)
  재발급 시마다 Refresh Token도 새로 발급
  이전 Refresh Token은 즉시 무효화
  이전 RT 재사용 감지 → 탈취 의심 → 모든 세션 강제 종료
```

---

## 😱 흔한 보안 실수

### Before: Refresh Token 재사용 허용 (회전 없음)

```java
// ❌ 탈취된 Refresh Token이 만료 전까지 계속 사용 가능
public TokenResponse refresh(String refreshToken) {
    validateRefreshToken(refreshToken); // 유효성만 확인
    String newAccessToken = createAccessToken(...);
    return new TokenResponse(newAccessToken, refreshToken); // RT 그대로 반환
}

// ✅ RTR: 재발급마다 Refresh Token도 교체
public TokenResponse refresh(String oldRefreshToken) {
    validateAndInvalidate(oldRefreshToken); // 검증 후 즉시 무효화
    String newAccessToken = createAccessToken(...);
    String newRefreshToken = createRefreshToken(...);
    saveToRedis(newRefreshToken);
    return new TokenResponse(newAccessToken, newRefreshToken);
}
```

### Before: Refresh Token을 LocalStorage에 저장

```javascript
// ❌ LocalStorage → XSS로 JavaScript 탈취 가능
localStorage.setItem('refreshToken', token);

// ✅ HttpOnly Secure 쿠키 → JavaScript 접근 불가
// 서버에서 설정:
ResponseCookie cookie = ResponseCookie.from("refreshToken", token)
    .httpOnly(true)           // JavaScript 접근 차단
    .secure(true)             // HTTPS에서만 전송
    .sameSite("Strict")       // 크로스 사이트 전송 차단 (CSRF 방어)
    .path("/api/auth/refresh") // 재발급 경로에서만 전송
    .maxAge(Duration.ofDays(7))
    .build();
response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
```

---

## ✨ 올바른 보안 구현

### Redis 기반 RTR 전체 구현

```java
// Redis 키 구조:
// refresh:token:{jti}   → "userId:username" (개별 토큰 유효성)
// refresh:user:{userId} → Set<jti>          (사용자의 모든 토큰 목록)

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final JwtTokenProvider jwtTokenProvider;
    private final StringRedisTemplate redisTemplate;
    private final UserDetailsService userDetailsService;

    private static final String TOKEN_PREFIX = "refresh:token:";
    private static final String USER_PREFIX  = "refresh:user:";

    // 로그인 성공 시 Refresh Token 저장
    public void save(Long userId, String username, String refreshToken) {
        String jti = jwtTokenProvider.getJti(refreshToken);
        long ttlSeconds = jwtTokenProvider.getRefreshTokenValidityMs() / 1000;

        // jti → userId:username (TTL = 토큰 수명)
        redisTemplate.opsForValue().set(
            TOKEN_PREFIX + jti, userId + ":" + username,
            Duration.ofSeconds(ttlSeconds));

        // userId → jti Set (다중 기기 지원)
        redisTemplate.opsForSet().add(USER_PREFIX + userId, jti);
        redisTemplate.expire(USER_PREFIX + userId, Duration.ofSeconds(ttlSeconds));
    }

    // Access Token 재발급 (RTR)
    public TokenResponse rotate(String oldRefreshToken, HttpServletResponse response) {
        // ① 만료됐어도 클레임 추출 (userId 필요)
        Claims claims = jwtTokenProvider.getClaimsFromExpiredToken(oldRefreshToken);
        String jti      = claims.getId();
        String username = claims.getSubject();
        Long   userId   = claims.get("userId", Long.class);

        // ② Redis에서 jti 유효성 확인
        String stored = redisTemplate.opsForValue().get(TOKEN_PREFIX + jti);

        if (stored == null) {
            // ★ jti가 없음 = 이미 사용된 토큰 재사용 → 탈취 의심
            revokeAll(userId, username);
            throw new JwtException("Refresh token reuse detected — possible theft");
        }

        // ③ 이전 jti 즉시 무효화
        redisTemplate.delete(TOKEN_PREFIX + jti);
        redisTemplate.opsForSet().remove(USER_PREFIX + userId, jti);

        // ④ 최신 사용자 정보로 새 토큰 발급
        UserDetails user = userDetailsService.loadUserByUsername(username);
        String newAccessToken  = jwtTokenProvider.createAccessToken(
            userId, username, user.getAuthorities());
        String newRefreshToken = jwtTokenProvider.createRefreshToken(userId, username);

        // ⑤ 새 Refresh Token 저장
        save(userId, username, newRefreshToken);

        // ⑥ HttpOnly 쿠키로 클라이언트에 전달
        setRefreshCookie(response, newRefreshToken);

        log.info("Tokens rotated: userId={}", userId);
        return new TokenResponse(newAccessToken); // 바디에는 Access Token만
    }

    // 탈취 감지: 해당 사용자의 모든 토큰 무효화
    private void revokeAll(Long userId, String username) {
        log.warn("[SECURITY] Refresh token reuse: userId={}, user={}", userId, username);
        Set<String> jtis = redisTemplate.opsForSet().members(USER_PREFIX + userId);
        if (jtis != null) {
            jtis.forEach(j -> redisTemplate.delete(TOKEN_PREFIX + j));
        }
        redisTemplate.delete(USER_PREFIX + userId);
        // → 해당 사용자의 모든 기기 강제 로그아웃
    }

    // 단일 기기 로그아웃
    public void revoke(String refreshToken) {
        try {
            Claims claims = jwtTokenProvider.getClaimsFromExpiredToken(refreshToken);
            String jti   = claims.getId();
            Long userId  = claims.get("userId", Long.class);
            redisTemplate.delete(TOKEN_PREFIX + jti);
            redisTemplate.opsForSet().remove(USER_PREFIX + userId, jti);
        } catch (Exception e) {
            log.warn("Revoke failed: {}", e.getMessage());
        }
    }

    private void setRefreshCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", token)
            .httpOnly(true).secure(true).sameSite("Strict")
            .path("/api/auth/refresh").maxAge(Duration.ofDays(7))
            .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}

// 재발급 컨트롤러
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RefreshTokenService refreshTokenService;

    @PostMapping("/refresh")
    public TokenResponse refresh(
            @CookieValue(name = "refreshToken", required = false) String rt,
            HttpServletResponse response) {
        if (rt == null) throw new JwtException("Refresh token not found");
        return refreshTokenService.rotate(rt, response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "refreshToken", required = false) String rt,
            HttpServletResponse response) {
        if (rt != null) refreshTokenService.revoke(rt);
        // 쿠키 삭제
        ResponseCookie del = ResponseCookie.from("refreshToken", "")
            .httpOnly(true).secure(true).path("/api/auth/refresh").maxAge(0).build();
        response.addHeader(HttpHeaders.SET_COOKIE, del.toString());
        return ResponseEntity.noContent().build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. RTR 탈취 감지 메커니즘

```
정상 흐름:
  로그인 → RT1(jti-1) 발급 → Redis: token:jti-1 = "1:kim"
  15분 후 → RT1으로 재발급
  → Redis에 jti-1 있음 → jti-1 삭제 → RT2(jti-2) 발급
  30분 후 → RT2로 재발급 → RT3 발급 ...

탈취 공격 시나리오:
  공격자가 RT1 탈취 (네트워크, XSS 등)
  정상 사용자가 먼저 RT1으로 재발급 → RT2 발급, jti-1 삭제
  공격자가 RT1으로 재발급 시도:
    → Redis에 jti-1 없음 → "재사용 감지"
    → 해당 사용자의 모든 RT 삭제 (RT2 포함)
    → 사용자 + 공격자 모두 재로그인 필요

공격자가 먼저 사용한 경우:
  공격자 → RT1으로 RT2 발급, jti-1 삭제
  정상 사용자 → RT1으로 재발급 시도
    → Redis에 jti-1 없음 → "재사용 감지"
    → RT2(공격자 보유) 포함 모든 토큰 삭제
    → 공격자 세션도 종료됨
```

### 2. Redis 키 구조와 원자성

```java
// 원자적 교체: DELETE + SET을 Lua 스크립트로 처리
DefaultRedisScript<Long> rotateScript = new DefaultRedisScript<>();
rotateScript.setScriptText("""
    local deleted = redis.call('DEL', KEYS[1])
    redis.call('SETEX', KEYS[2], ARGV[1], ARGV[2])
    redis.call('SREM', KEYS[3], ARGV[3])
    redis.call('SADD', KEYS[3], ARGV[4])
    return deleted
""");
rotateScript.setResultType(Long.class);

redisTemplate.execute(rotateScript,
    List.of(TOKEN_PREFIX + oldJti,              // KEYS[1]: 삭제할 키
            TOKEN_PREFIX + newJti,              // KEYS[2]: 새 키
            USER_PREFIX + userId),              // KEYS[3]: Set 키
    String.valueOf(ttlSeconds),                 // ARGV[1]: TTL
    userId + ":" + username,                    // ARGV[2]: 값
    oldJti,                                     // ARGV[3]: Set에서 제거
    newJti);                                    // ARGV[4]: Set에 추가

// 원자적 처리의 중요성:
// DELETE 성공 + SETEX 실패 → 새 토큰 없음, 이전 토큰도 없음 → 재로그인 필요
// DELETE 실패 + SETEX 성공 → 두 토큰 모두 유효 → 이전 토큰 재사용 시 탈취 감지
// Lua 스크립트: 두 연산 원자적으로 실행 → 불일치 상태 방지
```

### 3. 다중 기기 동시 로그인 지원

```java
// 기기별 다른 jti 보유:
// refresh:user:1 → Set{"jti-phone", "jti-pc", "jti-tablet"}

// 기기 A(phone) 로그아웃:
redisTemplate.delete(TOKEN_PREFIX + "jti-phone");
redisTemplate.opsForSet().remove(USER_PREFIX + 1, "jti-phone");
// → PC, Tablet 세션 영향 없음

// 전체 로그아웃 (비밀번호 변경 등):
Set<String> all = redisTemplate.opsForSet().members(USER_PREFIX + 1);
all.forEach(jti -> redisTemplate.delete(TOKEN_PREFIX + jti));
redisTemplate.delete(USER_PREFIX + 1);
// → 모든 기기 강제 로그아웃
```

### 4. 토큰 발급 전체 플로우

```
POST /api/auth/login (username, password)
  → AuthenticationManager.authenticate()
  → 인증 성공
  → jwtTokenProvider.createAccessToken() → AT (exp: 15분)
  → jwtTokenProvider.createRefreshToken() → RT (exp: 7일)
  → refreshTokenService.save(userId, username, RT) → Redis 저장
  → 응답:
     body: {"accessToken": "eyJ...AT..."}
     Set-Cookie: refreshToken=eyJ...RT...; HttpOnly; Secure; Path=/api/auth/refresh

이후 API 요청:
  Authorization: Bearer eyJ...AT...
  → JwtAuthenticationFilter → 검증 → SecurityContext

AT 만료 후:
  POST /api/auth/refresh
  Cookie: refreshToken=eyJ...RT...
  → refreshTokenService.rotate(RT)
  → Redis: RT jti 확인 → 삭제 → 새 AT, RT 발급
  → 응답:
     body: {"accessToken": "eyJ...newAT..."}
     Set-Cookie: refreshToken=eyJ...newRT...; HttpOnly; Secure; Path=/api/auth/refresh
```

---

## 💻 실험으로 확인하기

### 실험 1: RTR 탈취 감지 시나리오

```java
@Test
void refreshTokenReuse_detectsTheft_revokesAllSessions() {
    // given: 로그인 후 RT1 발급
    String rt1 = loginAndGetRefreshToken("kim");

    // when: 정상 재발급 → RT1 무효화, RT2 발급
    TokenResponse res1 = refreshTokenService.rotate(rt1, mockResponse);
    String rt2 = res1.getRefreshToken();

    // then: 공격자가 탈취한 RT1으로 재시도
    assertThatThrownBy(() -> refreshTokenService.rotate(rt1, mockResponse))
        .isInstanceOf(JwtException.class)
        .hasMessageContaining("Refresh token reuse detected");

    // RT2도 무효화됨 (모든 세션 종료)
    assertThatThrownBy(() -> refreshTokenService.rotate(rt2, mockResponse))
        .isInstanceOf(JwtException.class);
}
```

### 실험 2: Redis 키 상태 확인

```bash
# 로그인 직후
redis-cli KEYS "refresh:*"
# 1) "refresh:token:uuid-abc"
# 2) "refresh:user:1"

redis-cli GET "refresh:token:uuid-abc"   # "1:kim"
redis-cli SMEMBERS "refresh:user:1"      # "uuid-abc"
redis-cli TTL "refresh:token:uuid-abc"   # 604800

# 재발급 후
redis-cli KEYS "refresh:*"
# 1) "refresh:token:uuid-xyz"  (새 jti)
# 2) "refresh:user:1"
# "refresh:token:uuid-abc" 삭제됨
```

### 실험 3: 다중 기기 독립성 확인

```bash
# 기기 A, B 각각 로그인
redis-cli SMEMBERS "refresh:user:1"
# 1) "jti-device-a"
# 2) "jti-device-b"

# 기기 A 로그아웃
POST /api/auth/logout (Cookie: refreshToken=<RT_A>)
redis-cli SMEMBERS "refresh:user:1"
# 1) "jti-device-b"  ← 기기 B는 유지

# 기기 B는 정상 사용 가능
POST /api/auth/refresh (Cookie: refreshToken=<RT_B>) → 200 OK
```

---

## 🔒 보안 체크리스트

```
RTR 구현
  ☐ 재발급 시 이전 Refresh Token 즉시 무효화
  ☐ 재사용 감지 시 해당 사용자의 모든 세션 무효화
  ☐ Redis DELETE + 새 토큰 저장을 Lua 스크립트로 원자적 처리

Refresh Token 저장
  ☐ 클라이언트: HttpOnly Secure 쿠키 (path=/api/auth/refresh)
  ☐ LocalStorage, sessionStorage 저장 금지
  ☐ 서버: Redis jti → userId:username + TTL

보안 이벤트
  ☐ 탈취 감지 시 WARN 로그 (userId, IP, 시각)
  ☐ 비밀번호 변경 시 모든 Refresh Token 무효화
  ☐ 계정 정지 시 즉시 모든 Refresh Token 무효화
```

---

## 🤔 트레이드오프

```
RTR vs 단일 장기 Refresh Token:
  RTR:
    장점  탈취 감지 가능, 이전 토큰 즉시 무효화
    단점  네트워크 오류 시 토큰 불일치 발생 가능
          → 재로그인 필요 (UX 저하)

  단일 Refresh Token (회전 없음):
    장점  네트워크 오류에 강인 (재시도 가능)
    단점  탈취 감지 불가, 만료 전까지 무효화 불가

RTR 네트워크 오류 대응:
  문제: 서버가 새 RT를 발급했지만 클라이언트가 응답 수신 실패
        → 이전 RT로 재시도 → 탈취 감지로 오판
  해결:
    A. Grace Period: 이전 RT를 짧은 시간(30초) 유효하게 유지
    B. Idempotency Key: 동일 요청 재처리 허용
    C. UX 희생: 재로그인 유도 (가장 단순)

HttpOnly 쿠키 vs LocalStorage:
  HttpOnly 쿠키:
    장점  XSS로 JavaScript 탈취 불가
    단점  CSRF 주의 (SameSite=Strict로 방어)
  LocalStorage:
    장점  JavaScript로 쉽게 관리
    단점  XSS로 탈취 가능 → 금지
```

---

## 📌 핵심 정리

```
RTR 핵심 원리
  재발급 시 이전 RT 무효화 + 새 RT 발급
  이전 RT 재사용 감지 → 탈취 의심 → 모든 세션 강제 종료

Redis 키 구조
  refresh:token:{jti} → "userId:username" (TTL = RT 수명)
  refresh:user:{userId} → Set{jti...}   (다중 기기 지원)

탈취 감지
  jti가 Redis에 없음 = 이미 사용된 토큰 재사용
  → 해당 사용자 전체 jti 삭제 → 모든 기기 로그아웃

클라이언트 저장
  Refresh Token: HttpOnly Secure 쿠키 (path 제한)
  Access Token: 메모리 변수 (JavaScript 변수)

다중 기기
  refresh:user:{userId} Set으로 기기별 jti 관리
  개별 로그아웃: 해당 jti만 삭제
  전체 로그아웃: Set 전체 삭제
```

---

## 🤔 생각해볼 문제

**Q1.** RTR 구현에서 "이전 Refresh Token 삭제"와 "새 Refresh Token 저장"이 원자적으로 이루어지지 않는 경우(서버 장애, Redis 연결 실패 등), 어떤 상태가 발생할 수 있으며 이를 방지하거나 복구하는 방법은?

**Q2.** Refresh Token을 `path=/api/auth/refresh` 쿠키로 설정하면 해당 경로에서만 전송됩니다. 하지만 공격자가 서버의 SSRF 취약점을 이용해 `/api/auth/refresh`로 요청을 유도하면 Refresh Token이 노출되는가?

**Q3.** 사용자가 비밀번호를 변경한 직후 이전 비밀번호로 발급된 Access Token은 아직 만료되지 않은 상태입니다. RTR 전략에서 비밀번호 변경 후 이전 Access Token이 계속 사용되는 것을 차단하는 방법은?

> 💡 **해설**
>
> **Q1.** 이전 토큰 삭제 성공 + 새 토큰 저장 실패 시 클라이언트는 새 토큰을 받지 못하고 이전 토큰은 무효화됐으므로 재로그인이 필요합니다. 새 토큰 저장 성공 + 이전 토큰 삭제 실패 시 두 토큰이 모두 유효해지고, 이전 토큰 사용 시 "탈취 감지"로 오판됩니다. Redis Lua 스크립트로 두 연산을 원자적으로 처리하면 이 불일치를 방지할 수 있습니다. 완벽한 원자성이 어렵다면 "이전 토큰을 짧은 Grace Period(30초) 동안 유효로 유지"하는 방법으로 네트워크 오류 시 재시도를 허용하고, Grace Period 이후에 자동 무효화합니다.
>
> **Q2.** SSRF로 `/api/auth/refresh`를 호출하더라도 공격자는 피해자 브라우저의 쿠키에 접근할 수 없습니다. SSRF는 서버에서 서버로 요청을 만드는 것이므로 피해자의 브라우저 쿠키가 포함되지 않습니다. CSRF(브라우저를 통한 크로스 사이트 요청)라면 `SameSite=Strict` 속성으로 방어됩니다. `SameSite=Strict`는 다른 사이트에서 해당 쿠키를 포함한 요청을 브라우저가 전송하지 않도록 차단합니다. 따라서 HttpOnly + Secure + SameSite=Strict 조합으로 대부분의 공격 벡터를 차단합니다.
>
> **Q3.** 세 가지 접근법이 있습니다. 첫째, 비밀번호 변경 시 해당 사용자의 모든 Refresh Token을 즉시 무효화합니다(RT는 Redis에서 삭제). 이렇게 하면 Access Token이 만료(최대 15분)되면 Refresh 재발급이 실패하고 재로그인이 필요합니다. 둘째, Access Token에 비밀번호 해시의 일부를 클레임으로 포함시켜 검증 시 DB의 현재 비밀번호 해시와 비교합니다(DB 조회 발생). 셋째, 가장 실용적인 방법은 짧은 Access Token 수명(15분) 유지입니다. 비밀번호 변경 시 Refresh Token만 무효화하면 최대 15분 내에 이전 Access Token이 만료되고 Refresh 재발급 실패로 재로그인이 필요합니다. 보안 요구가 높은 경우에만 두 번째 방법을 적용합니다.

---

<div align="center">

**[← 이전: JWT Token 검증과 SecurityContext 저장](./04-jwt-validation-security-context.md)** | **[홈으로 🏠](../README.md)** | **[다음: Claims 추출과 사용 ➡️](./06-claims-extraction.md)**

</div>
