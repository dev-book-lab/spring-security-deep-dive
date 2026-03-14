# JWT Token 검증과 SecurityContext 저장 — parseClaimsJws() 내부와 Authentication 생성

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `JwtParser.parseClaimsJws()`가 서명과 만료 시간을 검증하는 내부 단계는?
- 검증 성공 후 `Authentication` 객체를 생성해 `SecurityContextHolder`에 저장하는 정확한 코드 경로는?
- `UsernamePasswordAuthenticationToken.authenticated()`와 `unauthenticated()`의 차이는?
- JWT 기반 인증에서 `credentials`를 `null`로 설정해도 안전한 이유는?
- `SecurityContext`를 `SecurityContextHolder`에 설정할 때 스레드 안전성은 어떻게 보장되는가?
- `@AuthenticationPrincipal`로 Controller에서 사용자 정보를 주입받는 내부 동작은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 검증 → SecurityContext 저장의 중요성

```
JwtFilter: 토큰 검증 → SecurityContext 저장 안 함
AuthorizationFilter: SecurityContext 조회 → 익명 → 403

JwtFilter: 토큰 검증 → SecurityContext에 kimAuthentication 저장
AuthorizationFilter: authentication.getAuthorities() → ROLE_USER → 통과

SecurityContext 저장의 역할:
  이후 필터들이 인증된 사용자 정보를 공유
  Controller, @PreAuthorize 등에서 authentication 조회 가능
  요청 완료 후 SecurityContextHolderFilter가 자동 정리 (STATELESS)
```

---

## 😱 흔한 보안 실수

### Before: unauthenticated() 토큰을 SecurityContext에 저장

```java
// ❌ authorities=null → isAuthenticated()=false → AuthorizationFilter 거부
UsernamePasswordAuthenticationToken token =
    new UsernamePasswordAuthenticationToken(userDetails, password, null);
// null authorities → unauthenticated!

// ✅ authenticated() 팩토리 메서드 사용
UsernamePasswordAuthenticationToken auth =
    UsernamePasswordAuthenticationToken.authenticated(
        userDetails,
        null,                          // credentials: JWT 환경에서 null
        userDetails.getAuthorities()   // 반드시 포함
    );
```

### Before: SecurityContextHolder에 직접 접근 (테스트 어려움)

```java
// ❌ static 접근 → 테스트에서 교체 어려움
SecurityContextHolder.getContext().setAuthentication(authentication);

// ✅ SecurityContextHolderStrategy 사용
private SecurityContextHolderStrategy securityContextHolderStrategy =
    SecurityContextHolder.getContextHolderStrategy();

SecurityContext context = securityContextHolderStrategy.createEmptyContext();
context.setAuthentication(authentication);
securityContextHolderStrategy.setContext(context);
```

---

## ✨ 올바른 보안 구현

### 검증 → Authentication → SecurityContext 전체 구현

```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationProcessor {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private SecurityContextHolderStrategy securityContextHolderStrategy =
        SecurityContextHolder.getContextHolderStrategy();

    public void processAuthentication(String token, HttpServletRequest request) {

        Claims claims = jwtTokenProvider.getClaims(token);

        // tokenType 검증 (Refresh Token 혼용 방지)
        if (!"ACCESS".equals(claims.get("tokenType", String.class))) {
            throw new JwtException("Only access tokens are allowed for API auth");
        }

        String username = claims.getSubject();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // 계정 상태 검증
        if (!userDetails.isEnabled())
            throw new DisabledException("Account is disabled");
        if (!userDetails.isAccountNonLocked())
            throw new LockedException("Account is locked");

        // Authentication 생성 (반드시 authenticated 상태)
        UsernamePasswordAuthenticationToken authentication =
            UsernamePasswordAuthenticationToken.authenticated(
                userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request));

        // SecurityContext에 저장
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
    }
}
```

---

## 🔬 내부 동작 원리

### 1. parseClaimsJws() 내부 검증 단계

```java
// DefaultJwtParser.parseClaimsJws() 단계:

// 1단계: 토큰 분리
//   parts.length != 3 → MalformedJwtException

// 2단계: Header 파싱
//   alg 추출 (none → UnsupportedJwtException)

// 3단계: Signature 검증 ← 가장 먼저, 가장 중요
//   signingInput = parts[0] + "." + parts[1]
//   expectedSig = HMAC_SHA256(signingInput, secretKey)
//   actualSig   = Base64URL.decode(parts[2])
//
//   // 상수 시간 비교 (타이밍 공격 방지)
//   if (!MessageDigest.isEqual(expectedSig, actualSig))
//       throw SignatureException("JWT signature does not match")
//   일반 equals()는 첫 불일치에서 즉시 반환 → 공격자가 시간으로 추론 가능

// 4단계: Payload 파싱 → Claims

// 5단계: exp 검증
//   if (now > exp + allowedClockSkew) → ExpiredJwtException

// 6단계: nbf, iss, aud 등 검증
```

### 2. UsernamePasswordAuthenticationToken 상태 전이

```java
// unauthenticated (인증 전, 로그인 요청 시):
UsernamePasswordAuthenticationToken.unauthenticated(principal, credentials)
// → super.setAuthenticated(false) → isAuthenticated() = false

// authenticated (인증 후, JWT 필터에서):
UsernamePasswordAuthenticationToken.authenticated(principal, credentials, authorities)
// → super.setAuthenticated(true) → isAuthenticated() = true

// AuthorizationFilter 판단:
// isAuthenticated() = false → AccessDeniedException → 401
// isAuthenticated() = true  → 권한 검사 진행

// credentials=null 안전한 이유:
// JWT 환경에서 비밀번호 불필요
// eraseCredentials() 호출 시 null이면 아무것도 지울 것 없음
// 메모리에 비밀번호 잔류하지 않음 → 힙 덤프 공격 방어
```

### 3. SecurityContext 생명주기 (STATELESS)

```java
// SecurityContextHolderFilter.java (6.x):
public void doFilter(...) {
    // 요청 시작: 빈 SecurityContext 설정
    Supplier<SecurityContext> deferredContext =
        this.securityContextRepository.loadDeferredContext(httpRequest);
    // NullSecurityContextRepository → 항상 빈 컨텍스트
    this.securityContextHolderStrategy.setDeferredContext(deferredContext);

    try {
        chain.doFilter(request, response);
        // JwtFilter → Authentication 설정
        // AuthorizationFilter → Authentication 사용
        // Controller → @AuthenticationPrincipal
    } finally {
        // 요청 완료: 반드시 정리 (스레드 풀 재사용 문제 방지)
        this.securityContextHolderStrategy.clearContext();
        // STATELESS: saveContext() 호출 안 함 → 세션에 저장 안 함
    }
}
```

### 4. @AuthenticationPrincipal 처리

```java
// AuthenticationPrincipalArgumentResolver.resolveArgument():
// ① SecurityContextHolder.getContext().getAuthentication() 조회
// ② authentication.getPrincipal() 추출
// ③ expression 속성 있으면 SpEL 평가
//    @AuthenticationPrincipal(expression = "userId")
//    → principal.getUserId() SpEL 평가
// ④ 타입 검증 후 반환

// Controller 사용:
@GetMapping("/api/orders")
public List<Order> getOrders(
        @AuthenticationPrincipal CustomUserDetails userDetails) {
    return orderService.findByUserId(userDetails.getUserId());
}

// SpEL로 특정 필드:
@GetMapping("/api/profile")
public UserProfile getProfile(
        @AuthenticationPrincipal(expression = "userId") Long userId) {
    return userService.getProfile(userId);
}
```

---

## 💻 실험으로 확인하기

### 실험 1: authenticated vs unauthenticated 동작 차이

```java
@Test
void unauthenticatedToken_isRejected() {
    UsernamePasswordAuthenticationToken unauth =
        UsernamePasswordAuthenticationToken.unauthenticated("kim", null);
    assertThat(unauth.isAuthenticated()).isFalse();

    SecurityContextHolder.getContext().setAuthentication(unauth);
    assertThatThrownBy(() -> securedService.doSecuredThing())
        .isInstanceOf(AccessDeniedException.class);
    SecurityContextHolder.clearContext();
}

@Test
void authenticatedToken_isAccepted() {
    UserDetails user = createUser("kim", "ROLE_USER");
    UsernamePasswordAuthenticationToken auth =
        UsernamePasswordAuthenticationToken.authenticated(
            user, null, user.getAuthorities());
    assertThat(auth.isAuthenticated()).isTrue();

    SecurityContextHolder.getContext().setAuthentication(auth);
    assertDoesNotThrow(() -> securedService.doSecuredThing());
    SecurityContextHolder.clearContext();
}
```

### 실험 2: SecurityContext 생명주기 TRACE 로그

```yaml
logging:
  level:
    org.springframework.security.web.context: TRACE
```

```
TRACE SecurityContextHolderFilter - Set SecurityContextHolder to empty context
DEBUG JwtAuthenticationFilter   - JWT auth set: user=kim, path=/api/orders
DEBUG AuthorizationFilter        - Authorized
TRACE SecurityContextHolderFilter - Cleared SecurityContextHolder
```

### 실험 3: @AuthenticationPrincipal SpEL

```java
@SpringBootTest
@AutoConfigureMockMvc
class AuthPrincipalTest {

    @Test
    @WithMockUser(username = "kim", roles = "USER")
    void authPrincipal_injectedCorrectly() throws Exception {
        mockMvc.perform(get("/api/me"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("kim"));
    }
}
```

---

## 🔒 보안 체크리스트

```
Authentication 생성
  ☐ UsernamePasswordAuthenticationToken.authenticated() 사용
  ☐ authorities 반드시 포함 (빈 리스트도 isAuthenticated()=true)
  ☐ credentials=null (비밀번호 메모리 잔류 방지)

SecurityContext 설정
  ☐ SecurityContextHolderStrategy 사용 (테스트 용이)
  ☐ 새 SecurityContext 생성 후 Authentication 설정 (기존 컨텍스트 오염 방지)
  ☐ 요청 완료 후 clearContext() → SecurityContextHolderFilter 자동 처리
```

---

## 🤔 트레이드오프

```
DB 조회 포함 vs JWT 클레임만 사용:
  DB 조회:
    장점  계정 정지/비밀번호 변경 즉시 반영
    단점  모든 API 요청에 DB 조회 → 부하, 지연

  클레임만 사용:
    장점  DB 조회 없음 → 빠름, 수평 확장 용이
    단점  계정 정지가 토큰 만료 전까지 즉시 반영 안 됨
    → 짧은 토큰 + Redis 블랙리스트로 완화
```

---

## 📌 핵심 정리

```
parseClaimsJws() 검증 순서
  형식 → Signature(상수시간비교) → exp → nbf → iss/aud

Authentication 상태
  unauthenticated(): authorities=null → isAuthenticated()=false → 거부
  authenticated(): authorities 포함 → isAuthenticated()=true → 허용
  credentials=null: JWT 환경에서 안전

SecurityContext 생명주기 (STATELESS)
  요청 시작 → 빈 컨텍스트 (NullSecurityContextRepository)
  JwtFilter → Authentication 설정 (ThreadLocal)
  요청 완료 → clearContext() (SecurityContextHolderFilter finally)

@AuthenticationPrincipal
  → authentication.getPrincipal()
  → expression SpEL로 특정 필드 추출 가능
```

---

## 🤔 생각해볼 문제

**Q1.** `UsernamePasswordAuthenticationToken.authenticated(userDetails, null, userDetails.getAuthorities())`에서 `credentials`를 `null`로 설정합니다. `eraseCredentials()`가 나중에 호출되면 어떻게 동작하는가? 비밀번호를 메모리에 남기지 않는 것이 왜 중요한가?

**Q2.** `SecurityContextHolderFilter`의 `finally` 블록에서 `clearContext()`를 호출합니다. JwtFilter에서 이미 Authentication을 설정한 후 `clearContext()`를 안 하면 어떤 상황이 발생하는가?

**Q3.** Spring Security의 `SecurityContextHolder`는 기본적으로 `ThreadLocal`을 사용합니다. Java 21의 가상 스레드(Virtual Thread)에서 수백만 개가 생성되면 수백만 개의 `ThreadLocal` 인스턴스가 생성될 수 있습니다. 이 문제를 어떻게 설계로 해결할 수 있는가?

> 💡 **해설**
>
> **Q1.** `UsernamePasswordAuthenticationToken`은 `AbstractAuthenticationToken.eraseCredentials()`를 상속하며, `credentials`가 `Erasable` 인터페이스를 구현하면 `eraseCredentials()`를 호출하고 그렇지 않으면 필드를 `null`로 설정합니다. `credentials`가 이미 `null`이면 아무것도 하지 않으므로 안전합니다. 비밀번호를 메모리에 남기지 않는 것이 중요한 이유는 힙 덤프(heap dump) 공격에서 메모리를 분석하면 평문 또는 해시된 비밀번호가 노출될 수 있기 때문입니다. JVM GC가 객체를 수거하기 전까지 메모리에 잔류하므로 장기 실행 서버에서 위험합니다.
>
> **Q2.** 서블릿 컨테이너(Tomcat)는 스레드 풀을 사용하며, 하나의 스레드가 여러 요청을 순차적으로 처리합니다. 요청 A에서 JwtFilter가 kim의 Authentication을 ThreadLocal에 설정한 후 `clearContext()`가 호출되지 않으면 ThreadLocal에 kim의 SecurityContext가 남습니다. 다음 요청 B가 같은 스레드에서 처리될 때 kim의 SecurityContext가 그대로 남아있어 다른 사용자의 요청이 kim으로 처리될 수 있습니다. 이는 심각한 보안 취약점(사용자 간 데이터 유출)입니다. `finally` 블록의 `clearContext()`가 이를 방지합니다.
>
> **Q3.** 가상 스레드에서 `ThreadLocal` 남용 문제 해결 방법은 세 가지입니다. ① Java 21의 `ScopedValue`(JEP 446)를 사용합니다. `ScopedValue`는 가상 스레드에 최적화되어 상속 없이 명시적 범위(scope) 안에서만 유효합니다. ② Spring Security 6.x의 `RequestAttributeSecurityContextRepository`를 사용하면 SecurityContext를 ThreadLocal 대신 Request 속성에 저장합니다. ③ Spring WebFlux(Reactive)는 처음부터 Reactor Context에 SecurityContext를 저장하므로 ThreadLocal 문제가 없습니다.

---

<div align="center">

**[← 이전: JWT Token 발급 과정](./03-jwt-token-provider.md)** | **[홈으로 🏠](../README.md)** | **[다음: Refresh Token 전략 (RTR) ➡️](./05-refresh-token-rotation.md)**

</div>
