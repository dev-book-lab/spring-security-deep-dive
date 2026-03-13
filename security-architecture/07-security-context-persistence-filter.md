# SecurityContextPersistenceFilter 동작 — SecurityContext의 요청 간 영속성

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `SecurityContextPersistenceFilter`(구버전)와 `SecurityContextHolderFilter`(신버전)의 핵심 차이는 무엇인가?
- `HttpSessionSecurityContextRepository`는 `SecurityContext`를 HttpSession의 어느 속성에 저장하는가?
- 로그인 후 두 번째 요청에서 인증 상태가 유지되는 정확한 흐름은 무엇인가?
- JWT 환경에서 `SecurityContext`를 세션에 저장하지 않으려면 어떻게 설정해야 하는가?
- `SecurityContextRepository`를 커스터마이징해서 세션 대신 Redis에 저장할 수 있는가?
- `NullSecurityContextRepository`는 언제 사용하며 어떤 효과가 있는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: HTTP는 Stateless 프로토콜이다

```
HTTP 요청 흐름:
  요청 1 (POST /login)
    → AuthenticationManager에서 인증 성공
    → SecurityContext에 Authentication 저장
    → 응답 반환
    → 요청 1 처리 스레드 종료 (SecurityContext 사라짐)

  요청 2 (GET /dashboard)
    → 새 스레드 시작
    → SecurityContext가 비어 있음
    → 다시 로그인 요청??? ← 사용자 경험 최악

해결: SecurityContext를 요청 간에 영속화
  요청 1 종료 전: SecurityContext → HttpSession 저장
  요청 2 시작 시: HttpSession → SecurityContext 복원
  → 사용자는 한 번 로그인하면 세션 유지 기간 동안 재인증 불필요
```

---

## 😱 흔한 보안 실수

### Before: JWT 환경에서 SecurityContext가 세션에 저장되어 불필요한 세션 생성

```java
// ❌ 문제: SessionCreationPolicy.STATELESS 설정을 했지만
//   SecurityContextPersistenceFilter(구버전)가 여전히 세션을 생성할 수 있음

// Spring Security 5.x (SecurityContextPersistenceFilter):
// 인증 성공 후 SecurityContext를 HttpSession에 저장하는 로직이 내장됨
// STATELESS 설정이 세션 생성을 완전히 막지 않는 경우가 있었음

// Spring Security 6.x (SecurityContextHolderFilter):
// SecurityContextHolderFilter는 저장 책임이 없음
// → 인증 Filter가 명시적으로 SecurityContextRepository.saveContext() 호출해야 함
// → NullSecurityContextRepository 설정 시 저장 자체를 막을 수 있음

// ✅ JWT Stateless 환경 완전한 설정
http
    .sessionManagement(s -> s
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .securityContext(sc -> sc
        .securityContextRepository(new NullSecurityContextRepository()))
    // → HttpSession에 SecurityContext 저장 완전 차단
    // → 매 요청마다 JwtAuthenticationFilter에서 토큰 검증
```

### Before: 동일 요청 내에서 SecurityContext를 변경했지만 저장 시점을 놓침

```java
// ❌ 문제: 권한을 변경했지만 다음 요청에 반영되지 않음
@PostMapping("/promote-user")
@PreAuthorize("hasRole('ADMIN')")
public void promoteUser(@RequestParam Long userId,
                        HttpServletRequest request,
                        HttpServletResponse response) {
    userService.addRole(userId, "ROLE_MANAGER");

    // 현재 로그인한 사용자를 승격시키는 경우:
    Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
    // ... 새 Authentication 생성 ...
    SecurityContext newCtx = SecurityContextHolder.createEmptyContext();
    newCtx.setAuthentication(newAuth);
    SecurityContextHolder.setContext(newCtx);

    // ❌ SecurityContextRepository에 저장하지 않음
    // → 다음 요청 시 HttpSession에서 이전 SecurityContext 복원
    // → 권한 변경이 반영되지 않음
}

// ✅ 올바른 방법: SecurityContextRepository를 통해 저장
@Autowired
SecurityContextRepository securityContextRepository;

@PostMapping("/promote-user")
public void promoteUser(...) {
    // ...
    SecurityContextHolder.setContext(newCtx);
    // HttpSession에 새 SecurityContext 저장
    securityContextRepository.saveContext(newCtx, request, response);
}
```

---

## ✨ 올바른 보안 구현

### 세션 기반 vs Stateless 저장소 선택

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // ── 세션 기반 (웹 애플리케이션) ──────────────────────────────────
    @Bean
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
            .securityContext(sc -> sc
                // 기본값: HttpSessionSecurityContextRepository
                // 세션에 SecurityContext 저장/로드
                .securityContextRepository(new HttpSessionSecurityContextRepository())
                // requireExplicitSave(true): 명시적 save 호출 시에만 저장 (6.x 기본)
                // requireExplicitSave(false): 응답 전 자동 저장 (5.x 방식)
                .requireExplicitSave(true)
            );
        return http.build();
    }

    // ── JWT Stateless ───────────────────────────────────────────────
    @Bean
    public SecurityFilterChain jwtChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .securityContext(sc -> sc
                // 저장 자체를 하지 않음 → 매 요청마다 토큰 재검증
                .securityContextRepository(new NullSecurityContextRepository()));
        return http.build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. SecurityContextPersistenceFilter (Spring Security 5.x, deprecated)

```java
// SecurityContextPersistenceFilter.java (deprecated since 5.7)
public class SecurityContextPersistenceFilter extends GenericFilterBean {

    private SecurityContextRepository repo;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // ① 요청 시작: HttpSession에서 SecurityContext 즉시 로드
        SecurityContext contextBeforeChainExecution =
            repo.loadContext(new HttpRequestResponseHolder(httpRequest, httpResponse));

        try {
            // ② ThreadLocal에 저장
            SecurityContextHolder.setContext(contextBeforeChainExecution);
            chain.doFilter(httpRequest, httpResponse);
        } finally {
            // ③ 요청 종료: 변경된 SecurityContext를 HttpSession에 저장
            SecurityContext contextAfterChainExecution =
                SecurityContextHolder.getContext();
            SecurityContextHolder.clearContext(); // ThreadLocal 정리

            // ④ 변경이 있었으면 세션에 저장
            repo.saveContext(contextAfterChainExecution, httpRequest, httpResponse);
        }
    }
}

// 문제점:
// 모든 요청에서 즉시 세션 I/O 발생 (정적 리소스 요청에도)
// filter 내에서 저장을 담당 → 개발자가 저장 시점 제어 어려움
```

### 2. SecurityContextHolderFilter (Spring Security 6.x, 현재)

```java
// SecurityContextHolderFilter.java
public class SecurityContextHolderFilter extends GenericFilterBean {

    private final SecurityContextRepository securityContextRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws ServletException, IOException {

        // ① 지연 로딩: Supplier만 저장, 실제 I/O는 최초 getContext() 호출 시
        Supplier<SecurityContext> deferredContext =
            this.securityContextRepository.loadDeferredContext(
                (HttpServletRequest) request);

        try {
            SecurityContextHolder.setDeferredContext(deferredContext);
            chain.doFilter(request, response);
        } finally {
            // ② ThreadLocal 정리만 담당 (저장은 책임지지 않음)
            SecurityContextHolder.clearContext();
        }

        // 저장 책임: 인증에 성공한 각 Filter가 직접 saveContext() 호출
        // UsernamePasswordAuthenticationFilter.successfulAuthentication() 내부:
        //   securityContextRepository.saveContext(context, request, response)
    }
}
```

### 3. HttpSessionSecurityContextRepository — 세션 기반 저장

```java
// HttpSessionSecurityContextRepository.java
public class HttpSessionSecurityContextRepository
        implements SecurityContextRepository {

    // HttpSession에 SecurityContext를 저장할 속성 이름
    public static final String SPRING_SECURITY_CONTEXT_ATTR_NAME =
        "SPRING_SECURITY_CONTEXT";

    // ── 로드: HttpSession → SecurityContext ──────────────────────────
    @Override
    public DeferredSecurityContext loadDeferredContext(
            HttpServletRequest request) {
        return new SupplierDeferredSecurityContext(
            // Supplier: 처음 get()이 호출될 때 실제 로드
            () -> readSecurityContextFromSession(request.getSession(false)),
            this.securityContextHolderStrategy
        );
    }

    private SecurityContext readSecurityContextFromSession(HttpSession session) {
        if (session == null) {
            return generateNewContext(); // 빈 SecurityContext 반환
        }
        Object contextFromSession =
            session.getAttribute(SPRING_SECURITY_CONTEXT_ATTR_NAME);
        if (contextFromSession == null) {
            return generateNewContext();
        }
        if (!(contextFromSession instanceof SecurityContext)) {
            return generateNewContext(); // 타입 불일치 → 새 컨텍스트
        }
        return (SecurityContext) contextFromSession;
    }

    // ── 저장: SecurityContext → HttpSession ──────────────────────────
    @Override
    public void saveContext(SecurityContext context,
                            HttpServletRequest request,
                            HttpServletResponse response) {
        // 익명 Authentication이거나 저장할 필요 없으면 스킵
        Authentication authentication = context.getAuthentication();
        if (authentication == null || trustResolver.isAnonymous(authentication)) {
            // 익명 사용자의 SecurityContext는 세션에 저장하지 않음
            // → 불필요한 세션 생성 방지
            return;
        }

        HttpSession session = request.getSession(false);
        if (session == null) {
            if (contextChanged(context)) {
                // SecurityContext가 변경됐으면 세션 생성 후 저장
                session = request.getSession(true);
            } else {
                return;
            }
        }

        // "SPRING_SECURITY_CONTEXT" 속성에 SecurityContext 저장
        session.setAttribute(SPRING_SECURITY_CONTEXT_ATTR_NAME, context);
    }
}
```

### 4. 요청 간 SecurityContext 유지 전체 흐름

```
첫 번째 요청: POST /login (username=kim, password=1234)
│
├─ SecurityContextHolderFilter
│    loadDeferredContext() → HttpSession 없음 → 빈 SecurityContext Supplier
│
├─ UsernamePasswordAuthenticationFilter
│    attemptAuthentication()
│    → DaoAuthenticationProvider.authenticate() → 인증 성공
│    → successfulAuthentication() 호출:
│         SecurityContext ctx = SecurityContextHolder.createEmptyContext()
│         ctx.setAuthentication(usernamePasswordAuthToken)
│         SecurityContextHolder.setContext(ctx)
│         securityContextRepository.saveContext(ctx, request, response)
│         ┌─────────────────────────────────────────────────────────┐
│         │ HttpSession["SPRING_SECURITY_CONTEXT"] = SecurityContext│ ← 저장!
│         └─────────────────────────────────────────────────────────┘
│         Set-Cookie: JSESSIONID=ABC123 응답 헤더 추가
│
└─ 응답: 200 OK (Set-Cookie: JSESSIONID=ABC123)


두 번째 요청: GET /dashboard (Cookie: JSESSIONID=ABC123)
│
├─ SecurityContextHolderFilter
│    loadDeferredContext()
│    → request.getSession(false) → HttpSession(ABC123) 발견
│    → Supplier 생성 (아직 로드 안 함)
│
├─ (다른 Filter들)
│
├─ AuthorizationFilter
│    SecurityContextHolder.getContext().getAuthentication()
│    → Supplier.get() 호출 (지연 로드 실행)
│    → HttpSession["SPRING_SECURITY_CONTEXT"] 조회
│    → kim의 Authentication 반환
│    → 권한 검사 → 통과
│
└─ Controller: "Welcome, kim!"
```

### 5. NullSecurityContextRepository — Stateless JWT 환경

```java
// NullSecurityContextRepository.java
public final class NullSecurityContextRepository implements SecurityContextRepository {

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        // 항상 빈 SecurityContext 반환 (세션 조회 없음)
        return new SupplierDeferredSecurityContext(
            SecurityContextHolder.getContextHolderStrategy()::createEmptyContext,
            SecurityContextHolder.getContextHolderStrategy()
        );
    }

    @Override
    public void saveContext(SecurityContext context,
                            HttpServletRequest request,
                            HttpServletResponse response) {
        // 아무것도 저장하지 않음
        // → 매 요청마다 JWT 검증으로 SecurityContext를 새로 채움
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false;
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 세션에 저장된 SecurityContext 확인

```java
@GetMapping("/debug/session-context")
public Map<String, Object> sessionContext(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) return Map.of("session", "none");

    Object ctx = session.getAttribute(
        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_ATTR_NAME);

    if (ctx instanceof SecurityContext secCtx) {
        Authentication auth = secCtx.getAuthentication();
        return Map.of(
            "sessionId", session.getId(),
            "username", auth != null ? auth.getName() : "null",
            "authorities", auth != null ? auth.getAuthorities().toString() : "[]"
        );
    }
    return Map.of("context", "not found in session");
}
```

```bash
# 로그인 후 접근
curl -b "JSESSIONID=<session-id>" http://localhost:8080/debug/session-context
# → {"sessionId":"ABC123","username":"kim","authorities":"[ROLE_USER]"}
# → HttpSession에 SecurityContext가 직렬화되어 저장됨을 확인
```

### 실험 2: Stateless 설정 후 세션 미생성 확인

```java
// JWT 설정 (NullSecurityContextRepository)

@GetMapping("/debug/stateless-check")
public Map<String, Object> statelessCheck(HttpServletRequest request,
                                           Authentication auth) {
    HttpSession session = request.getSession(false);
    return Map.of(
        "sessionExists", session != null,
        "username", auth != null ? auth.getName() : "null"
    );
}
```

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/debug/stateless-check
# → {"sessionExists":false,"username":"kim"}
# → 인증은 됐지만 세션이 생성되지 않음
```

### 실험 3: requireExplicitSave 동작 차이

```java
// requireExplicitSave(false) — Spring Security 5.x 방식
// Filter 종료 시 자동으로 saveContext() 호출
// → 인증 변경 후 저장 코드 불필요

// requireExplicitSave(true) — Spring Security 6.x 기본
// saveContext()를 명시적으로 호출해야 저장됨
// → 개발자가 저장 시점 명확히 제어 가능

// 실험: 권한 변경 후 명시적 저장 없이 다음 요청 확인
@PostMapping("/change-role-test")
public String changeRole(HttpServletRequest req, HttpServletResponse res) {
    Authentication current = SecurityContextHolder.getContext().getAuthentication();
    List<GrantedAuthority> newAuth = new ArrayList<>(current.getAuthorities());
    newAuth.add(new SimpleGrantedAuthority("ROLE_VIP"));

    SecurityContext newCtx = SecurityContextHolder.createEmptyContext();
    newCtx.setAuthentication(
        new UsernamePasswordAuthenticationToken(
            current.getPrincipal(), null, newAuth));
    SecurityContextHolder.setContext(newCtx);

    // requireExplicitSave(true): 아래 코드 없으면 다음 요청에 ROLE_VIP 없음
    // securityContextRepository.saveContext(newCtx, req, res);

    return "Role changed (check next request)";
}
```

---

## 🔒 보안 체크리스트

```
세션 기반 애플리케이션
  ☐ SPRING_SECURITY_CONTEXT 세션 속성의 직렬화 가능 여부 확인
     (CustomUserDetails가 Serializable 구현 필수)
  ☐ 세션 타임아웃 설정 확인 (server.servlet.session.timeout)
  ☐ 로그아웃 시 세션 무효화 및 SecurityContext 정리 확인

JWT/Stateless 애플리케이션
  ☐ NullSecurityContextRepository 설정으로 세션 저장 완전 차단
  ☐ SessionCreationPolicy.STATELESS 병행 설정
  ☐ 불필요한 HttpSession 생성 여부 모니터링

Security 6.x 전환 시
  ☐ SecurityContextPersistenceFilter → SecurityContextHolderFilter 교체 확인
  ☐ requireExplicitSave(true) 환경에서 인증 후 saveContext() 호출 여부 검토
  ☐ 커스텀 인증 Filter에서 saveContext() 명시적 호출 추가
```

---

## 🤔 트레이드오프

```
HttpSessionSecurityContextRepository (세션 기반):
  장점  브라우저 기반 웹 앱에서 자연스러운 로그인 상태 유지
        추가 토큰 검증 없이 세션만으로 인증 상태 확인
  단점  서버에 상태가 생김 → 수평 확장 시 세션 공유 필요 (Redis 등)
        세션 하이재킹 공격 가능성 → HTTPS + Secure 쿠키 필수

NullSecurityContextRepository (Stateless):
  장점  서버가 완전히 Stateless → 수평 확장 용이
        세션 관련 보안 문제 없음
  단점  매 요청마다 토큰 검증 비용 (JWT 서명 검증 등)
        토큰 강제 만료가 어려움 (블랙리스트 필요)

Redis 기반 SecurityContextRepository (하이브리드):
  장점  세션을 서버 메모리 대신 Redis에 저장 → 수평 확장 가능
        세션 즉시 만료 가능 (Redis TTL 또는 key 삭제)
  단점  Redis 의존성 추가
        커스텀 SecurityContextRepository 구현 필요
```

---

## 📌 핵심 정리

```
SecurityContextPersistenceFilter (5.x, deprecated)
  요청마다 즉시 세션 로드 + 요청 종료 시 자동 저장
  → 불필요한 세션 I/O 발생

SecurityContextHolderFilter (6.x, 현재)
  지연 로딩 (Supplier 패턴) + 저장은 인증 Filter 책임
  → 실제로 필요할 때만 세션 I/O 발생

HttpSessionSecurityContextRepository
  SPRING_SECURITY_CONTEXT 세션 속성에 직렬화해서 저장
  익명 Authentication은 세션에 저장하지 않음

NullSecurityContextRepository
  저장 없음, 로드 시 항상 빈 SecurityContext 반환
  JWT Stateless 환경에서 반드시 설정

requireExplicitSave (6.x 기본값: true)
  개발자 또는 인증 Filter가 saveContext()를 명시적으로 호출해야 저장됨
  커스텀 인증 Filter 작성 시 saveContext() 호출 필수
```

---

## 🤔 생각해볼 문제

**Q1.** `HttpSessionSecurityContextRepository`는 익명 `Authentication`이 설정된 `SecurityContext`를 세션에 저장하지 않습니다. 만약 저장한다면 어떤 문제가 발생하는가? 악의적 사용자가 이를 어떻게 악용할 수 있는가?

**Q2.** Spring Session(Redis)을 사용해 세션을 서버 외부에 저장하는 환경에서 `HttpSessionSecurityContextRepository`는 동일하게 동작하는가? `HttpSession` 구현체가 바뀌어도 문제가 없는 이유는?

**Q3.** 멀티 탭 브라우저 환경에서 탭 A에서 로그아웃하고 탭 B에서 요청을 보내면 어떤 일이 발생하는가? `SecurityContextPersistenceFilter`(5.x)와 `SecurityContextHolderFilter`(6.x)에서 이 시나리오가 다르게 처리되는가?

> 💡 **해설**
>
> **Q1.** 익명 `Authentication`을 세션에 저장하면 브라우저에서 처음 요청을 보낸 순간 서버에 `HttpSession`이 생성되고 `JSESSIONID` 쿠키가 발급됩니다. 공격자는 이를 악용해 세션 고정 공격(Session Fixation)을 시도할 수 있습니다. 공격자가 특정 `JSESSIONID` 값으로 익명 세션을 먼저 생성한 뒤, 피해자가 그 세션 ID로 로그인하도록 유도하면 공격자가 피해자의 인증된 세션을 탈취할 수 있습니다. 또한 수많은 익명 요청이 각각 세션을 생성하면 서버 메모리를 고갈시키는 DoS 공격으로도 활용될 수 있습니다.
>
> **Q2.** Spring Session은 `HttpSession` 인터페이스를 구현하는 프록시 객체(`HttpSessionWrapper`)를 제공하고, 실제 저장은 Redis에 위임합니다. `HttpSessionSecurityContextRepository`는 `HttpSession.getAttribute()` / `setAttribute()` 메서드만 사용하므로 `HttpSession` 구현체가 Redis 기반으로 바뀌어도 코드 변경 없이 동일하게 동작합니다. Spring Session이 `HttpSession` 인터페이스를 통해 투명하게 Redis와 연동하기 때문입니다. 이것이 인터페이스 기반 설계의 장점입니다.
>
> **Q3.** 로그아웃 처리 시 `LogoutFilter`는 `LogoutHandler` 목록을 실행하는데, `SecurityContextLogoutHandler`가 `session.invalidate()`를 호출해 세션을 무효화합니다. 탭 B에서 다음 요청을 보낼 때 `Cookie: JSESSIONID=<무효화된 ID>`가 전송됩니다. 두 Filter 모두 `request.getSession(false)`로 세션을 조회하는데, 무효화된 세션 ID에 해당하는 세션이 없으므로 `null`이 반환됩니다. 결과적으로 빈 `SecurityContext`가 로드되고, `AuthorizationFilter`에서 `AnonymousAuthenticationToken`으로 처리되어 인증이 필요한 리소스에 접근 시 로그인 페이지로 리다이렉트됩니다. 이 동작은 두 버전에서 동일합니다.

---

<div align="center">

**[← 이전: GrantedAuthority vs Role 차이](./06-granted-authority-vs-role.md)** | **[홈으로 🏠](../README.md)** | **[Chapter 2로 이동: AuthenticationManager vs ProviderManager ➡️](../authentication-process/01-authentication-manager-provider-manager.md)**

</div>
