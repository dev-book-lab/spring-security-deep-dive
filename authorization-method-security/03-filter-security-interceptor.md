# FilterSecurityInterceptor 내부 구조 — URL 기반 접근 제어의 전 과정

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `FilterSecurityInterceptor`(5.x)와 `AuthorizationFilter`(6.x)의 관계와 차이는?
- `SecurityMetadataSource`는 어떻게 요청 URL을 `ConfigAttribute` 목록으로 변환하는가?
- `AbstractSecurityInterceptor`가 인증 상태를 재확인하는 시나리오는 무엇인가?
- `ExceptionTranslationFilter`와 `AuthorizationFilter`가 협력하는 방식은?
- `authorizeHttpRequests()`와 구버전 `authorizeRequests()`의 내부 구현 차이는?
- `RequestMatcher`가 URL 매칭에서 순서가 중요한 이유는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### URL 기반 접근 제어가 Filter Chain 마지막에 위치하는 이유

```
Filter Chain 실행 순서 (관련 부분):

  SecurityContextHolderFilter (100)
    → 요청마다 SecurityContext 복원

  UsernamePasswordAuthenticationFilter (1900)
    → 폼 로그인 처리 (POST /login만)

  ExceptionTranslationFilter (3500)
    → AccessDeniedException → 401/403 응답 처리
    → AuthenticationException → 로그인 페이지 리다이렉트

  AuthorizationFilter (3600) ← 여기서 URL 기반 접근 제어
    → 모든 요청에 대해 권한 검사
    → DENY → AccessDeniedException throw
            → ExceptionTranslationFilter가 처리

설계 원칙:
  인증 필터들이 먼저 SecurityContext를 채운다
  → 마지막에 AuthorizationFilter가 SecurityContext를 읽어 권한 판단
  ExceptionTranslationFilter는 AuthorizationFilter 바로 앞에 위치
  → AuthorizationFilter가 던진 예외를 처리하기 위해
```

---

## 😱 흔한 보안 실수

### Before: requestMatchers 순서를 잘못 지정

```java
// ❌ 문제: 넓은 패턴이 좁은 패턴보다 먼저 오면 좁은 패턴에 도달하지 못함
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").authenticated()  // /admin/public도 잡힘
    .requestMatchers("/admin/public/**").permitAll() // 이 규칙은 절대 실행 안 됨
    .anyRequest().authenticated()
);
// → /admin/public/info 요청 → 첫 번째 규칙 매칭 → authenticated 검사
// → 로그인 안 된 경우 401 (두 번째 규칙은 실행 안 됨)

// ✅ 좁은 패턴을 먼저, 넓은 패턴을 나중에
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/public/**").permitAll() // 먼저 — 더 구체적
    .requestMatchers("/admin/**").hasRole("ADMIN")   // 나중에 — 더 넓음
    .anyRequest().authenticated()
);
```

### Before: authorizeRequests()와 authorizeHttpRequests() 혼용

```java
// ❌ 혼용: 같은 SecurityFilterChain에 두 가지 사용
http
    .authorizeRequests(auth -> auth           // 구버전 (deprecated)
        .antMatchers("/old/**").permitAll()
    )
    .authorizeHttpRequests(auth -> auth        // 신버전
        .requestMatchers("/new/**").permitAll()
    );
// → FilterSecurityInterceptor(구버전)와 AuthorizationFilter(신버전)가 모두 등록됨
// → 요청이 두 번 권한 검사를 받음 → 예측 불가능한 동작

// ✅ 신버전으로 통일
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/old/**", "/new/**").permitAll()
    .anyRequest().authenticated()
);
```

---

## ✨ 올바른 보안 구현

### 현대적인 URL 기반 접근 제어 (Spring Security 6.x)

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        // 정적 리소스 — 인증 불필요
        .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
        // 공개 API
        .requestMatchers(HttpMethod.GET, "/api/posts/**").permitAll()
        .requestMatchers("/api/auth/**").permitAll()
        // 관리자 전용
        .requestMatchers("/admin/**").hasRole("ADMIN")
        // 사용자 리소스 (소유권은 Method Security에서)
        .requestMatchers("/api/users/**").hasRole("USER")
        // 나머지는 인증 필요
        .anyRequest().authenticated()
    );
    return http.build();
}
```

---

## 🔬 내부 동작 원리

### 1. AuthorizationFilter — Spring Security 6.x 기본 URL 접근 제어

```java
// AuthorizationFilter.java (spring-security 6.x)
public class AuthorizationFilter extends GenericFilterBean {

    private final AuthorizationManager<HttpServletRequest> authorizationManager;
    private AuthorizationEventPublisher eventPublisher = ...;
    private boolean observeOncePerRequest = false; // 기본: 매 요청마다 실행

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        // ① once-per-request 처리 (forward, include 시 중복 방지)
        if (this.observeOncePerRequest && isApplied(req)) {
            chain.doFilter(request, response);
            return;
        }

        // ② AuthorizationManager로 권한 검사 위임
        // RequestMatcherDelegatingAuthorizationManager가 RequestMatcher로 매칭
        AuthorizationDecision decision = this.authorizationManager.check(
            this::getAuthentication,  // SecurityContextHolder에서 지연 조회
            req
        );

        // ③ 이벤트 발행 (감사 로그용)
        this.eventPublisher.publishAuthorizationEvent(
            this::getAuthentication, req, decision);

        // ④ 거부 → AccessDeniedException throw
        if (decision != null && !decision.isGranted()) {
            throw new AccessDeniedException("Access Denied");
        }

        chain.doFilter(request, response);
    }

    private Authentication getAuthentication() {
        // 지연 로딩 — 권한 검사가 필요할 때만 SecurityContextHolder 접근
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new AuthenticationCredentialsNotFoundException("...");
        }
        return auth;
    }
}
```

### 2. RequestMatcherDelegatingAuthorizationManager — URL 매칭과 AuthorizationManager 선택

```java
// RequestMatcherDelegatingAuthorizationManager.java
public final class RequestMatcherDelegatingAuthorizationManager
        implements AuthorizationManager<HttpServletRequest> {

    // (RequestMatcher, AuthorizationManager) 쌍의 순서 있는 리스트
    private final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            HttpServletRequest request) {

        // 등록된 RequestMatcher를 순서대로 검사
        for (RequestMatcherEntry<...> mapping : this.mappings) {

            RequestMatcher matcher = mapping.getRequestMatcher();
            MatchResult matchResult = matcher.matcher(request);

            if (!matchResult.isMatch()) {
                continue; // 매칭 안 됨 → 다음 규칙
            }

            // 매칭된 AuthorizationManager로 위임
            AuthorizationManager<RequestAuthorizationContext> manager =
                mapping.getEntry();

            return manager.check(authentication,
                new RequestAuthorizationContext(request, matchResult.getVariables()));
        }

        // 어떤 규칙도 매칭 안 됨
        // → anyRequest()를 설정하지 않으면 여기서 null 반환 → 허용
        return null;
    }
}

// 각 AuthorizationManager 구현체:
// permitAll()       → PermitAllAuthorizationManager (항상 granted)
// denyAll()         → DenyAllAuthorizationManager (항상 denied)
// authenticated()   → AuthenticatedAuthorizationManager (isAuthenticated 검사)
// hasRole("ADMIN")  → AuthorityAuthorizationManager ("ROLE_ADMIN" 검사)
// hasAuthority("X") → AuthorityAuthorizationManager ("X" 검사)
// access(expr)      → WebExpressionAuthorizationManager (SpEL 평가)
```

### 3. SecurityMetadataSource — 구버전 (FilterSecurityInterceptor) 방식

```java
// FilterSecurityInterceptor.java (5.x, deprecated)
// AbstractSecurityInterceptor를 상속하는 구버전 방식
public class FilterSecurityInterceptor
        extends AbstractSecurityInterceptor implements Filter {

    private FilterInvocationSecurityMetadataSource securityMetadataSource;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        FilterInvocation filterInvocation =
            new FilterInvocation(request, response, chain);

        // AbstractSecurityInterceptor.beforeInvocation() 호출
        InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
        // → SecurityMetadataSource에서 ConfigAttribute 로드
        // → AccessDecisionManager로 권한 결정

        try {
            filterInvocation.getChain().doFilter(
                filterInvocation.getRequest(),
                filterInvocation.getResponse());
        } finally {
            super.finallyInvocation(token);
        }
        super.afterInvocation(token, null);
    }
}

// AbstractSecurityInterceptor.beforeInvocation() 핵심 로직:
protected InterceptorStatusToken beforeInvocation(Object object) {

    // ① SecurityMetadataSource에서 ConfigAttribute 로드
    // URL → ConfigAttribute 변환
    Collection<ConfigAttribute> attributes =
        this.obtainSecurityMetadataSource().getAttributes(object);

    if (attributes == null || attributes.isEmpty()) {
        return null; // 보호 대상 아님 → 통과
    }

    // ② Authentication 재검증 (필요 시)
    Authentication authenticated = authenticateIfRequired();

    // ③ AccessDecisionManager로 최종 권한 결정
    attemptAuthorization(object, attributes, authenticated);

    return new InterceptorStatusToken(SecurityContextHolder.getContext(),
        false, attributes, object);
}
```

### 4. ExceptionTranslationFilter와 AuthorizationFilter 협력

```java
// ExceptionTranslationFilter.java
// AuthorizationFilter 바로 앞(순서 3500)에서 예외를 처리하는 방패

public class ExceptionTranslationFilter extends GenericFilterBean
        implements MessageSourceAware {

    private final AuthenticationEntryPoint authenticationEntryPoint;
    private AccessDeniedHandler accessDeniedHandler;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        try {
            // 다음 필터(AuthorizationFilter 등) 실행
            chain.doFilter(request, response);

        } catch (AccessDeniedException ex) {
            // AuthorizationFilter가 던진 AccessDeniedException 처리
            if (authenticationTrustResolver.isAnonymous(getAuthentication())) {
                // 익명 사용자: 로그인 페이지로 리다이렉트
                // SavedRequest에 현재 요청 저장 (로그인 후 복원)
                sendStartAuthentication(request, response, chain,
                    new InsufficientAuthenticationException("..."));
            } else {
                // 인증된 사용자인데 권한 없음: 403 응답
                accessDeniedHandler.handle(request, response, ex);
            }

        } catch (AuthenticationException ex) {
            // 인증 관련 예외: 로그인 페이지로 리다이렉트
            sendStartAuthentication(request, response, chain, ex);
        }
    }

    private void sendStartAuthentication(HttpServletRequest request, ...) {
        // 현재 요청을 HttpSessionRequestCache에 저장
        // → 로그인 성공 후 SavedRequestAwareAuthenticationSuccessHandler가 복원
        requestCache.saveRequest(request, response);
        // → 로그인 페이지로 리다이렉트
        authenticationEntryPoint.commence(request, response, authException);
    }
}
```

### 5. authorizeRequests() vs authorizeHttpRequests() 내부 차이

```
구버전 authorizeRequests():
  등록하는 Filter: FilterSecurityInterceptor (순서 MAX_INT)
  방식: SecurityMetadataSource + AccessDecisionManager + Voter
  matcher: antMatchers() (AntPathRequestMatcher)
  SpEL: WebSecurityExpressionHandler

신버전 authorizeHttpRequests():
  등록하는 Filter: AuthorizationFilter (순서 3600)
  방식: RequestMatcherDelegatingAuthorizationManager
  matcher: requestMatchers() (MvcRequestMatcher, AntPathRequestMatcher 등)
  SpEL: WebExpressionAuthorizationManager (access() 사용 시)

핵심 차이:
  구버전: Voter 기반 투표 방식 (AffirmativeBased, ConsensusBased)
  신버전: AuthorizationManager 방식 (타입 안전, 함수형)
  신버전: 지연 Authentication 로드 (Supplier<Authentication>)
         → permitAll()에서 SecurityContextHolder 접근 안 함 (성능 향상)
```

### 6. 전체 요청 흐름 ASCII 다이어그램

```
GET /admin/users (익명 사용자)
│
▼ SecurityContextHolderFilter
│    HttpSession에 SecurityContext 없음 → 빈 컨텍스트 생성
│    Authentication = AnonymousAuthenticationToken
│
▼ ExceptionTranslationFilter (try 블록 시작)
│
▼ AuthorizationFilter
│    authorizationManager.check(authentication, request)
│    → RequestMatcherDelegatingAuthorizationManager
│       requestMatchers("/admin/**").hasRole("ADMIN") 매칭
│       → AuthorityAuthorizationManager.check()
│          authentication.getAuthorities()에 "ROLE_ADMIN" 없음
│          → AuthorizationDecision(false)
│    → 거부 → AccessDeniedException throw
│
▼ ExceptionTranslationFilter (catch AccessDeniedException)
│    isAnonymous(authentication) → true
│    → requestCache.saveRequest("/admin/users")
│    → authenticationEntryPoint.commence()
│       → 302 Redirect → /login
│
GET /admin/users (인증된 ROLE_USER 사용자)
│
▼ AuthorizationFilter
│    AuthorityAuthorizationManager.check()
│    → "ROLE_ADMIN" 없음 → 거부
│
▼ ExceptionTranslationFilter (catch AccessDeniedException)
│    isAnonymous → false
│    → accessDeniedHandler.handle() → 403 Forbidden
```

---

## 💻 실험으로 확인하기

### 실험 1: RequestMatcher 순서 영향 확인

```java
// 순서가 중요함을 보여주는 테스트
@Test
@WithAnonymousUser
void requestMatcher_order_matters() throws Exception {
    // 좁은 패턴이 먼저 → /public/info 허용
    mockMvc.perform(get("/admin/public/info"))
        .andExpect(status().isOk());    // permitAll() 적용

    // 넓은 패턴이 먼저인 경우:
    // 같은 요청이 401로 응답됨
}
```

### 실험 2: AuthorizationFilter 지연 Authentication 로드 확인

```java
// permitAll() 규칙에서 DB 조회 없음 확인
// (SecurityContextHolder 접근 자체를 안 함)
@Test
void permitAll_doesNotLoadAuthentication() {
    // /public/** 요청은 AuthorizationFilter에서
    // authentication Supplier를 호출하지 않음
    // → DB 세션 조회 발생 안 함
    // → 성능 향상
}
```

### 실험 3: 접근 제어 이벤트 리스닝

```java
@Component
public class AuthorizationEventListener {

    @EventListener
    public void onDenied(AuthorizationDeniedEvent event) {
        log.warn("Access denied: request={}, user={}",
            ((HttpServletRequest)event.getSource()).getRequestURI(),
            event.getAuthentication().get().getName());
    }

    @EventListener
    public void onGranted(AuthorizationGrantedEvent event) {
        log.debug("Access granted: request={}",
            ((HttpServletRequest)event.getSource()).getRequestURI());
    }
}
```

### 실험 4: TRACE 로그로 매칭 과정 관찰

```yaml
logging:
  level:
    org.springframework.security.web.access: TRACE
```

```
# GET /admin/dashboard (ROLE_USER 로그인 상태)
TRACE RequestMatcherDelegatingAuthorizationManager - Checking authorization on ...
TRACE AntPathRequestMatcher - Checking match of request : '/admin/dashboard'; against '/css/**'  → no match
TRACE AntPathRequestMatcher - Checking match of request : '/admin/dashboard'; against '/admin/**' → match
DEBUG AuthorityAuthorizationManager - Checking authority: ROLE_ADMIN
DEBUG AuthorityAuthorizationManager - Denied
```

---

## 🔒 보안 체크리스트

```
RequestMatcher 순서
  ☐ 구체적인(좁은) 패턴을 먼저 등록
  ☐ anyRequest()는 반드시 마지막에 등록
  ☐ 인증이 필요 없는 URL만 permitAll() 처리
  ☐ GET /api/resource와 POST /api/resource를 다르게 처리 시
     HttpMethod 파라미터 명시: requestMatchers(HttpMethod.GET, "/api/resource")

신버전 사용
  ☐ authorizeRequests() 대신 authorizeHttpRequests() 사용 (6.x)
  ☐ antMatchers() 대신 requestMatchers() 사용
  ☐ 두 가지 혼용 금지 (FilterSecurityInterceptor + AuthorizationFilter 중복)

ExceptionTranslationFilter
  ☐ AccessDeniedHandler 커스터마이징 (API: JSON 403, 웹: 커스텀 에러 페이지)
  ☐ AuthenticationEntryPoint 커스터마이징 (API: JSON 401, 웹: 로그인 리다이렉트)
```

---

## 🤔 트레이드오프

```
URL 기반 접근 제어 vs Method Security:
  URL 기반:
    장점  Spring Security 설정 한 곳에 집중 → 전체 보안 정책 파악 용이
          Controller 코드에 보안 어노테이션 없어도 됨
    단점  URL 패턴으로 표현할 수 없는 세밀한 권한(소유권 등) 불가
          URL 변경 시 보안 설정도 변경 필요

  Method Security (@PreAuthorize):
    장점  도메인 객체 수준의 세밀한 권한 제어 가능
          코드와 보안 정책이 함께 → 누락 위험 감소
    단점  보안 정책이 여러 클래스에 분산 → 전체 파악 어려움

권장 패턴:
  URL 기반: 1차 방어선 (인증 여부, 역할 수준)
  Method Security: 2차 방어선 (소유권, 세밀한 조건)
  → Defense in Depth
```

---

## 📌 핵심 정리

```
AuthorizationFilter (6.x 기본)
  요청 → RequestMatcherDelegatingAuthorizationManager
  → RequestMatcher 순서대로 매칭
  → 해당 AuthorizationManager.check()
  → 거부 시 AccessDeniedException throw

ExceptionTranslationFilter와 협력
  익명 → 로그인 페이지 리다이렉트 + SavedRequest 저장
  인증됨 + 권한 없음 → 403 Forbidden

authorizeHttpRequests() (신버전) 차이점
  AuthorizationFilter 사용 (구버전: FilterSecurityInterceptor)
  Supplier<Authentication> 지연 로드 → permitAll() 성능 향상
  AuthorizationManager 방식 (구버전: AccessDecisionManager + Voter)

RequestMatcher 순서 원칙
  좁은 패턴 먼저 → 넓은 패턴 나중 → anyRequest() 마지막
```

---

## 🤔 생각해볼 문제

**Q1.** `requestMatchers("/api/**").permitAll()`로 설정한 URL에서도 `SecurityContextHolderFilter`는 실행됩니다. 그런데 `AuthorizationFilter`는 `permitAll()`인 URL에서 `SecurityContextHolder.getContext().getAuthentication()`을 호출하지 않습니다. 이것이 성능에 어떤 영향을 주는가?

**Q2.** 같은 URL 패턴에 대해 `requestMatchers("/api/admin/**").hasRole("ADMIN")`과 `requestMatchers("/api/admin/**").hasRole("SUPER_ADMIN")`을 순서대로 등록하면 어떻게 동작하는가?

**Q3.** `authorizeHttpRequests()`에서 `.anyRequest().denyAll()`을 마지막에 추가하는 것과 `.anyRequest().authenticated()`를 추가하는 것의 보안 관점에서 차이는 무엇이며, 각각 어떤 상황에 적합한가?

> 💡 **해설**
>
> **Q1.** `AuthorizationFilter`는 `Supplier<Authentication>`을 사용해 지연 로드합니다. `RequestMatcherDelegatingAuthorizationManager`가 `permitAll()`에 매핑된 `PermitAllAuthorizationManager`를 선택하면, 이 구현체는 Supplier를 호출하지 않고 항상 `AuthorizationDecision(true)`를 반환합니다. 즉, `permitAll()` URL에서는 `SecurityContextHolder.getContext()` 접근이 일어나지 않아 HttpSession을 열거나 읽는 I/O가 발생하지 않습니다. 구버전 `FilterSecurityInterceptor`는 매 요청마다 Authentication을 조회했으므로 신버전 대비 정적 리소스 요청 처리 비용이 절감됩니다.
>
> **Q2.** `RequestMatcherDelegatingAuthorizationManager`는 등록 순서대로 첫 번째 매칭되는 규칙만 적용합니다. 따라서 `/api/admin/**`에 첫 번째로 매칭되는 `hasRole("ADMIN")` 규칙만 적용되고 두 번째 규칙은 실행되지 않습니다. 두 조건을 AND로 적용하려면 `access("hasRole('ADMIN') and hasRole('SUPER_ADMIN')")`처럼 단일 규칙으로 표현하거나, 커스텀 `AuthorizationManager`를 구현해야 합니다.
>
> **Q3.** `.anyRequest().authenticated()`는 인증된 사용자라면 명시적으로 허용하지 않은 URL도 접근 가능합니다. `.anyRequest().denyAll()`은 명시적으로 허용하지 않은 모든 URL을 차단합니다. 보안 관점에서 `denyAll()`이 더 안전한 화이트리스트 방식으로, 새 URL이 추가됐을 때 접근 규칙을 잊어도 자동으로 차단됩니다. 반면 `authenticated()`는 새 Controller 메서드 추가 시 의도치 않게 허용될 수 있습니다. 고보안 환경(금융, 의료)에서는 `denyAll()`을 기본으로 설정하고 필요한 URL만 명시적으로 허용하는 전략이 권장됩니다.

---

<div align="center">

**[← 이전: Method Security 동작 원리 (AOP Proxy)](./02-method-security-aop.md)** | **[홈으로 🏠](../README.md)** | **[다음: AccessDecisionManager와 Voter 체인 ➡️](./04-access-decision-manager.md)**

</div>
