# Security Filter 15개 완전 정복 — 실행 순서·역할·생략 조건

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `FilterChainProxy`가 실행하는 Filter의 정렬 순서는 무엇이 결정하는가?
- `ExceptionTranslationFilter`는 왜 `AuthorizationFilter` 바로 앞에 위치해야 하는가?
- `AnonymousAuthenticationFilter`가 없으면 인증되지 않은 요청이 `AuthorizationFilter`에 도달했을 때 어떤 일이 발생하는가?
- JWT 환경에서 비활성화해야 하는 Filter는 무엇이고 그 이유는?
- `UsernamePasswordAuthenticationFilter`가 모든 요청에서 실행되는가, 특정 요청에만 실행되는가?
- `DisableEncodeUrlFilter`는 어떤 보안 취약점을 방어하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 인증·인가는 여러 독립적인 관심사로 구성된다

```
보안 처리를 단일 Filter로 구현한다면:
  class MegaSecurityFilter implements Filter {
      doFilter(request, response, chain) {
          // 1. URL에 세션 ID 인코딩 방지
          // 2. SecurityContext 복원
          // 3. CORS 처리
          // 4. CSRF 검증
          // 5. 로그아웃 처리
          // 6. 폼 로그인 처리
          // 7. JWT 검증
          // 8. Basic Auth 처리
          // 9. 익명 사용자 설정
          // 10. 세션 관리
          // 11. 예외 처리
          // 12. 권한 검사
          // ... 모든 것이 한 곳에
      }
  }
  → 각 관심사를 독립적으로 교체·비활성화 불가
  → 테스트 단위가 너무 큼

해결: 각 관심사를 독립된 Filter로 분리
  → 특정 Filter만 비활성화 가능 (JWT 환경에서 FormLogin Filter 제거 등)
  → 순서를 정밀하게 제어
  → 각 Filter를 독립적으로 테스트
```

---

## 😱 흔한 보안 실수

### Before: Filter 순서를 임의로 바꾸면 동일하게 동작한다고 착각

```java
// ❌ 위험: ExceptionTranslationFilter를 AuthorizationFilter 뒤에 배치
// (예시를 위한 극단적 설정 — 실제로는 직접 순서 변경 불가)

// ExceptionTranslationFilter는 AuthorizationFilter 바로 앞에 있어야 함
// 이유: AuthorizationFilter가 던진 AccessDeniedException을
//       ExceptionTranslationFilter가 catch해서 적절한 응답으로 변환하기 때문

// ExceptionTranslationFilter가 뒤에 있으면:
// AccessDeniedException이 ExceptionTranslationFilter를 거치지 않고
// Servlet Container까지 전파 → 500 에러 또는 기본 에러 페이지 노출
```

### Before: JWT 환경에서 세션 관련 Filter를 그냥 두면 성능에만 영향을 준다

```java
// ❌ 잘못된 이해:
// "Stateless 설정을 했으니 세션 Filter가 있어도 무해하다"

// ✅ 실제 문제:
// SessionManagementFilter: 인증 시 세션 고정 방어를 위해 세션 생성 시도
//   → STATELESS 설정 시 세션을 만들지 않지만 Filter 자체는 실행됨 (낭비)
// SecurityContextPersistenceFilter (구버전): 매 요청마다 HttpSession 조회
//   → "JSESSIONID" 쿠키 없어도 세션 저장소를 확인하는 I/O 발생

// ✅ JWT 환경 최소 구성:
http
    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .csrf(csrf -> csrf.disable())
    .formLogin(AbstractHttpConfigurer::disable)
    .httpBasic(AbstractHttpConfigurer::disable);
// → UsernamePasswordAuthenticationFilter, DefaultLoginPageGeneratingFilter
//   BasicAuthenticationFilter 등이 체인에서 제거됨
```

---

## ✨ 올바른 보안 구현

### 각 Filter의 역할과 비활성화 방법

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // 1. DisableEncodeUrlFilter → 항상 활성화 (비활성화 API 없음)
        // 2. WebAsyncManagerIntegrationFilter → 항상 활성화
        // 3. SecurityContextHolderFilter → 항상 활성화

        // 4. HeaderWriterFilter → 비활성화 시:
        .headers(headers -> headers.disable())

        // 5. CorsFilter → 비활성화 시:
        .cors(cors -> cors.disable())
        // 또는 활성화:
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))

        // 6. CsrfFilter → JWT/Stateless에서 비활성화:
        .csrf(csrf -> csrf.disable())

        // 7. LogoutFilter → 비활성화 시:
        .logout(logout -> logout.disable())

        // 8. UsernamePasswordAuthenticationFilter → 비활성화 시:
        .formLogin(AbstractHttpConfigurer::disable)

        // 9. DefaultLoginPageGeneratingFilter → formLogin 비활성화 시 자동 제거
        // 10. DefaultLogoutPageGeneratingFilter → logout 비활성화 시 자동 제거

        // 11. BasicAuthenticationFilter → 비활성화 시:
        .httpBasic(AbstractHttpConfigurer::disable)

        // 12. RequestCacheAwareFilter → 커스텀 RequestCache:
        .requestCache(cache -> cache.requestCache(new NullRequestCache()))

        // 13. SecurityContextHolderAwareRequestFilter → 항상 활성화
        // 14. AnonymousAuthenticationFilter → 비활성화 시:
        .anonymous(AbstractHttpConfigurer::disable)

        // 15. SessionManagementFilter → STATELESS 설정 시 기능 비활성화:
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

        // 16. ExceptionTranslationFilter → 항상 활성화 (필수)
        // 17. AuthorizationFilter → 항상 활성화 (필수)
    ;
    return http.build();
}
```

---

## 🔬 내부 동작 원리

### 1. FilterOrderRegistration — Filter 순서 결정 메커니즘

```java
// FilterOrderRegistration.java (Spring Security 내부)
// 각 Filter 클래스에 정수 순서 값을 부여
// 간격을 100씩 두어 커스텀 Filter를 사이에 끼워 넣을 수 있도록 설계

final class FilterOrderRegistration {
    FilterOrderRegistration() {
        // 순서값 100부터 시작, 간격 100
        int order = 100;
        put(DisableEncodeUrlFilter.class, order);               // 100
        put(ForceEagerSessionCreationFilter.class, order += 100); // 200
        put(ChannelProcessingFilter.class, order += 100);       // 300
        order += 100; // 400 gap
        put(WebAsyncManagerIntegrationFilter.class, order += 100); // 500
        put(SecurityContextHolderFilter.class, order += 100);   // 600
        put(SecurityContextPersistenceFilter.class, order += 100); // 700 (deprecated)
        put(HeaderWriterFilter.class, order += 100);            // 800
        put(CorsFilter.class, order += 100);                    // 900
        put(CsrfFilter.class, order += 100);                    // 1000
        put(LogoutFilter.class, order += 100);                  // 1100
        put(OAuth2AuthorizationRequestRedirectFilter.class, order += 100); // 1200
        put(Saml2WebSsoAuthenticationRequestFilter.class, order += 100);   // 1300
        put(X509AuthenticationFilter.class, order += 100);      // 1400
        put(AbstractPreAuthenticatedProcessingFilter.class, order += 100); // 1500
        put(CasAuthenticationFilter.class, order += 100);       // 1600
        put(OAuth2LoginAuthenticationFilter.class, order += 100); // 1700
        put(Saml2WebSsoAuthenticationFilter.class, order += 100); // 1800
        put(UsernamePasswordAuthenticationFilter.class, order += 100); // 1900
        put(OpenIDAuthenticationFilter.class, order += 100);    // 2000
        put(DefaultLoginPageGeneratingFilter.class, order += 100); // 2100
        put(DefaultLogoutPageGeneratingFilter.class, order += 100); // 2200
        put(ConcurrentSessionFilter.class, order += 100);       // 2300
        put(DigestAuthenticationFilter.class, order += 100);    // 2400
        put(BearerTokenAuthenticationFilter.class, order += 100); // 2500
        put(BasicAuthenticationFilter.class, order += 100);     // 2600
        put(RequestCacheAwareFilter.class, order += 100);       // 2700
        put(SecurityContextHolderAwareRequestFilter.class, order += 100); // 2800
        put(JaasApiIntegrationFilter.class, order += 100);      // 2900
        put(RememberMeAuthenticationFilter.class, order += 100); // 3000
        put(AnonymousAuthenticationFilter.class, order += 100); // 3100
        put(OAuth2AuthorizationCodeGrantFilter.class, order += 100); // 3200
        put(SessionManagementFilter.class, order += 100);       // 3300
        put(ExceptionTranslationFilter.class, order += 100);    // 3400
        put(FilterSecurityInterceptor.class, order += 100);     // 3500 (deprecated)
        put(AuthorizationFilter.class, order += 100);           // 3600
        put(SwitchUserFilter.class, order += 100);              // 3700
    }
}
```

### 2. 각 Filter의 역할 상세

```
실행 순서  Filter 이름                         역할 요약
────────  ─────────────────────────────────  ────────────────────────────────────────
100       DisableEncodeUrlFilter             URL에 jsessionid 파라미터 인코딩 방지
                                             (세션 하이재킹 방어)
                                             response.encodeURL()을 무력화하는
                                             HttpServletResponseWrapper 씌움

500       WebAsyncManagerIntegrationFilter   SecurityContext를 비동기 처리 (DeferredResult,
                                             Callable)로 전파하는 WebAsyncManager 통합

600       SecurityContextHolderFilter        SecurityContext 생명주기 관리
                                             요청 시작: SecurityContextRepository에서 로드
                                             요청 종료: clear + 저장

800       HeaderWriterFilter                 보안 응답 헤더 자동 추가
                                             X-Content-Type-Options: nosniff
                                             X-Frame-Options: DENY
                                             X-XSS-Protection: 0
                                             Cache-Control: no-cache, no-store
                                             Content-Security-Policy (설정 시)

900       CorsFilter                         CORS Preflight(OPTIONS) 요청 처리
                                             인증 Filter 전에 실행되어야
                                             OPTIONS 요청이 401을 받지 않음

1000      CsrfFilter                         CSRF 토큰 검증
                                             GET/HEAD/OPTIONS/TRACE는 통과
                                             POST/PUT/DELETE/PATCH는 토큰 검증

1100      LogoutFilter                       /logout POST 요청 감지
                                             SecurityContext 정리 + 세션 무효화
                                             LogoutSuccessHandler 호출

1700      OAuth2LoginAuthenticationFilter   OAuth2 Authorization Code 처리
                                             /login/oauth2/code/* 콜백 처리

1900      UsernamePasswordAuthenticationFilter
                                             /login POST 요청에만 실행
                                             (AntPathRequestMatcher("/login", "POST"))
                                             폼 파라미터에서 username/password 추출
                                             → AuthenticationManager 위임

2100      DefaultLoginPageGeneratingFilter  커스텀 loginPage 없을 때
                                             /login GET 요청에 기본 로그인 폼 HTML 제공

2500      BearerTokenAuthenticationFilter   OAuth2 Resource Server 설정 시 활성화
                                             Authorization: Bearer 헤더에서 토큰 추출
                                             → JwtDecoder 또는 OpaqueTokenIntrospector 검증

2600      BasicAuthenticationFilter         Authorization: Basic 헤더 처리
                                             Base64 디코딩 → username:password 추출
                                             → AuthenticationManager 위임

2700      RequestCacheAwareFilter           인증 전 접근하려 했던 URL을 SavedRequest로 저장
                                             인증 성공 후 원래 URL로 리다이렉트 지원

2800      SecurityContextHolderAwareRequestFilter
                                             request.isUserInRole() 등 서블릿 API가
                                             SecurityContext와 연동되도록 request 래핑

3000      RememberMeAuthenticationFilter   remember-me 쿠키가 있고 SecurityContext가
                                             비어 있을 때 자동 인증

3100      AnonymousAuthenticationFilter    SecurityContext가 비어 있으면
                                             AnonymousAuthenticationToken 삽입
                                             → AuthorizationFilter에서 "인증됨" 상태로 처리

3300      SessionManagementFilter          세션 고정 방어 (인증 성공 후 세션 교체)
                                             동시 접속 제한 확인

3400      ExceptionTranslationFilter       try { chain.doFilter() } catch {
                                               AuthenticationException → 401 또는 로그인으로 리다이렉트
                                               AccessDeniedException   → 403 또는 로그인으로 리다이렉트
                                             }
                                             뒤에 오는 AuthorizationFilter의 예외를 catch

3600      AuthorizationFilter              최종 권한 검사
                                             AuthorizationManager.check() 호출
                                             → ACCESS_DENIED → AccessDeniedException
```

### 3. ExceptionTranslationFilter와 AuthorizationFilter의 협력 구조

```java
// ExceptionTranslationFilter.java — 핵심 동작
public class ExceptionTranslationFilter extends GenericFilterBean {

    private AuthenticationEntryPoint authenticationEntryPoint;
    private AccessDeniedHandler accessDeniedHandler;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        try {
            // 뒤에 오는 모든 Filter (특히 AuthorizationFilter)를 감싸서 실행
            chain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            // 인증이 안 된 상태에서 보호 리소스 접근
            // → 로그인 페이지로 리다이렉트 또는 401 JSON 응답
            handleAuthenticationException(request, response, chain, ex);
        } catch (AccessDeniedException ex) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (authenticationTrustResolver.isAnonymous(auth)
                    || authenticationTrustResolver.isRememberMe(auth)) {
                // 익명 사용자나 Remember-Me 사용자 → 인증 필요
                handleAuthenticationException(request, response, chain,
                    new InsufficientAuthenticationException("..."));
            } else {
                // 인증은 됐지만 권한 없음 → 403
                handleAccessDeniedException(request, response, ex);
            }
        }
    }
}

// AuthorizationFilter.java — 최종 권한 검사
public class AuthorizationFilter extends GenericFilterBean {

    private AuthorizationManager<HttpServletRequest> authorizationManager;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws ServletException, IOException {

        // AuthorizationManager에게 현재 인증 정보와 요청 정보를 전달해 권한 검사
        AuthorizationDecision decision = this.authorizationManager.check(
            SecurityContextHolder::getContext, // Supplier<Authentication>
            (HttpServletRequest) request
        );

        if (decision != null && !decision.isGranted()) {
            // AccessDeniedException을 throw → ExceptionTranslationFilter가 catch
            throw new AccessDeniedException("Access Denied");
        }

        chain.doFilter(request, response);
    }
}
```

### 4. AnonymousAuthenticationFilter가 없으면 생기는 문제

```java
// AnonymousAuthenticationFilter.java
public class AnonymousAuthenticationFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        // SecurityContext에 Authentication이 없는 경우에만 동작
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            // 익명 Authentication을 생성해서 SecurityContext에 저장
            Authentication anon = createAuthentication((HttpServletRequest) request);
            // anon = AnonymousAuthenticationToken("anonymousUser", "ROLE_ANONYMOUS")
            SecurityContextHolder.getContext().setAuthentication(anon);
        }
        chain.doFilter(request, response);
    }
}

// AnonymousAuthenticationFilter가 없다면:
// SecurityContext가 비어 있는 상태로 AuthorizationFilter에 도달
// → AuthorizationFilter: SecurityContextHolder.getContext().getAuthentication() == null
// → Supplier<Authentication>이 null 반환
// → AuthorizationManager 구현에 따라 NPE 또는 예측 불가능한 동작
// → ExceptionTranslationFilter에서 null 체크 실패 가능

// AnonymousAuthenticationFilter 덕분에:
// 미인증 요청에도 항상 Authentication 객체가 존재
// → AuthorizationFilter에서 isAnonymous() 체크로 명확히 처리 가능
```

### 5. UsernamePasswordAuthenticationFilter는 모든 요청에 실행되지 않는다

```java
// AbstractAuthenticationProcessingFilter.java (UsernamePasswordAuthenticationFilter의 부모)
public abstract class AbstractAuthenticationProcessingFilter
        extends GenericFilterBean {

    // 인증 처리를 시도할 URL 패턴 (기본값: "/login" POST)
    private RequestMatcher requiresAuthenticationRequestMatcher;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        // ① 현재 요청이 로그인 URL인지 확인
        if (!requiresAuthentication((HttpServletRequest) request,
                                    (HttpServletResponse) response)) {
            // 로그인 URL이 아니면 그냥 다음 Filter로 넘김 (인증 시도 없음)
            chain.doFilter(request, response);
            return;
        }

        // ② 로그인 URL이면 인증 시도
        try {
            Authentication authResult = attemptAuthentication(
                (HttpServletRequest) request, (HttpServletResponse) response);
            // ...
        }
    }

    protected boolean requiresAuthentication(HttpServletRequest request,
                                              HttpServletResponse response) {
        // AntPathRequestMatcher("/login", "POST").matches(request)
        return this.requiresAuthenticationRequestMatcher.matches(request);
    }
}
// 결론: UsernamePasswordAuthenticationFilter는
// POST /login 요청에서만 인증을 시도
// GET /login, GET /api/users 등은 이 Filter에서 아무 처리 없이 그냥 통과
```

---

## 💻 실험으로 확인하기

### 실험 1: 실행 중인 Filter 목록과 순서 출력

```java
@Component
public class FilterChainLogger {

    private final FilterChainProxy filterChainProxy;

    public FilterChainLogger(
            @Qualifier("springSecurityFilterChain") Filter filter) {
        this.filterChainProxy = (FilterChainProxy) filter;
    }

    @PostConstruct
    public void logFilters() {
        filterChainProxy.getFilterChains().forEach(chain -> {
            System.out.println("=== SecurityFilterChain ===");
            chain.getFilters().forEach(f ->
                System.out.println("  " + f.getClass().getSimpleName())
            );
        });
    }
}
```

```
=== SecurityFilterChain ===
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CorsFilter
  CsrfFilter
  LogoutFilter
  UsernamePasswordAuthenticationFilter
  DefaultLoginPageGeneratingFilter
  DefaultLogoutPageGeneratingFilter
  BasicAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  SessionManagementFilter
  ExceptionTranslationFilter
  AuthorizationFilter
```

### 실험 2: DisableEncodeUrlFilter 동작 확인

```java
@GetMapping("/test-url")
public String test(HttpServletResponse response) {
    // DisableEncodeUrlFilter가 없으면:
    // response.encodeURL("/dashboard") → "/dashboard;jsessionid=ABC123"
    // URL에 세션 ID가 노출 → 세션 하이재킹 위험

    // DisableEncodeUrlFilter가 있으면:
    // response.encodeURL("/dashboard") → "/dashboard" (jsessionid 없음)
    return response.encodeURL("/dashboard");
}
```

```bash
# DisableEncodeUrlFilter 적용 전
curl http://localhost:8080/test-url
# → /dashboard;jsessionid=ABC123DEF456  (세션 ID 노출!)

# DisableEncodeUrlFilter 적용 후
curl http://localhost:8080/test-url
# → /dashboard  (세션 ID 없음)
```

### 실험 3: JWT 환경 최소 Filter 구성

```java
@Bean
public SecurityFilterChain jwtFilterChain(HttpSecurity http,
                                           JwtAuthenticationFilter jwtFilter) throws Exception {
    http
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/auth/**").permitAll()
            .anyRequest().authenticated());
    return http.build();
}
```

```java
// 위 설정 적용 후 Filter 목록:
// DisableEncodeUrlFilter          (비활성화 불가)
// WebAsyncManagerIntegrationFilter (비활성화 불가)
// SecurityContextHolderFilter     (비활성화 불가)
// HeaderWriterFilter
// JwtAuthenticationFilter         (커스텀, 추가됨)
// RequestCacheAwareFilter
// SecurityContextHolderAwareRequestFilter
// AnonymousAuthenticationFilter
// SessionManagementFilter
// ExceptionTranslationFilter      (비활성화 불가)
// AuthorizationFilter             (비활성화 불가)
//
// 제거된 Filter:
// CsrfFilter, LogoutFilter, UsernamePasswordAuthenticationFilter,
// DefaultLoginPageGeneratingFilter, DefaultLogoutPageGeneratingFilter,
// BasicAuthenticationFilter
```

### 실험 4: 커스텀 Filter를 특정 순서에 삽입

```java
// addFilterBefore / addFilterAfter / addFilterAt 비교
http
    // JwtFilter를 UsernamePasswordAuthenticationFilter 바로 앞에 (순서 1900 - 1)
    .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)

    // AuditFilter를 AuthorizationFilter 바로 뒤에 (순서 3600 + 1)
    .addFilterAfter(auditFilter, AuthorizationFilter.class)

    // LoggingFilter를 SecurityContextHolderFilter와 같은 순서에 (순서 600)
    // 동일 순서에서는 나중에 추가된 것이 뒤에 실행
    .addFilterAt(loggingFilter, SecurityContextHolderFilter.class);
```

---

## 🔒 보안 체크리스트

```
필수 활성화 Filter (비활성화 금지)
  ☐ DisableEncodeUrlFilter  — URL에 세션 ID 노출 방지
  ☐ SecurityContextHolderFilter — SecurityContext 생명주기
  ☐ ExceptionTranslationFilter — 인증/인가 예외 처리
  ☐ AuthorizationFilter    — 최종 권한 검사

JWT/Stateless 환경에서 비활성화
  ☐ CsrfFilter             — Stateless이므로 CSRF 불필요
  ☐ SessionManagementFilter — 세션 사용 안 함 (STATELESS 설정)
  ☐ FormLogin/BasicAuth    — 사용하지 않는 인증 방식 제거

커스텀 Filter 삽입 위치
  ☐ JWT 검증 Filter는 UsernamePasswordAuthenticationFilter 앞에 배치
  ☐ CORS Filter는 인증 Filter 앞에 있는지 확인
  ☐ 감사(Audit) Filter는 AuthorizationFilter 뒤에 배치
```

---

## 🤔 트레이드오프

```
Filter 세분화:
  장점  각 관심사를 독립적으로 활성화·비활성화·교체 가능
        특정 Filter만 테스트 가능 (@WithMockUser 등)
        새 인증 방식 추가 = 새 Filter 삽입만으로 완성
  단점  Filter 수가 많아지면 각 요청의 처리 오버헤드 증가
        (실제로는 각 Filter가 경량이므로 성능 영향 미미)
        Filter 순서 이해 없이 커스텀 Filter 삽입 시 예측 불가능한 동작

순서 간격(100 단위):
  장점  커스텀 Filter를 기존 Filter 사이에 유연하게 삽입 가능
  단점  FilterOrderRegistration의 100 단위 간격이 공개 API가 아니므로
        직접 순서 숫자를 사용하면 버전업 시 깨질 수 있음
        → addFilterBefore/After 사용 권장
```

---

## 📌 핵심 정리

```
Filter 실행 순서 결정
  FilterOrderRegistration에 각 Filter 클래스 → 정수 순서 매핑
  HttpSecurity가 활성화된 Feature에 따라 해당 Filter를 목록에 추가
  build() 시 순서 값으로 정렬 → DefaultSecurityFilterChain에 전달

반드시 기억할 순서 관계
  CorsFilter(900) → CsrfFilter(1000) → 인증 Filter → AnonymousFilter(3100)
  → ExceptionTranslationFilter(3400) → AuthorizationFilter(3600)

ExceptionTranslationFilter가 AuthorizationFilter 앞에 있는 이유
  AuthorizationFilter의 AccessDeniedException을 try-catch로 감싸야 하기 때문
  두 Filter의 순서가 바뀌면 예외가 처리되지 않고 Servlet Container로 전파됨

AnonymousAuthenticationFilter가 필요한 이유
  미인증 요청에도 Authentication 객체를 보장
  → AuthorizationFilter에서 null 없이 안전한 권한 검사 가능

JWT 환경 비활성화 대상
  CsrfFilter, UsernamePasswordAuthenticationFilter,
  BasicAuthenticationFilter, DefaultLoginPageGeneratingFilter
```

---

## 🤔 생각해볼 문제

**Q1.** `BearerTokenAuthenticationFilter`(순서 2500)와 커스텀 `JwtAuthenticationFilter`를 `addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)`로 등록하면 두 Filter가 모두 활성화될 수 있습니다. 이때 어떤 문제가 발생하며 어떻게 해결해야 하는가?

**Q2.** `AnonymousAuthenticationFilter`를 `http.anonymous(AbstractHttpConfigurer::disable)`로 비활성화하면 어떤 상황에서 문제가 생기는가? `permitAll()` 설정과 어떻게 상호작용하는가?

**Q3.** `RequestCacheAwareFilter`(순서 2700)는 인증 전 요청을 저장해 인증 성공 후 원래 URL로 리다이렉트합니다. JWT + Stateless 환경에서 이 Filter를 비활성화하지 않으면 어떤 부작용이 발생할 수 있으며, `NullRequestCache`를 설정하는 것이 올바른 해결책인가?

> 💡 **해설**
>
> **Q1.** `BearerTokenAuthenticationFilter`는 `Authorization: Bearer` 헤더를 처리하는 Spring Security의 기본 OAuth2 Resource Server Filter입니다. 커스텀 `JwtAuthenticationFilter`와 동시에 활성화되면 동일한 Bearer 토큰을 두 Filter가 각각 처리하려 시도합니다. `BearerTokenAuthenticationFilter`(순서 2500)가 먼저 실행되고, 검증 실패 시 `InvalidBearerTokenException`을 throw해 요청이 종료될 수 있습니다. 해결 방법은 `oauth2ResourceServer()` 설정을 사용하거나 커스텀 Filter를 사용하는 방식 중 하나만 선택하는 것입니다. 커스텀 Filter를 사용한다면 `oauth2ResourceServer()` 설정을 제거해 `BearerTokenAuthenticationFilter`가 체인에 추가되지 않도록 해야 합니다.
>
> **Q2.** `AnonymousAuthenticationFilter` 비활성화 시 SecurityContext가 비어 있는 상태로 `AuthorizationFilter`에 도달합니다. `AuthorizationManager`는 `null` Authentication을 받으면 구현에 따라 `NullPointerException` 또는 `ACCESS_DENIED`를 반환합니다. `permitAll()` 설정은 내부적으로 `permitAll`을 `AuthorizationDecision(true)`와 연결하므로 Authentication이 null이어도 통과할 수 있지만, 이는 구현 세부사항에 의존합니다. `ExceptionTranslationFilter`의 `isAnonymous()` 체크도 Authentication이 null이면 예외 처리 경로가 달라질 수 있습니다. 익명 사용자를 허용하는 `permitAll()` 경로가 있다면 `AnonymousAuthenticationFilter`를 비활성화하지 않는 것이 안전합니다.
>
> **Q3.** JWT + Stateless 환경에서 `RequestCacheAwareFilter`를 그냥 두면, 미인증 상태로 `/api/users` 접근 시 이 URL이 `HttpSessionRequestCache`에 저장됩니다. `SessionCreationPolicy.STATELESS` 설정 시 세션 생성을 하지 않으므로 실제로 저장되지는 않지만 캐시 확인 로직이 매 요청마다 실행됩니다. REST API 클라이언트는 리다이렉트를 따르지 않으므로 RequestCache가 의미 없습니다. `http.requestCache(cache -> cache.requestCache(new NullRequestCache()))`로 설정하면 캐시 조회 자체를 건너뛰어 불필요한 처리를 제거할 수 있습니다. 이는 Stateless API에서 권장되는 설정입니다.

---

<div align="center">

**[← 이전: SecurityFilterChain 구성과 우선순위](./02-security-filter-chain.md)** | **[홈으로 🏠](../README.md)** | **[다음: SecurityContext & SecurityContextHolder ➡️](./04-security-context-holder.md)**

</div>
