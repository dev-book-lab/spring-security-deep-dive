# Custom JWT Authentication Filter — OncePerRequestFilter 구현과 필터 배치 전략

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `OncePerRequestFilter`를 상속해야 하는 이유와 `GenericFilterBean`과의 차이는?
- JWT 필터를 `UsernamePasswordAuthenticationFilter` 앞에 배치해야 하는 이유는?
- `shouldNotFilter()` 메서드로 특정 경로를 필터 대상에서 제외하는 올바른 방법은?
- 토큰 검증 실패 시 예외를 던지는 방식과 SecurityContext 비우고 체인을 진행하는 방식의 차이는?
- `SecurityContextHolderStrategy`를 통해 SecurityContext를 설정하는 스레드 안전한 방식은?
- `WebAuthenticationDetailsSource`로 요청 세부 정보를 Authentication에 추가하는 이유는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### JWT 필터가 필요한 위치

```
Spring Security Filter Chain에서 JWT 인증의 역할:

  SecurityContextHolderFilter (100)
    → 매 요청마다 빈 SecurityContext 생성 (STATELESS 환경)

  [★ JwtAuthenticationFilter 삽입 위치]
    → Authorization 헤더에서 토큰 추출
    → 토큰 검증 (서명, 만료)
    → SecurityContextHolder에 Authentication 설정

  UsernamePasswordAuthenticationFilter (1900)
    → 폼 로그인 처리 (POST /login만)
    → JWT 환경에서는 disable() 또는 커스텀 로그인 엔드포인트로 대체

  AuthorizationFilter (3600)
    → SecurityContextHolder의 Authentication으로 권한 검사
    → JWT 필터가 설정한 Authentication을 사용

JWT 필터를 앞에 배치하는 이유:
  UsernamePasswordAuthenticationFilter 실행 전에
  Bearer 토큰으로 인증 상태를 설정
  → 폼 로그인이 아닌 토큰 기반 인증 처리
```

---

## 😱 흔한 보안 실수

### Before: GenericFilterBean 사용 — Forward 시 중복 실행

```java
// ❌ GenericFilterBean은 Forward/Include 요청에도 실행됨
// → JWT 파싱이 두 번 실행 (비효율 또는 중복 인증 문제)
@Component
public class JwtFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res,
                          FilterChain chain) throws IOException, ServletException {
        processJwt((HttpServletRequest) req); // Forward 시 재실행됨
        chain.doFilter(req, res);
    }
}

// ✅ OncePerRequestFilter: 요청당 정확히 한 번만 실행
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // 내부적으로 request 속성에 FILTERED 플래그 설정
    // Forward, Include, Error dispatch에서도 한 번만 실행 보장
}
```

### Before: 인증 실패 시 예외를 Filter 밖으로 던짐

```java
// ❌ RuntimeException throw → DispatcherServlet 레벨 오류 → 500 응답
@Override
protected void doFilterInternal(HttpServletRequest request, ...) {
    String token = extractToken(request);
    Claims claims = jwtTokenProvider.parseToken(token); // JwtException 발생 시
    // claims null → NullPointerException → 500
    setAuthentication(claims);
    chain.doFilter(request, response);
}

// ✅ 예외를 잡아 SecurityContext 비우고 체인 계속 진행
// → AuthorizationFilter에서 인증 없음을 감지 → 401
@Override
protected void doFilterInternal(HttpServletRequest request, ...) {
    String token = extractToken(request);
    if (token != null) {
        try {
            Claims claims = jwtTokenProvider.parseToken(token);
            setAuthentication(request, claims);
        } catch (JwtException e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            SecurityContextHolder.clearContext(); // 인증 정보 없음
        }
    }
    chain.doFilter(request, response); // 반드시 계속 진행
}
```

### Before: @Component + addFilterBefore 중복 등록

```java
// ❌ @Component → SpringBoot가 Servlet FilterChain에 자동 등록
//    addFilterBefore() → Spring Security FilterChain에도 등록
//    → 동일 인스턴스가 두 번 실행됨

@Component // ← 문제의 원인
public class JwtAuthenticationFilter extends OncePerRequestFilter { ... }

@Bean
public SecurityFilterChain filterChain(HttpSecurity http,
                                        JwtAuthenticationFilter jwtFilter) throws Exception {
    http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class); // 두 번 등록
    ...
}

// ✅ 해결 방법 A: @Component 제거, @Bean으로만 관리
@Bean
public JwtAuthenticationFilter jwtAuthenticationFilter() { ... }

// ✅ 해결 방법 B: @Component 유지 + FilterRegistrationBean 비활성화
@Bean
public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration(
        JwtAuthenticationFilter filter) {
    FilterRegistrationBean<JwtAuthenticationFilter> registration =
        new FilterRegistrationBean<>(filter);
    registration.setEnabled(false); // Servlet FilterChain 등록 비활성화
    return registration;
}
```

---

## ✨ 올바른 보안 구현

### 완전한 JWT 인증 필터 구현

```java
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    // SecurityContextHolderStrategy: 전략 패턴으로 캡슐화 → 테스트 시 교체 가능
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
        SecurityContextHolder.getContextHolderStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain)
            throws ServletException, IOException {

        // ① Authorization: Bearer 헤더에서 토큰 추출
        String token = resolveToken(request);

        if (token != null) {
            try {
                // ② 토큰 검증 (서명, 만료, iss 등)
                if (jwtTokenProvider.validateToken(token)) {

                    // ③ 클레임에서 username 추출
                    String username = jwtTokenProvider.getUsername(token);

                    // ④ UserDetails 로드 (계정 상태 DB 확인 포함)
                    UserDetails userDetails =
                        userDetailsService.loadUserByUsername(username);

                    // ⑤ authenticated() 상태의 Authentication 생성
                    UsernamePasswordAuthenticationToken authentication =
                        UsernamePasswordAuthenticationToken.authenticated(
                            userDetails,
                            null,                        // credentials: JWT에서 null
                            userDetails.getAuthorities() // 권한 포함 필수
                        );

                    // ⑥ 요청 세부 정보 설정 (IP, 세션 ID 등 — 감사 로그용)
                    authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                    // ⑦ SecurityContext에 Authentication 저장
                    SecurityContext context =
                        securityContextHolderStrategy.createEmptyContext();
                    context.setAuthentication(authentication);
                    securityContextHolderStrategy.setContext(context);

                    log.debug("JWT auth set: user={}, path={}",
                        username, request.getRequestURI());
                }
            } catch (ExpiredJwtException e) {
                log.info("Expired JWT: {}", e.getMessage());
                securityContextHolderStrategy.clearContext();
                // 만료 토큰 → 체인 계속 → 401 (Refresh Token으로 갱신 유도)
            } catch (JwtException e) {
                log.warn("Invalid JWT: {}", e.getMessage());
                securityContextHolderStrategy.clearContext();
            }
        }

        // ⑧ 인증 성공/실패 무관하게 체인 계속 (AuthorizationFilter가 최종 판단)
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null; // 헤더 없거나 형식 틀림
    }

    // 이 경로들은 필터 실행 자체를 건너뜀
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/auth/") // 로그인, 회원가입, 토큰 재발급
            || path.startsWith("/actuator/health"); // 인프라 헬스체크
    }
}
```

### SecurityConfig 등록

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class JwtSecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new JsonAuthenticationEntryPoint())
            )
            // JWT 필터를 UsernamePasswordAuthenticationFilter 앞에 삽입
            .addFilterBefore(jwtAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}

// 401 JSON 응답 EntryPoint
@Component
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                          HttpServletResponse response,
                          AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.getWriter().write(
            "{\"error\":\"UNAUTHORIZED\",\"message\":\"인증이 필요합니다.\"}");
    }
}
```

---

## 🔬 내부 동작 원리

### 1. OncePerRequestFilter 내부 구현

```java
// OncePerRequestFilter.java
public abstract class OncePerRequestFilter extends GenericFilterBean {

    @Override
    public final void doFilter(ServletRequest request, ServletResponse response,
                                FilterChain filterChain)
            throws ServletException, IOException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();

        // 이미 이 필터를 실행했는가?
        boolean hasAlreadyFiltered =
            request.getAttribute(alreadyFilteredAttributeName) != null;

        if (hasAlreadyFiltered || shouldNotFilter(httpRequest)) {
            // 중복 실행 방지 또는 shouldNotFilter=true → 건너뜀
            filterChain.doFilter(request, response);
        } else {
            // 첫 실행: 플래그 설정
            request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
            try {
                doFilterInternal(httpRequest, (HttpServletResponse) response,
                    filterChain);
            } finally {
                // 요청 종료 후 플래그 제거
                request.removeAttribute(alreadyFilteredAttributeName);
            }
        }
    }

    // 서브클래스에서 override: 특정 경로 제외
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return false; // 기본: 모든 요청에 적용
    }

    protected abstract void doFilterInternal(
        HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException;
}
```

### 2. addFilterBefore vs addFilterAt vs addFilterAfter

```java
// addFilterBefore(filter, referenceClass):
//   filter를 referenceClass 필터 바로 앞에 삽입
http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
// 실행 순서: ... → JwtFilter → UsernamePasswordAuthFilter → ...

// addFilterAt(filter, referenceClass):
//   filter를 referenceClass와 같은 순서값으로 등록
//   referenceClass를 대체하지 않음 (둘 다 등록됨)
http.addFilterAt(customFilter, BasicAuthenticationFilter.class);

// addFilterAfter(filter, referenceClass):
//   filter를 referenceClass 필터 바로 뒤에 삽입
http.addFilterAfter(auditFilter, AuthorizationFilter.class);

// JWT 필터 적절 위치:
// UsernamePasswordAuthenticationFilter 앞:
//   → 폼 로그인 처리 전에 Bearer 토큰 인증 수행
//   → 토큰으로 이미 인증됐으면 UsernamePasswordFilter는 영향 없음

// SecurityContextHolderFilter 뒤:
//   → SecurityContextHolder 초기화 후 JWT 필터 실행
//   → 이 순서가 기본적으로 보장됨
```

### 3. shouldNotFilter vs permitAll() 차이

```java
// shouldNotFilter():
//   필터 로직 자체를 실행하지 않음
//   JWT 파싱 시도조차 안 함
//   장점: 성능 (불필요한 헤더 파싱, 예외 처리 생략)
//   적합: 토큰 유무와 무관하게 항상 공개 (헬스체크, 정적 리소스)

@Override
protected boolean shouldNotFilter(HttpServletRequest request) {
    return request.getServletPath().startsWith("/actuator/health");
}

// permitAll():
//   JWT 필터는 실행되지만 AuthorizationFilter에서 무조건 허용
//   토큰 있으면 인증됨, 없으면 익명 상태로 처리
//   장점: 토큰 있으면 인증 컨텍스트 활용 가능
//   적합: 비로그인도 허용하지만 로그인 여부에 따라 응답 달라지는 API

.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/posts/**").permitAll() // 목록 조회: 비로그인 허용
    .anyRequest().authenticated()
)
// /api/posts 요청 시 토큰이 있으면 Authentication 설정 (좋아요 여부 표시 등)
// 토큰 없으면 익명 → 좋아요 여부 없이 반환
```

### 4. WebAuthenticationDetailsSource — 요청 세부 정보

```java
// WebAuthenticationDetails가 담는 정보:
//   remoteAddress: 클라이언트 IP (request.getRemoteAddr())
//   sessionId:     현재 세션 ID (STATELESS에서는 null)

// 활용:
@EventListener
public void onAuthSuccess(AuthenticationSuccessEvent event) {
    WebAuthenticationDetails details =
        (WebAuthenticationDetails) event.getAuthentication().getDetails();
    log.info("JWT auth: user={}, ip={}",
        event.getAuthentication().getName(),
        details.getRemoteAddress());
}
// → 이상 행동 탐지: 동일 토큰이 다른 IP에서 사용됨
// → 감사 로그: 어디서 인증했는지 기록
```

---

## 💻 실험으로 확인하기

### 실험 1: 필터 실행 순서 확인

```yaml
logging:
  level:
    org.springframework.security.web: DEBUG
```

```
# JWT 있는 요청:
DEBUG SecurityFilterChain - Executing filter JwtAuthenticationFilter
DEBUG JwtAuthenticationFilter - JWT auth set: user=kim, path=/api/orders
DEBUG SecurityFilterChain - Executing filter AuthorizationFilter
DEBUG AuthorizationFilter  - Authorized

# JWT 없는 요청:
DEBUG SecurityFilterChain - Executing filter JwtAuthenticationFilter
# (JWT 없음 → 아무것도 안 함)
DEBUG SecurityFilterChain - Executing filter AuthorizationFilter
DEBUG AuthorizationFilter  - Failed: No Authentication
```

### 실험 2: shouldNotFilter 동작 확인

```java
@SpringBootTest
@AutoConfigureMockMvc
class JwtFilterTest {

    @Test
    void healthCheck_jwtFilterSkipped() throws Exception {
        // /actuator/health: shouldNotFilter=true → JWT 없어도 통과
        mockMvc.perform(get("/actuator/health"))
            .andExpect(status().isOk());
    }

    @Test
    void api_withoutJwt_returns401() throws Exception {
        mockMvc.perform(get("/api/orders"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void api_withValidJwt_returns200() throws Exception {
        String token = jwtTokenProvider.createAccessToken(
            1L, "kim", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        mockMvc.perform(get("/api/orders")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }

    @Test
    void api_withExpiredJwt_returns401() throws Exception {
        String expired = createExpiredToken("kim");
        mockMvc.perform(get("/api/orders")
                .header("Authorization", "Bearer " + expired))
            .andExpect(status().isUnauthorized());
    }
}
```

### 실험 3: 중복 등록 감지

```bash
# 필터가 두 번 등록된 경우 로그:
# DEBUG JwtAuthenticationFilter - JWT auth set: user=kim
# DEBUG JwtAuthenticationFilter - JWT auth set: user=kim  ← 두 번 출력되면 문제

# 정상: 한 번만 출력
# DEBUG JwtAuthenticationFilter - JWT auth set: user=kim
```

---

## 🔒 보안 체크리스트

```
필터 구현
  ☐ OncePerRequestFilter 상속 (GenericFilterBean 사용 금지)
  ☐ 인증 실패 시 clearContext() 후 chain.doFilter() 계속
  ☐ 예외를 FilterChain 밖으로 던지지 않음 (500 방지)
  ☐ Authorization 헤더만 허용 (URL 파라미터 방식 금지 — 서버 로그 노출)

필터 등록
  ☐ addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
  ☐ @Component + addFilterBefore 중복 등록 방지
     (FilterRegistrationBean.setEnabled(false) 또는 @Component 제거)

shouldNotFilter 설정
  ☐ 공개 엔드포인트 명시 (로그인, 회원가입, 헬스체크)
  ☐ 불필요한 JWT 파싱 제거로 성능 향상

EntryPoint
  ☐ JWT 환경: JSON 401 응답 EntryPoint 설정
  ☐ HTML 리다이렉트 EntryPoint 사용 금지 (API 클라이언트에 HTML 응답 방지)
```

---

## 🤔 트레이드오프

```
shouldNotFilter vs permitAll():
  shouldNotFilter:
    장점  필터 자체 불실행 → 성능 최적
    단점  토큰이 있어도 파싱 안 함 → 인증 상태 알 수 없음
    → 순수 공개 API (인증 정보 전혀 불필요)

  permitAll():
    장점  토큰 있으면 인증, 없으면 익명 → 맥락 파악 가능
    단점  모든 요청에 JWT 파싱 시도 → 약간의 추가 비용
    → 로그인/비로그인 모두 허용하되 구분이 필요한 API

UserDetails DB 조회 여부:
  매 요청마다 DB 조회:
    장점  계정 정지/삭제 즉시 반영
    단점  DB 부하, 응답 지연 (모든 API 요청에 DB 조회)

  JWT 클레임에서 직접 생성:
    장점  DB 조회 없음 → 빠름, 확장성 좋음
    단점  계정 정지가 토큰 만료 전까지 즉시 반영 안 됨
    → 짧은 액세스 토큰(15분) + Redis 블랙리스트 조합 권장
```

---

## 📌 핵심 정리

```
OncePerRequestFilter
  요청당 정확히 한 번 실행 (Forward/Include 중복 방지)
  shouldNotFilter(): 특정 경로 필터 실행 자체 제외
  doFilterInternal(): 실제 JWT 처리 로직 구현

JWT 필터 처리 흐름
  ① Authorization: Bearer 헤더 추출
  ② 토큰 검증 (JwtTokenProvider)
  ③ username 추출 → UserDetails 로드
  ④ UsernamePasswordAuthenticationToken.authenticated() 생성
  ⑤ SecurityContextHolderStrategy로 SecurityContext 저장
  ⑥ chain.doFilter() (인증 성공/실패 무관)

인증 실패 처리
  catch JwtException → clearContext() → chain.doFilter()
  → AuthorizationFilter → AccessDeniedException
  → ExceptionTranslationFilter → AuthenticationEntryPoint → 401 JSON

중복 등록 방지
  @Component 없이 @Bean만 또는
  FilterRegistrationBean.setEnabled(false)로 Servlet 체인 등록 비활성화
```

---

## 🤔 생각해볼 문제

**Q1.** `JwtAuthenticationFilter`에 `@Component`를 붙이고 `SecurityConfig`에서 `addFilterBefore()`로 등록하면 필터가 두 번 실행될 수 있습니다. Spring Boot가 `@Component` Filter를 자동으로 Servlet FilterChain에 등록하는 메커니즘은 무엇이며, 어떻게 방지하는가?

**Q2.** `shouldNotFilter()`에서 `/api/public/posts`를 제외하면 해당 경로에서는 JWT 파싱이 전혀 일어나지 않습니다. 비로그인도 허용하지만 로그인 사용자에게는 "좋아요 여부"를 추가로 응답해야 하는 API라면 `shouldNotFilter()`와 `permitAll()` 중 어느 것이 더 적합한가?

**Q3.** `WebAuthenticationDetailsSource().buildDetails(request)`로 설정하는 `remoteAddress`가 AWS ELB, Nginx 리버스 프록시 뒤에서 항상 프록시 IP가 나오는 문제를 어떻게 해결하는가?

> 💡 **해설**
>
> **Q1.** Spring Boot는 `ApplicationContext`에 등록된 `Filter` 타입의 Bean을 `FilterRegistrationBean`으로 자동 래핑해 내장 Servlet 컨테이너(Tomcat 등)의 FilterChain에 등록합니다. 이것이 Spring Security FilterChain과는 별개의 Servlet 수준 FilterChain입니다. 동일 필터가 두 체인에 모두 등록되므로 요청당 두 번 실행됩니다. `OncePerRequestFilter`의 FILTERED 플래그 덕분에 두 번째 실행 시 로직이 스킵되긴 하지만 여전히 두 번 호출됩니다. 방지 방법은 ① `@Component` 제거 후 `@Bean`으로만 관리, ② `@Component` 유지 + `FilterRegistrationBean.setEnabled(false)`로 Servlet 체인 등록 비활성화, ③ `@Component` 유지 + `shouldNotFilter()`에서 Servlet 체인 실행 시를 감지해 건너뜀 중 하나를 선택합니다.
>
> **Q2.** `permitAll()`이 더 적합합니다. `shouldNotFilter()`를 사용하면 JWT 필터가 실행되지 않아 토큰이 있어도 인증 상태가 설정되지 않고 항상 익명 사용자로 처리됩니다. `permitAll()`을 사용하면 JWT 필터가 실행되어 토큰이 있으면 `Authentication`이 설정되고 없으면 익명 상태로 처리됩니다. Controller에서 `Authentication authentication` 파라미터 또는 `@AuthenticationPrincipal`로 로그인 여부를 확인해 조건부 응답을 구성할 수 있습니다. `shouldNotFilter()`는 인증 정보가 전혀 필요 없는 경우(헬스체크, 순수 정적 리소스)에만 사용합니다.
>
> **Q3.** 리버스 프록시는 실제 클라이언트 IP를 `X-Forwarded-For` 또는 `X-Real-IP` 헤더에 담아 전달합니다. Spring Boot에서 `server.forward-headers-strategy=native` (또는 `framework`) 설정으로 `ForwardedHeaderFilter`를 활성화하면 `request.getRemoteAddr()`가 실제 클라이언트 IP를 반환합니다. 단, `X-Forwarded-For` 헤더는 공격자가 조작 가능하므로 신뢰할 수 있는 프록시 목록을 설정(`server.tomcat.remote-ip-header`, `server.tomcat.internal-proxies`)해야 합니다. 또는 커스텀 `WebAuthenticationDetailsSource`를 구현해 `X-Forwarded-For` 헤더를 직접 읽어 `details`에 설정하는 방법도 있습니다.

---

<div align="center">

**[← 이전: JWT 구조 완전 분석](./01-jwt-structure-analysis.md)** | **[홈으로 🏠](../README.md)** | **[다음: JWT Token 발급 과정 ➡️](./03-jwt-token-provider.md)**

</div>
