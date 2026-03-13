# UsernamePasswordAuthenticationFilter 분석 — attemptAuthentication부터 SuccessHandler까지

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `UsernamePasswordAuthenticationFilter`는 모든 요청에서 실행되는가, 아니면 특정 조건에서만 실행되는가?
- `attemptAuthentication()` → `successfulAuthentication()` / `unsuccessfulAuthentication()` 흐름에서 각 메서드의 정확한 책임은?
- `AuthenticationSuccessHandler`와 `AuthenticationFailureHandler`는 각각 언제 호출되며 기본 구현은 무엇인가?
- 로그인 성공 후 `SecurityContext`에 `Authentication`이 저장되는 정확한 시점은?
- JSON 바디로 로그인 요청을 받으려면 어떻게 커스터마이징해야 하는가?
- `SavedRequestAwareAuthenticationSuccessHandler`가 로그인 전 요청 URL로 리다이렉트하는 원리는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 폼 로그인 처리를 Controller에서 하면 안 되는 이유

```
❌ Controller에서 로그인 처리:
  @PostMapping("/login")
  public String login(@RequestParam String username,
                      @RequestParam String password,
                      HttpSession session) {
      User user = userService.findAndValidate(username, password);
      session.setAttribute("user", user);
      return "redirect:/dashboard";
  }

  문제:
  → SecurityContext와 무관 → @PreAuthorize 등 보안 어노테이션 동작 안 함
  → CSRF 보호, 세션 고정 방어, Remember-Me 등 보안 기능 미작동
  → 인증 성공/실패 이벤트가 발행되지 않음 → 감사 로그 불가
  → 로그인 전 요청 URL로 리다이렉트 기능 없음

✅ UsernamePasswordAuthenticationFilter:
  → Security Filter Chain에 통합 → 모든 보안 기능 자동 적용
  → 인증 성공 시 SecurityContext에 Authentication 저장
  → 세션 고정 방어 자동 실행
  → SavedRequest로 원래 URL 복원 자동 처리
```

---

## 😱 흔한 보안 실수

### Before: 로그인 URL 패턴을 permitAll()에 추가하지 않음

```java
// ❌ 문제: POST /login 자체를 authenticated()로 보호하면
//   인증 전 사용자가 로그인 시도 자체를 못 함
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .anyRequest().authenticated()); // /login POST도 여기에 걸림

// ✅ 올바른 설정
http
    .formLogin(form -> form
        .loginPage("/login")
        .loginProcessingUrl("/login") // POST /login 처리
        .permitAll()                  // GET/POST /login 모두 허용
    )
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/public/**").permitAll()
        .anyRequest().authenticated());
// formLogin().permitAll()은 내부적으로:
//   loginPage("/login"), loginProcessingUrl("/login"), failureUrl 모두 permitAll 처리
```

### Before: JSON 로그인 구현 시 CSRF 설정 누락

```java
// ❌ REST API 클라이언트가 JSON으로 로그인 시
//   기본 CSRF 보호 → X-CSRF-TOKEN 없으면 403

// ✅ JSON 로그인 + CSRF 처리
http
    .csrf(csrf -> csrf
        .ignoringRequestMatchers("/api/auth/login") // JSON 로그인 엔드포인트 제외
    )
    .addFilterBefore(jsonLoginFilter(), UsernamePasswordAuthenticationFilter.class);

// 또는 Stateless JWT 환경에서:
http.csrf(AbstractHttpConfigurer::disable);
```

---

## ✨ 올바른 보안 구현

### 폼 로그인 커스터마이징

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .formLogin(form -> form
            .loginPage("/login")                    // 커스텀 로그인 페이지 (GET)
            .loginProcessingUrl("/auth/login")      // 로그인 폼 POST URL
            .usernameParameter("email")             // 폼 파라미터명 변경
            .passwordParameter("passwd")
            .defaultSuccessUrl("/dashboard", false) // 성공 후 기본 리다이렉트
            // false: SavedRequest가 있으면 그쪽으로 (권장)
            // true:  항상 /dashboard로
            .failureUrl("/login?error=true")        // 실패 후 리다이렉트
            .successHandler(customSuccessHandler()) // 커스텀 핸들러
            .failureHandler(customFailureHandler())
            .permitAll()
        );
    return http.build();
}

// 커스텀 SuccessHandler — JSON 응답
@Bean
public AuthenticationSuccessHandler customSuccessHandler() {
    return (request, response, authentication) -> {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        Map<String, Object> body = Map.of(
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities()
        );
        new ObjectMapper().writeValue(response.getWriter(), body);
    };
}
```

### JSON 바디 로그인 필터 구현

```java
// REST API 환경에서 JSON 바디로 로그인 처리
public class JsonLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper;

    public JsonLoginFilter(AuthenticationManager authenticationManager,
                           ObjectMapper objectMapper) {
        super(authenticationManager);
        this.objectMapper = objectMapper;
        // POST /api/auth/login 에서만 실행
        setRequiresAuthenticationRequestMatcher(
            new AntPathRequestMatcher("/api/auth/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException {
        try {
            // JSON 바디에서 자격증명 추출
            LoginRequest loginRequest = objectMapper.readValue(
                request.getInputStream(), LoginRequest.class);

            UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
                );
            setDetails(request, token);
            return getAuthenticationManager().authenticate(token);
        } catch (IOException e) {
            throw new AuthenticationServiceException(
                "Failed to parse login request", e);
        }
    }
}
```

---

## 🔬 내부 동작 원리

### 1. AbstractAuthenticationProcessingFilter — 공통 처리 흐름

```java
// AbstractAuthenticationProcessingFilter.java
// UsernamePasswordAuthenticationFilter의 부모
public abstract class AbstractAuthenticationProcessingFilter
        extends GenericFilterBean implements ApplicationEventPublisherAware,
        MessageSourceAware {

    // 이 Filter가 처리할 URL 패턴
    private RequestMatcher requiresAuthenticationRequestMatcher;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response,
                          FilterChain chain) throws IOException, ServletException {

        // ① 현재 요청이 로그인 URL인가? (기본: POST /login)
        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response); // 아니면 그냥 통과
            return;
        }

        try {
            // ② 인증 시도 (하위 클래스 구현)
            Authentication authResult = attemptAuthentication(request, response);

            if (authResult == null) {
                // 인증 처리가 완료되지 않음 (멀티 스텝 인증 등)
                return;
            }

            // ③ 세션 관리 (세션 고정 방어)
            this.sessionStrategy.onAuthentication(authResult, request, response);

            // ④ 인증 성공 처리
            successfulAuthentication(request, response, chain, authResult);

        } catch (InternalAuthenticationServiceException failed) {
            // 서버 내부 오류
            unsuccessfulAuthentication(request, response, failed);
        } catch (AuthenticationException ex) {
            // 자격증명 오류, 계정 상태 오류 등
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    // ④ 인증 성공 처리
    protected void successfulAuthentication(HttpServletRequest request,
                                             HttpServletResponse response,
                                             FilterChain chain,
                                             Authentication authResult)
            throws IOException, ServletException {

        // SecurityContext에 Authentication 저장
        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authResult);
        this.securityContextHolderStrategy.setContext(context);

        // SecurityContextRepository에 저장 (HttpSession)
        this.securityContextRepository.saveContext(context, request, response);

        // Remember-Me 처리 (체크박스 선택 시 쿠키 발행)
        this.rememberMeServices.loginSuccess(request, response, authResult);

        // 인증 성공 이벤트 발행
        if (this.eventPublisher != null) {
            this.eventPublisher.publishEvent(
                new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }

        // SuccessHandler 호출 (리다이렉트 등)
        this.successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    // ⑤ 인증 실패 처리
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                               HttpServletResponse response,
                                               AuthenticationException failed)
            throws IOException, ServletException {

        // SecurityContext 초기화
        this.securityContextHolderStrategy.clearContext();

        // Remember-Me 쿠키 제거
        this.rememberMeServices.loginFail(request, response);

        // FailureHandler 호출 (에러 리다이렉트 등)
        this.failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
```

### 2. UsernamePasswordAuthenticationFilter — 폼 파라미터 추출

```java
// UsernamePasswordAuthenticationFilter.java
public class UsernamePasswordAuthenticationFilter
        extends AbstractAuthenticationProcessingFilter {

    // 기본 로그인 URL: POST /login
    public static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
        new AntPathRequestMatcher("/login", "POST");

    // 폼 파라미터명 (변경 가능)
    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY; // "username"
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY; // "password"

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException {

        // POST 메서드 확인 (GET 로그인 요청은 처리하지 않음)
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                "Authentication method not supported: " + request.getMethod());
        }

        // 폼 파라미터에서 username, password 추출
        String username = obtainUsername(request);
        username = (username != null) ? username.trim() : "";
        String password = obtainPassword(request);
        password = (password != null) ? password : "";

        // 인증 전 토큰 생성 (isAuthenticated=false)
        UsernamePasswordAuthenticationToken authRequest =
            UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        // WebAuthenticationDetails 설정 (IP, 세션 ID)
        setDetails(request, authRequest);

        // AuthenticationManager에 위임
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    // 폼 파라미터에서 값 추출
    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(this.usernameParameter);
    }
    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(this.passwordParameter);
    }
}
```

### 3. AuthenticationSuccessHandler 구현체 계층

```java
// 1. SimpleUrlAuthenticationSuccessHandler
//    → 지정된 URL로 리다이렉트 (가장 단순)
public class SimpleUrlAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    private String defaultTargetUrl = "/"; // 기본 리다이렉트 URL

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        response.sendRedirect(targetUrl);
    }
}

// 2. SavedRequestAwareAuthenticationSuccessHandler (기본값)
//    → 로그인 전 접근하려 했던 URL로 리다이렉트
//    SimpleUrlAuthenticationSuccessHandler 상속
public class SavedRequestAwareAuthenticationSuccessHandler
        extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        // RequestCacheAwareFilter가 저장한 로그인 전 URL 조회
        SavedRequest savedRequest =
            this.requestCache.getRequest(request, response);

        if (savedRequest == null) {
            // 저장된 요청 없음 → 기본 URL로 리다이렉트
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        String targetUrl = savedRequest.getRedirectUrl();
        // 저장된 요청 제거
        this.requestCache.removeRequest(request, response);
        // 원래 요청 URL로 리다이렉트
        response.sendRedirect(targetUrl);
    }
}

// 동작 예시:
// 사용자가 /dashboard 접근 → 로그인 페이지로 리다이렉트
// RequestCacheAwareFilter: /dashboard를 HttpSession에 SavedRequest로 저장
// 로그인 성공 → SavedRequestAwareAuthenticationSuccessHandler
//   → savedRequest.getRedirectUrl() = /dashboard
//   → response.sendRedirect("/dashboard")
```

### 4. AuthenticationFailureHandler 구현체

```java
// SimpleUrlAuthenticationFailureHandler (기본값)
public class SimpleUrlAuthenticationFailureHandler
        implements AuthenticationFailureHandler {

    private String defaultFailureUrl; // "/login?error" 등

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        if (this.defaultFailureUrl == null) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        }
        // 실패 URL로 리다이렉트 (세션에 에러 저장)
        saveException(request, exception);
        response.sendRedirect(this.defaultFailureUrl);
    }

    // 에러 메시지를 세션/request 속성에 저장
    // 로그인 페이지에서 ${sessionScope.SPRING_SECURITY_LAST_EXCEPTION.message}로 접근 가능
    protected final void saveException(HttpServletRequest request,
                                        AuthenticationException exception) {
        request.getSession()
            .setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
    }
}
```

### 5. 전체 흐름 ASCII 다이어그램

```
POST /login (username=kim&password=1234)
│
▼ UsernamePasswordAuthenticationFilter.doFilter()
│
├─ requiresAuthentication() → true (POST /login 매칭)
│
├─ attemptAuthentication()
│    username = request.getParameter("username") = "kim"
│    password = request.getParameter("password") = "1234"
│    token = new UPAT("kim", "1234")   [isAuthenticated=false]
│    return authManager.authenticate(token)
│         └─ DaoAuthenticationProvider
│              loadUserByUsername("kim") → UserDetails
│              PasswordEncoder.matches("1234", hash) → true
│              return new UPAT(userDetails, null, roles) [isAuthenticated=true]
│
├─ sessionStrategy.onAuthentication()
│    → 세션 고정 방어: 새 세션 ID 발급
│
├─ successfulAuthentication()
│    SecurityContext.setAuthentication(authResult)
│    securityContextRepository.saveContext()  → HttpSession["SPRING_SECURITY_CONTEXT"]
│    rememberMeServices.loginSuccess()        → Remember-Me 쿠키 발행 (체크박스 선택 시)
│    eventPublisher.publishEvent()            → InteractiveAuthenticationSuccessEvent
│    successHandler.onAuthenticationSuccess() → /dashboard로 리다이렉트
│
└─ 응답: 302 Found → Location: /dashboard
         Set-Cookie: JSESSIONID=<new-id> (새 세션 ID)
```

---

## 💻 실험으로 확인하기

### 실험 1: 로그인 전 URL 복원 동작 확인

```bash
# 1. 인증 없이 /dashboard 접근
curl -c cookies.txt http://localhost:8080/dashboard
# → 302 → /login (SavedRequest에 /dashboard 저장됨)

# 2. 로그인
curl -c cookies.txt -b cookies.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"
# → 302 → /dashboard (SavedRequestAwareAuthenticationSuccessHandler 동작)

# 직접 로그인 페이지에서 로그인 (SavedRequest 없음):
curl -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"
# → 302 → / (defaultSuccessUrl 기본값)
```

### 실험 2: 로그인 성공/실패 이벤트 리스닝

```java
@Component
public class AuthenticationEventListener {

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        Authentication auth = event.getAuthentication();
        log.info("Login success: user={}, ip={}",
            auth.getName(),
            ((WebAuthenticationDetails) auth.getDetails()).getRemoteAddress());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        log.warn("Login failure: user={}, reason={}",
            event.getAuthentication().getName(),
            event.getException().getMessage());
    }
}
```

### 실험 3: 세션 고정 방어 확인

```bash
# 로그인 전 세션 ID 확인
curl -c before.txt http://localhost:8080/login
BEFORE_SESSION=$(grep JSESSIONID before.txt | awk '{print $7}')
echo "Before: $BEFORE_SESSION"

# 로그인 수행
curl -c after.txt -b before.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"
AFTER_SESSION=$(grep JSESSIONID after.txt | awk '{print $7}')
echo "After: $AFTER_SESSION"

# Before != After → 세션 고정 방어 동작 확인
# (sessionStrategy.onAuthentication()이 새 세션 ID 발급)
```

### 실험 4: TRACE 로그로 전체 흐름 관찰

```yaml
logging:
  level:
    org.springframework.security.web.authentication: TRACE
    org.springframework.security.authentication: DEBUG
```

```
# POST /login 시:
TRACE AbstractAuthenticationProcessingFilter - Request is to process authentication
DEBUG DaoAuthenticationProvider - Authenticated user
DEBUG AbstractAuthenticationProcessingFilter - Set SecurityContextHolder to ...
TRACE AbstractAuthenticationProcessingFilter - Redirecting to /dashboard
```

---

## 🔒 보안 체크리스트

```
로그인 URL 보호
  ☐ loginPage() (GET)와 loginProcessingUrl() (POST) 모두 permitAll() 설정
  ☐ POST /login에 CSRF 토큰 포함 (기본 활성화)
  ☐ JSON 로그인 시 CSRF 처리 방식 결정 (disable 또는 헤더 방식)

세션 보안
  ☐ 로그인 성공 시 세션 고정 방어 (기본 활성화 — 변경 금지)
  ☐ HTTPS 환경에서 Secure 쿠키 설정
  ☐ sessionManagement().sessionFixation() 설정 확인

SuccessHandler 구현
  ☐ JSON API: 201 또는 200 응답 + 리다이렉트 없음
  ☐ 웹: SavedRequestAwareAuthenticationSuccessHandler (기본) 유지
  ☐ 리다이렉트 URL을 사용자 입력값으로 결정 금지 (Open Redirect 취약점)

FailureHandler 구현
  ☐ 에러 메시지에 "사용자 없음" vs "비밀번호 틀림" 구분 노출 금지
  ☐ 로그인 실패 횟수 기록 → N회 초과 시 계정 잠금 연동
```

---

## 🤔 트레이드오프

```
폼 로그인 vs JSON 로그인:
  폼 로그인:
    장점  Spring Security 기본 통합 완벽 (CSRF, SavedRequest, Remember-Me)
          별도 구현 없음
    단점  HTML 폼 + multipart/form-data 방식 → REST API 클라이언트 불편

  JSON 로그인:
    장점  REST API 클라이언트에서 자연스러운 JSON 요청
          응답도 JSON으로 제어 가능
    단점  커스텀 Filter 작성 필요
          CSRF 처리 별도 고려
          저장 가능 요청(SavedRequest) 연동 직접 구현 필요

SavedRequestAwareAuthenticationSuccessHandler:
  장점  사용자 경험 향상 (로그인 후 원래 URL로 복귀)
        추가 구현 없이 자동 동작
  단점  AJAX 요청이 SavedRequest에 저장되면 리다이렉트 URL이 이상해질 수 있음
        → requestCache.setRequestMatcher()로 저장 대상 제한 필요
```

---

## 📌 핵심 정리

```
실행 조건
  POST /login (기본) 요청에만 attemptAuthentication() 실행
  requiresAuthenticationRequestMatcher.matches() = true 일 때만

성공 흐름
  attemptAuthentication() → AuthenticationManager.authenticate()
  → successfulAuthentication():
      1. SecurityContext.setAuthentication()
      2. securityContextRepository.saveContext() (HttpSession 저장)
      3. rememberMeServices.loginSuccess()
      4. InteractiveAuthenticationSuccessEvent 발행
      5. successHandler.onAuthenticationSuccess() (리다이렉트)

실패 흐름
  AuthenticationException → unsuccessfulAuthentication():
      1. SecurityContext.clearContext()
      2. rememberMeServices.loginFail()
      3. failureHandler.onAuthenticationFailure() (에러 리다이렉트)

세션 고정 방어
  sessionStrategy.onAuthentication() → 로그인 성공 시 새 세션 ID 발급
  기본 전략: ChangeSessionIdAuthenticationStrategy

SavedRequest 복원
  로그인 전 접근 URL → RequestCacheAwareFilter가 저장
  로그인 성공 → SavedRequestAwareAuthenticationSuccessHandler가 복원
```

---

## 🤔 생각해볼 문제

**Q1.** `successfulAuthentication()`에서 `securityContextRepository.saveContext()`를 호출한 후 `successHandler.onAuthenticationSuccess()`에서 `response.sendRedirect()`를 호출합니다. 만약 SuccessHandler에서 `SecurityContextHolder.getContext().setAuthentication(null)`을 호출하면 어떤 결과가 생기는가?

**Q2.** AJAX로 `POST /login`을 요청하는 경우 `SavedRequestAwareAuthenticationSuccessHandler`가 `302 Redirect`를 반환합니다. 브라우저의 AJAX 요청은 302를 자동으로 따라가므로 리다이렉트된 페이지의 HTML이 응답으로 반환됩니다. 이를 해결하기 위한 커스텀 SuccessHandler 설계 방법은?

**Q3.** `sessionStrategy.onAuthentication()`에서 기본 전략인 `ChangeSessionIdAuthenticationStrategy`가 `request.changeSessionId()`를 호출합니다. 이것이 `InvalidateSessionAuthenticationStrategy`와 다른 이유는 무엇이며, Servlet 3.1+ 환경에서 `changeSessionId()`가 세션 데이터를 어떻게 처리하는가?

> 💡 **해설**
>
> **Q1.** `securityContextRepository.saveContext()`는 이미 호출됐으므로 `HttpSession`에는 올바른 `Authentication`이 저장된 상태입니다. 이후 `SecurityContextHolder`에서 `Authentication`을 null로 바꿔도 `HttpSession`에 저장된 값에는 영향이 없습니다. 따라서 리다이렉트된 다음 요청에서 `SecurityContextHolderFilter`가 `HttpSession`에서 올바른 `SecurityContext`를 복원하므로 로그인 상태가 정상적으로 유지됩니다. 즉, 현재 요청의 `SecurityContextHolder`만 초기화될 뿐 인증 상태 자체는 유지됩니다.
>
> **Q2.** AJAX 로그인에서는 302 대신 JSON 응답을 반환하는 커스텀 `AuthenticationSuccessHandler`를 구현합니다. `response.setStatus(200)`, `response.setContentType("application/json")`을 설정하고 `{ "status": "success", "redirectUrl": "/dashboard" }`를 바디에 씁니다. `RequestCache`에서 `SavedRequest`를 꺼내 `redirectUrl`을 결정하고, 클라이언트 JavaScript가 이 URL로 직접 `window.location.href = redirectUrl`로 이동합니다. 또한 AJAX 요청인지 판별하기 위해 `X-Requested-With: XMLHttpRequest` 헤더를 확인하거나, 별도의 JSON API 로그인 엔드포인트(`/api/auth/login`)를 분리하는 방법이 깔끔합니다.
>
> **Q3.** `InvalidateSessionAuthenticationStrategy`는 기존 세션을 완전히 무효화하고 새 세션을 생성합니다. 이 과정에서 기존 세션에 저장된 데이터(장바구니, `SavedRequest` 등)가 모두 손실됩니다. 반면 `ChangeSessionIdAuthenticationStrategy`는 Servlet 3.1의 `HttpServletRequest.changeSessionId()`를 호출해 세션 ID만 새로 발급하고 세션 데이터는 그대로 보존합니다. 서버 내부에서 세션 저장소의 키만 변경되므로 세션 데이터 마이그레이션 비용이 없습니다. 세션 고정 공격을 방어하면서도 `SavedRequest`, `OAuth2AuthorizationRequest` 등 로그인 전 저장된 데이터를 잃지 않는 장점이 있어 Spring Security 4.0부터 기본 전략으로 채택됐습니다.

---

<div align="center">

**[← 이전: PasswordEncoder 종류와 선택](./04-password-encoder.md)** | **[홈으로 🏠](../README.md)** | **[다음: Remember-Me 인증 메커니즘 ➡️](./06-remember-me-authentication.md)**

</div>
