# Session Timeout 처리 — InvalidSessionStrategy가 호출되는 조건과 처리 흐름

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `server.servlet.session.timeout`이 실제로 적용되는 레이어는 어디이며 Spring Security와 어떻게 연결되는가?
- `SessionManagementFilter`가 무효한 세션을 감지하는 조건은 정확히 무엇인가?
- `InvalidSessionStrategy`가 호출되는 시점과 `ExceptionTranslationFilter`의 처리 흐름 차이는?
- 세션 타임아웃 후 API 요청 시 JSON 오류 응답을 반환하는 커스텀 전략 구현 방법은?
- 세션 타임아웃과 세션 만료(`SessionInformation.expireNow()`)는 Spring Security에서 어떻게 다르게 처리되는가?
- 세션 타임아웃을 줄였을 때 동시 세션 제어와 충돌이 생길 수 있는 시나리오는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 세션 타임아웃이 보안에 미치는 영향

```
타임아웃 없는 세션의 위험:
  1. 사용자가 공용 PC에서 로그인 후 그냥 자리를 떠남
  2. 세션이 무제한 유효 → 다음 사람이 로그인 상태 그대로 사용 가능
  3. 탈취된 세션 쿠키가 영원히 유효
  4. 서버 메모리: 비활성 세션이 무한정 축적

타임아웃 처리의 보안 관점:
  짧은 타임아웃 (5~15분): 보안성 높음, 사용자 불편
  긴 타임아웃 (8시간+): 사용성 높음, 보안 위험
  Remember-Me와 조합: 적절한 세션 타임아웃 + 장기 자동 로그인 분리

타임아웃 후 처리가 중요한 이유:
  단순히 "세션 없음"이 아닌
  → 적절한 메시지로 사용자 안내 (웹)
  → 명확한 401/440 응답으로 클라이언트 처리 가능 (API)
  → 타임아웃 vs 미인증 vs 권한없음을 구분해서 처리
```

---

## 😱 흔한 보안 실수

### Before: 세션 타임아웃과 스프링 시큐리티 설정의 불일치

```java
// ❌ 문제: application.properties에만 타임아웃 설정, Security 처리 없음
# application.properties
server.servlet.session.timeout=1800  # 30분

# Spring Security에 invalidSessionUrl 설정 없음
# → 타임아웃 후 요청 시 AccessDeniedException 또는 불명확한 응답

// ✅ 세션 타임아웃과 Security 처리 함께 설정
# application.properties
server.servlet.session.timeout=1800

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(session -> session
        .invalidSessionUrl("/session-timeout")         // 웹: 타임아웃 안내 페이지
        // 또는
        .invalidSessionStrategy(new CustomInvalidSessionStrategy()) // API: JSON 응답
    );
    return http.build();
}
```

### Before: AJAX 요청에 HTML 리다이렉트 응답

```java
// ❌ 문제: AJAX 요청도 302 리다이렉트로 처리됨
// 브라우저 AJAX → 302 → /session-timeout HTML → 클라이언트가 HTML을 JSON으로 파싱 시도 → 오류

// ✅ 요청 유형별 응답 분리
@Component
public class SmartInvalidSessionStrategy implements InvalidSessionStrategy {

    @Override
    public void onInvalidSessionDetected(HttpServletRequest request,
                                          HttpServletResponse response)
            throws IOException {

        // AJAX 요청 판별
        boolean isAjax = "XMLHttpRequest".equals(
            request.getHeader("X-Requested-With"))
            || request.getHeader("Accept") != null
               && request.getHeader("Accept").contains("application/json");

        if (isAjax) {
            // API/AJAX: JSON 응답
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                "{\"error\":\"SESSION_EXPIRED\",\"message\":\"세션이 만료되었습니다.\"}");
        } else {
            // 일반 웹: 리다이렉트
            response.sendRedirect("/session-timeout");
        }
    }
}
```

---

## ✨ 올바른 보안 구현

### 환경별 세션 타임아웃 설정

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(session -> session
        // 무효한 세션(타임아웃 등) 처리 전략
        .invalidSessionStrategy(new SmartInvalidSessionStrategy())
        // 세션 생성 정책
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        // 세션 고정 방어
        .sessionFixation(fixation -> fixation.changeSessionId())
    );
    return http.build();
}

// application.yml
// server:
//   servlet:
//     session:
//       timeout: 30m        # 30분 (단위 생략 시 초)
//       cookie:
//         http-only: true   # XSS 방어
//         secure: true      # HTTPS 전용
//         same-site: strict # CSRF 방어 보조
```

---

## 🔬 내부 동작 원리

### 1. 세션 타임아웃 발생 위치 — Servlet 컨테이너

```
세션 타임아웃은 Spring Security가 아닌 Servlet 컨테이너가 처리:

  Tomcat 내부:
    BackgroundProcess가 주기적으로(기본 60초마다) 세션 검사
    lastAccessedTime + maxInactiveInterval < 현재 시간 → 세션 만료
    HttpSession.invalidate() 호출
    → HttpSessionListener.sessionDestroyed() 이벤트 발행
    → HttpSessionEventPublisher → SessionRegistry 정리

  Spring Security가 타임아웃을 감지하는 시점:
    타임아웃 "순간"이 아닌
    만료된 세션 ID로 다음 요청이 올 때 감지
```

### 2. SessionManagementFilter — 무효 세션 감지 흐름

```java
// SessionManagementFilter.java
public class SessionManagementFilter extends GenericFilterBean {

    private final SecurityContextRepository securityContextRepository;
    private SessionAuthenticationStrategy sessionAuthenticationStrategy;
    private InvalidSessionStrategy invalidSessionStrategy;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                          FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        // ① 이미 이 필터가 처리했으면 스킵
        if (req.getAttribute(FILTER_APPLIED) != null) {
            chain.doFilter(request, response);
            return;
        }
        req.setAttribute(FILTER_APPLIED, Boolean.TRUE);

        // ② SecurityContextRepository에 SecurityContext가 없는가?
        //    (새 요청 or 세션 없는 요청)
        if (!securityContextRepository.containsContext(req)) {

            Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && !trustResolver.isAnonymous(authentication)) {
                // 인증된 사용자인데 SecurityContextRepository에 컨텍스트가 없음
                // → 세션이 만료되었을 가능성
                try {
                    sessionAuthenticationStrategy.onAuthentication(
                        authentication, req, (HttpServletResponse) response);
                } catch (SessionAuthenticationException ex) {
                    // ...
                    return;
                }
            } else {
                // ③ 무효한 세션 ID를 가진 요청인가?
                if (req.getRequestedSessionId() != null
                        && !req.isRequestedSessionIdValid()) {
                    // 세션 ID는 있지만 유효하지 않음 (타임아웃)
                    if (invalidSessionStrategy != null) {
                        invalidSessionStrategy.onInvalidSessionDetected(
                            req, (HttpServletResponse) response);
                        return; // 이후 처리 중단
                    }
                }
            }
        }
        chain.doFilter(request, response);
    }
}
```

### 3. 무효 세션 감지 조건 상세

```java
// req.getRequestedSessionId() != null
// → 클라이언트가 Cookie: JSESSIONID=XXX를 보냈음
// → 요청에 세션 ID가 포함됨

// !req.isRequestedSessionIdValid()
// → Servlet 컨테이너가 해당 세션 ID를 찾을 수 없음
// → 타임아웃으로 서버에서 삭제됨
// → 또는 서버 재시작으로 메모리에서 사라짐
// → 또는 distribute session에서 제거됨

// 두 조건 모두 충족할 때만 InvalidSessionStrategy 호출
// 조건 매트릭스:
// ┌─────────────────────────────┬──────────────────────────────────┐
// │ getRequestedSessionId()     │ isRequestedSessionIdValid()      │
// ├─────────────────────────────┼──────────────────────────────────┤
// │ null (쿠키 없음)              │ N/A → InvalidSession 호출 안 함    │
// │ XXX (쿠키 있음)               │ true → 유효한 세션 → 정상 처리        │
// │ XXX (쿠키 있음)               │ false → 무효 세션 → InvalidSession  │
// └─────────────────────────────┴──────────────────────────────────┘
```

### 4. 세션 타임아웃 vs 동시 세션 만료 처리 비교

```java
// 세션 타임아웃 처리 경로:
// 1. Tomcat이 세션 자동 만료 (maxInactiveInterval 초과)
// 2. JSESSIONID 쿠키가 있는 요청 도착
// 3. SessionManagementFilter: getRequestedSessionId() != null && !isValid()
// 4. InvalidSessionStrategy.onInvalidSessionDetected() → 리다이렉트/JSON 응답

// 동시 세션 만료(expireNow) 처리 경로:
// 1. 새 로그인으로 ConcurrentSessionControlAuthenticationStrategy → expireNow()
// 2. 기존 세션 ID로 요청 도착
// 3. ConcurrentSessionFilter: sessionRegistry.getSessionInformation(id).isExpired()
// 4. SessionInformationExpiredStrategy → /session-expired 리다이렉트

// 차이:
// 타임아웃: 세션 자체가 Servlet 컨테이너에서 삭제됨 → isRequestedSessionIdValid()=false
// 동시세션 만료: 세션은 여전히 유효하지만 expired 플래그만 설정됨
//               → isRequestedSessionIdValid()=true 지만 SessionRegistry에서 expired
```

### 5. 세션 타임아웃 이벤트 처리 전체 흐름

```
사용자 로그인 → JSESSIONID=S1 쿠키 발급
30분 비활동 → Tomcat 백그라운드 프로세스:
  S1 세션의 lastAccessedTime + maxInactiveInterval < now
  → S1.invalidate() 호출
  → HttpSessionListener.sessionDestroyed(event)
  → HttpSessionEventPublisher → HttpSessionDestroyedEvent
  → SessionRegistryImpl.removeSessionInformation(S1)

다음 요청 (JSESSIONID=S1):
  SecurityContextHolderFilter:
    HttpSessionSecurityContextRepository.loadContext()
    → req.getSession(false) → null (세션 없음)
    → SecurityContext 빈 것 사용

  SessionManagementFilter:
    req.getRequestedSessionId() → "S1" (쿠키 있음)
    req.isRequestedSessionIdValid() → false (세션 삭제됨)
    → InvalidSessionStrategy.onInvalidSessionDetected()
       → 웹: response.sendRedirect("/session-timeout")
       → API: response.setStatus(401) + JSON

  (InvalidSessionStrategy 호출 후 chain.doFilter 호출 안 됨 → 이후 필터 스킵)
```

### 6. 세션 타임아웃 값별 보안 권장사항

```java
// 타임아웃 설정 가이드:
// 금융/의료/고보안: 5~15분
// 일반 업무 시스템: 30분~1시간
// 쇼핑몰 등 상용 서비스: 1~8시간
// 관리자 페이지: 짧게 (15~30분)

// Spring Boot 설정:
// server.servlet.session.timeout=30m  (30분)
// server.servlet.session.timeout=1h   (1시간)
// server.servlet.session.timeout=0    (무제한 — 보안 위험, 금지)

// 세션 타임아웃 vs Remember-Me 구분:
// 세션 타임아웃: 브라우저 세션 내 비활동 시간 제한
// Remember-Me: 브라우저 재시작 후에도 유지되는 장기 인증
// → 짧은 세션 타임아웃 + Remember-Me 조합이 UX/보안 균형
```

---

## 💻 실험으로 확인하기

### 실험 1: 타임아웃 빠르게 확인하기

```java
// 테스트 환경에서 짧은 타임아웃 설정
# application-test.properties
server.servlet.session.timeout=10s  # 10초

// 또는 프로그래매틱 설정
@Bean
public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> sessionTimeout() {
    return factory -> factory.getSession().setTimeout(Duration.ofSeconds(10));
}
```

```bash
# 1. 로그인
curl -c cookies.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"

# 2. 즉시 접근 → 성공
curl -b cookies.txt http://localhost:8080/api/profile
# → 200 OK

# 3. 15초 대기 후 접근 → 세션 타임아웃
sleep 15
curl -b cookies.txt http://localhost:8080/api/profile
# → 401 {"error":"SESSION_EXPIRED"} (커스텀 전략 적용 시)
# → 302 /session-timeout (기본 전략 적용 시)
```

### 실험 2: isRequestedSessionIdValid() 조건 로깅

```java
@Component
@Slf4j
public class SessionDebugFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        String sessionId = request.getRequestedSessionId();
        if (sessionId != null) {
            log.debug("Session ID in request: {}, valid: {}",
                sessionId, request.isRequestedSessionIdValid());
        }
        chain.doFilter(request, response);
    }
}
// 타임아웃 후: "Session ID in request: S1, valid: false"
```

### 실험 3: 타임아웃 이벤트 감지

```java
@Component
@Slf4j
public class SessionLifecycleListener {

    @EventListener
    public void onSessionDestroyed(HttpSessionDestroyedEvent event) {
        List<SecurityContext> contexts = event.getSecurityContexts();
        contexts.stream()
            .map(SecurityContext::getAuthentication)
            .filter(Objects::nonNull)
            .forEach(auth ->
                log.info("[SESSION-EXPIRED] user={}, sessionId={}",
                    auth.getName(), event.getId()));
    }
}
```

---

## 🔒 보안 체크리스트

```
타임아웃 설정
  ☐ server.servlet.session.timeout 명시적 설정 (기본 30분 의존 금지)
  ☐ 관리자 페이지: 별도 SecurityFilterChain에서 짧은 타임아웃
  ☐ server.servlet.session.timeout=0 (무제한) 절대 금지

쿠키 보안
  ☐ server.servlet.session.cookie.http-only=true
  ☐ server.servlet.session.cookie.secure=true (HTTPS 환경)
  ☐ server.servlet.session.cookie.same-site=strict

타임아웃 처리
  ☐ InvalidSessionStrategy 설정
  ☐ API/AJAX 요청과 일반 웹 요청 구분 처리
  ☐ 타임아웃 메시지에 민감 정보 포함 금지

HttpSessionEventPublisher
  ☐ @Bean 등록 (SessionRegistry 정리)
  ☐ 세션 소멸 이벤트 리스닝 (감사 로그)
```

---

## 🤔 트레이드오프

```
짧은 타임아웃 vs 긴 타임아웃:
  짧은 타임아웃 (5~15분):
    장점  공용 PC, 탈취 세션 노출 시간 최소화
    단점  긴 작업 중 세션 만료 → 작업 중단 → UX 저하
    완화: 사용자 활동 시 세션 갱신 (AJAX heartbeat, sessionManagement().maximumSessions)

  긴 타임아웃 (1~8시간):
    장점  중단 없는 사용자 경험
    단점  방치된 세션이 오래 유효 → 보안 위험
    완화: Remember-Me 비활성화, HTTPS 강제, 민감 작업 재인증 요구

invalidSessionUrl vs invalidSessionStrategy:
  invalidSessionUrl:
    장점  설정 간단, HTML 리다이렉트로 충분한 경우
    단점  API/AJAX 요청에 HTML 응답 → 클라이언트 처리 불가

  invalidSessionStrategy:
    장점  요청 유형별 맞춤 응답 (JSON, 리다이렉트, WebSocket 메시지)
    단점  직접 구현 필요
```

---

## 📌 핵심 정리

```
세션 타임아웃 처리 레이어
  Servlet 컨테이너 (Tomcat): 비활동 시간 초과 시 세션 자동 삭제
  Spring Security (SessionManagementFilter): 삭제된 세션 ID로 요청 감지

SessionManagementFilter 감지 조건
  req.getRequestedSessionId() != null  → 쿠키에 세션 ID 있음
  && !req.isRequestedSessionIdValid()  → 그 세션이 서버에 없음
  → InvalidSessionStrategy.onInvalidSessionDetected() 호출

InvalidSessionStrategy 선택
  invalidSessionUrl: 단순 리다이렉트 (기본)
  커스텀 구현: API/AJAX 구분 → JSON 401 또는 HTML 리다이렉트

세션 타임아웃 vs 동시 세션 만료
  타임아웃: Servlet 컨테이너가 세션 삭제 → isRequestedSessionIdValid()=false
  동시 만료: SessionInformation.expired=true 플래그 → ConcurrentSessionFilter가 처리
```

---

## 🤔 생각해볼 문제

**Q1.** `SessionManagementFilter`는 `req.getRequestedSessionId() != null && !req.isRequestedSessionIdValid()`일 때 `InvalidSessionStrategy`를 호출합니다. 하지만 처음 방문하는 사용자(쿠키 없음)는 `getRequestedSessionId() == null`이므로 호출되지 않습니다. 로그인하지 않은 채로 30분 방치 후 접근하면 `InvalidSessionStrategy`가 호출되는가?

**Q2.** 세션 타임아웃을 30분으로 설정했는데, 사용자가 30분 이상 걸리는 긴 폼 작성 중 제출 버튼을 누르면 세션이 만료됩니다. 세션 갱신을 위한 AJAX heartbeat 패턴을 구현할 때 보안 고려사항은 무엇인가?

**Q3.** `@SessionScope` Bean을 사용하는 서비스가 있을 때 세션 타임아웃이 발생하면 해당 Bean의 소멸자(`@PreDestroy`)가 호출되는가? Spring의 Bean 생명주기와 세션 생명주기의 관계를 설명하라.

> 💡 **해설**
>
> **Q1.** 처음 방문하는 사용자는 쿠키가 없으므로 `getRequestedSessionId()` 가 `null`이고 `InvalidSessionStrategy`는 호출되지 않습니다. 로그인 없이 30분 방치 후 접근하는 경우, 만약 이전에 세션이 생성됐다면(예: 폼 입력 중 CSRF 토큰 발급을 위한 세션) 그 세션 ID가 쿠키에 남아있고 타임아웃으로 삭제됐을 것이므로 `InvalidSessionStrategy`가 호출됩니다. 처음 방문(쿠키 없음)이라면 호출되지 않으며 정상적으로 새 세션이 생성됩니다. 즉, `InvalidSessionStrategy`는 "세션이 있었는데 만료된" 경우에만 호출됩니다.
>
> **Q2.** AJAX heartbeat 보안 고려사항은 세 가지입니다. 첫째, heartbeat 엔드포인트에 CSRF 토큰 검증이 필요합니다(`GET` 대신 `POST` 방식, CSRF 토큰 포함). 둘째, heartbeat 응답에 민감 정보를 포함하지 않습니다. 셋째, heartbeat가 실제 사용자 활동이 없어도 세션을 무제한 연장할 수 있어 공격자가 탈취한 세션을 지속시킬 수 있습니다. 이를 방지하려면 heartbeat에도 최대 세션 생존 시간(`absoluteTimeout`)을 별도로 설정하거나, 사용자가 실제 UI와 상호작용할 때만 heartbeat를 보내도록 클라이언트를 구현합니다. 또한 heartbeat 엔드포인트에 rate limit을 적용합니다.
>
> **Q3.** `@SessionScope` Bean은 Spring의 세션 스코프를 따르며, 세션이 만료될 때 `DisposableBean.destroy()` 또는 `@PreDestroy` 메서드가 호출됩니다. 정확한 흐름은 `HttpSessionDestroyedEvent` → `SessionScope.cleanupScopeState()` → 해당 스코프의 Bean 소멸자 호출입니다. 단, 이 동작이 올바르게 이루어지려면 `HttpSessionEventPublisher`가 등록되어 있어야 `HttpSessionDestroyedEvent`가 Spring ApplicationContext로 전달됩니다. Servlet 컨테이너가 세션을 타임아웃으로 삭제할 때 Spring은 이를 이벤트로 받아 해당 세션 스코프 Bean들을 정리합니다. 다만 서버가 비정상 종료되면 소멸자가 호출되지 않을 수 있으므로, 중요한 리소스 해제는 소멸자에만 의존하지 않도록 설계해야 합니다.

---

<div align="center">

**[← 이전: Concurrent Session Control](./02-concurrent-session-control.md)** | **[홈으로 🏠](../README.md)** | **[다음: SessionRegistry 활용 ➡️](./04-session-registry.md)**

</div>
