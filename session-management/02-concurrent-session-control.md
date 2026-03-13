# Concurrent Session Control — 동시 로그인 제한과 세션 만료 처리

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `maximumSessions(1)` 설정이 `SessionAuthenticationStrategy`와 어떻게 협력해 기존 세션을 만료시키는가?
- `ConcurrentSessionFilter`는 만료된 세션을 가진 요청을 어떻게 감지하고 처리하는가?
- `maxSessionsPreventsLogin(true)`와 `maxSessionsPreventsLogin(false)`(기본값)의 동작 차이는?
- `SessionRegistry`에 세션이 등록되는 시점은 어디이며 누가 담당하는가?
- 분산 환경(다중 서버)에서 Concurrent Session Control이 동작하려면 무엇이 필요한가?
- 사용자가 직접 로그아웃하지 않고 세션 타임아웃으로 세션이 만료되면 `SessionRegistry`는 어떻게 정리되는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 동시 로그인이 보안 위협이 되는 이유

```
시나리오:

  1. 사용자 kim이 PC에서 로그인 → 세션 A 생성
  2. 공격자가 kim의 자격증명으로 다른 기기에서 로그인 → 세션 B 생성
  3. kim의 세션 A가 유효한 상태에서 공격자의 세션 B도 동시에 유효
  4. kim이 비밀번호를 바꿔도 세션 B는 계속 유효할 수 있음

또는 라이선스 관점:
  스트리밍 서비스의 1인 1계정 정책 위반
  → 계정 공유 방지

Spring Security 해결책:
  maximumSessions(1) → 동일 사용자의 동시 세션 수 제한
  새 로그인 시:
    옵션 A: 기존 세션을 만료(expired) 처리 → 새 로그인 허용
    옵션 B: 새 로그인 자체를 차단 (이미 로그인된 경우 거부)
```

---

## 😱 흔한 보안 실수

### Before: SessionRegistry Bean 없이 Concurrent Session 설정

```java
// ❌ SessionRegistry를 @Bean으로 등록하지 않으면
//    각 SecurityFilterChain이 별도 SessionRegistry 인스턴스 사용
//    → 세션 조회/만료 기능이 올바르게 동작하지 않음

http.sessionManagement(session -> session
    .maximumSessions(1)
    // SessionRegistry를 명시하지 않으면 기본 InMemorySessionRegistry 사용
    // 관리자 페이지에서 세션 목록 조회 시 Bean 공유가 안 됨
);

// ✅ 공유 SessionRegistry Bean 명시적 등록
@Bean
public SessionRegistry sessionRegistry() {
    return new SessionRegistryImpl(); // InMemory (단일 서버용)
    // 다중 서버: SpringSessionBackedSessionRegistry 사용
}

@Bean
public SecurityFilterChain filterChain(HttpSecurity http,
                                        SessionRegistry sessionRegistry) throws Exception {
    http.sessionManagement(session -> session
        .maximumSessions(1)
        .sessionRegistry(sessionRegistry)
    );
    return http.build();
}
```

### Before: HttpSessionEventPublisher 미등록

```java
// ❌ HttpSessionEventPublisher 없이는 세션 타임아웃 시 SessionRegistry가 정리 안 됨

// ✅ 반드시 등록
@Bean
public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
    // HttpSession 생성/소멸 이벤트 → ApplicationContext 전달
    // → SessionRegistryImpl.onApplicationEvent() 호출
    // → 타임아웃 세션 자동 제거
}
// web.xml 방식:
// <listener>
//   <listener-class>
//     org.springframework.security.web.session.HttpSessionEventPublisher
//   </listener-class>
// </listener>
```

---

## ✨ 올바른 보안 구현

### 동시 세션 제어 완전한 설정

```java
@Configuration
@EnableWebSecurity
public class SessionSecurityConfig {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            SessionRegistry sessionRegistry) throws Exception {
        http
            .sessionManagement(session -> session
                .maximumSessions(1)
                    .sessionRegistry(sessionRegistry)
                    // false (기본): 새 로그인 시 기존 세션 만료, 새 로그인 허용
                    .maxSessionsPreventsLogin(false)
                    // 세션 만료 후 접근 시 리다이렉트 URL
                    .expiredUrl("/session-expired")
                .and()
                .sessionFixation(fixation -> fixation.changeSessionId())
            );
        return http.build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. ConcurrentSessionControlAuthenticationStrategy — 새 로그인 시 검사

```java
// ConcurrentSessionControlAuthenticationStrategy.java
public class ConcurrentSessionControlAuthenticationStrategy
        implements MessageSourceAware, SessionAuthenticationStrategy {

    private final SessionRegistry sessionRegistry;
    private boolean exceptionIfMaximumExceeded = false; // maxSessionsPreventsLogin
    private int maximumSessions = 1;

    @Override
    public void onAuthentication(Authentication authentication,
                                  HttpServletRequest request,
                                  HttpServletResponse response) {

        // ① 현재 사용자의 기존 세션 목록 조회
        List<SessionInformation> sessions = sessionRegistry
            .getAllSessions(authentication.getPrincipal(), false);

        int sessionCount = sessions.size();
        int allowedSessions = getMaximumSessionsForThisUser(authentication);

        if (sessionCount < allowedSessions) {
            return; // 아직 여유 있음 → 허용
        }

        if (allowedSessions == -1) {
            return; // 무제한
        }

        if (sessionCount == allowedSessions) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                // 현재 요청의 세션이 이미 등록된 세션 중 하나면 → 재로그인으로 허용
                for (SessionInformation si : sessions) {
                    if (si.getSessionId().equals(session.getId())) {
                        return;
                    }
                }
            }
            // 신규 세션: 허용된 수를 초과
        }

        if (exceptionIfMaximumExceeded) {
            // maxSessionsPreventsLogin=true: 새 로그인 자체를 차단
            throw new SessionAuthenticationException(
                messages.getMessage("ConcurrentSessionControlAuthenticationStrategy.exceededAllowed",
                    "Maximum sessions of " + allowedSessions + " for this principal exceeded"));
        }

        // maxSessionsPreventsLogin=false (기본): 기존 세션 중 가장 오래된 것 만료 처리
        allowableSessionsExceeded(sessions, allowedSessions, sessionRegistry);
    }

    protected void allowableSessionsExceeded(
            List<SessionInformation> sessions,
            int allowableSessions,
            SessionRegistry registry) {

        // 만료되지 않은 세션을 마지막 요청 시간 기준으로 정렬
        // 가장 오래된 세션(마지막 사용이 가장 오래된 것)을 만료 처리
        sessions.stream()
            .filter(s -> !s.isExpired())
            .sorted(Comparator.comparing(SessionInformation::getLastRequest))
            .limit(sessions.size() - allowableSessions + 1)
            .forEach(SessionInformation::expireNow);
        // expireNow(): SessionInformation.expired = true 플래그 설정
        // 실제 HttpSession.invalidate()가 아님 → 다음 요청 시 처리
    }
}
```

### 2. ConcurrentSessionFilter — 만료 세션 요청 처리

```java
// ConcurrentSessionFilter.java
// 필터 순서: 100 (초기에 실행 — 만료 세션 요청을 빠르게 차단)
public class ConcurrentSessionFilter extends GenericFilterBean {

    private final SessionRegistry sessionRegistry;
    private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                          FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpSession session = req.getSession(false);

        if (session != null) {
            // ① SessionRegistry에서 이 세션의 SessionInformation 조회
            SessionInformation info = sessionRegistry.getSessionInformation(session.getId());

            if (info != null) {
                if (info.isExpired()) {
                    // ② 만료된 세션 → 세션 무효화
                    doLogout(req, (HttpServletResponse) response);

                    // ③ 만료 전략 실행 (리다이렉트 또는 응답)
                    this.sessionInformationExpiredStrategy.onExpiredSessionDetected(
                        new SessionInformationExpiredEvent(info, req,
                            (HttpServletResponse) response, chain));
                    return; // 이후 필터 실행 안 함
                }

                // ④ 유효한 세션 → 마지막 요청 시간 갱신
                sessionRegistry.refreshLastRequest(session.getId());
            }
        }

        chain.doFilter(request, response);
    }

    private void doLogout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        this.handlers.logout(request, response, auth);
        // SecurityContext 클리어, RememberMe 쿠키 삭제 등
    }
}
```

### 3. RegisterSessionAuthenticationStrategy — 로그인 성공 시 세션 등록

```java
// RegisterSessionAuthenticationStrategy.java
// CompositeSessionAuthenticationStrategy의 마지막 단계
public class RegisterSessionAuthenticationStrategy
        implements SessionAuthenticationStrategy {

    private final SessionRegistry sessionRegistry;

    @Override
    public void onAuthentication(Authentication authentication,
                                  HttpServletRequest request,
                                  HttpServletResponse response) {
        // 인증 성공 후 새 세션을 SessionRegistry에 등록
        sessionRegistry.registerNewSession(
            request.getSession().getId(),
            authentication.getPrincipal()
        );
        // → SessionRegistryImpl.sessionIds에 (sessionId → SessionInformation) 저장
        // → SessionInformation: principal, lastRequest, expired=false
    }
}
```

### 4. 전체 플로우 ASCII 다이어그램

```
사용자 A (1차 로그인):
  POST /login → 인증 성공
  ConcurrentSessionControlAuthenticationStrategy.onAuthentication()
    → sessionRegistry.getAllSessions(userA, false) → []
    → 0 < 1 → 허용
  RegisterSessionAuthenticationStrategy.onAuthentication()
    → sessionRegistry.registerNewSession(sessionId=S1, principal=userA)
  SecurityContext 저장 → 세션 S1 생성

사용자 A (2차 로그인, maxSessionsPreventsLogin=false):
  POST /login → 인증 성공
  ConcurrentSessionControlAuthenticationStrategy.onAuthentication()
    → sessionRegistry.getAllSessions(userA, false) → [S1]
    → 1 == 1 (현재 세션은 신규) → 한도 초과
    → allowableSessionsExceeded()
       → S1.expireNow() → SessionInformation.expired = true

  RegisterSessionAuthenticationStrategy.onAuthentication()
    → sessionRegistry.registerNewSession(sessionId=S2, principal=userA)

기존 세션 S1의 다음 요청:
  GET /dashboard (Cookie: JSESSIONID=S1)
  ConcurrentSessionFilter.doFilter()
    → sessionRegistry.getSessionInformation(S1) → expired=true
    → doLogout() → session.invalidate()
    → sessionInformationExpiredStrategy
       → response.sendRedirect("/session-expired")
```

### 5. HttpSessionEventPublisher — 세션 타임아웃 자동 정리

```java
// HttpSessionEventPublisher.java
// Servlet의 HttpSessionListener 구현
public class HttpSessionEventPublisher implements HttpSessionListener {

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        // Spring ApplicationContext에 HttpSessionCreatedEvent 발행
        HttpSessionCreatedEvent e = new HttpSessionCreatedEvent(event.getSession());
        getContext(event.getSession()).publishEvent(e);
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        // 세션 타임아웃 또는 invalidate() 시 호출
        // → HttpSessionDestroyedEvent 발행
        HttpSessionDestroyedEvent e = new HttpSessionDestroyedEvent(event.getSession());
        getContext(event.getSession()).publishEvent(e);
        // → SessionRegistryImpl.onApplicationEvent()
        //    → sessionIds에서 해당 세션 제거
        //    → principals에서 해당 principal 제거
    }
}

// SessionRegistryImpl.onApplicationEvent():
@Override
public void onApplicationEvent(AbstractSessionEvent event) {
    if (event instanceof SessionDestroyedEvent) {
        String sessionId = event.getId();
        removeSessionInformation(sessionId);
        // SessionRegistry에서 완전히 제거
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 동시 세션 제한 확인

```bash
# 1차 로그인 (세션 S1 생성)
curl -c s1.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"

# 2차 로그인 (세션 S2 생성, S1 만료)
curl -c s2.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"

# S1으로 접근 → 만료된 세션
curl -b s1.txt http://localhost:8080/dashboard
# → 302 Redirect → /session-expired

# S2로 접근 → 정상
curl -b s2.txt http://localhost:8080/dashboard
# → 200 OK
```

### 실험 2: maxSessionsPreventsLogin=true 동작

```bash
# 1차 로그인 성공
curl -c s1.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"
# → 200 OK

# 2차 로그인 시도 → 거부
curl -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"
# → 302 Redirect → /login?error
# 에러 메시지: "Maximum sessions of 1 for this principal exceeded"
```

### 실험 3: 현재 로그인 사용자 목록 조회

```java
@GetMapping("/admin/sessions")
public List<SessionInfo> getActiveSessions() {
    return sessionRegistry.getAllPrincipals()
        .stream()
        .filter(p -> !sessionRegistry.getAllSessions(p, false).isEmpty())
        .map(principal -> {
            List<SessionInformation> sessions =
                sessionRegistry.getAllSessions(principal, false);
            return new SessionInfo(
                principal.toString(),
                sessions.stream()
                    .map(s -> new SessionDetail(
                        s.getSessionId(),
                        s.getLastRequest(),
                        s.isExpired()
                    ))
                    .collect(Collectors.toList())
            );
        })
        .collect(Collectors.toList());
}
```

---

## 🔒 보안 체크리스트

```
기본 설정
  ☐ SessionRegistry를 공유 @Bean으로 등록
  ☐ HttpSessionEventPublisher를 @Bean으로 등록 (세션 타임아웃 정리)
  ☐ maximumSessions 값을 비즈니스 요구사항에 맞게 설정

전략 선택
  ☐ maxSessionsPreventsLogin=false (기본): 새 로그인 허용, 기존 세션 만료
       → UX 우선, 비밀번호 탈취 후 공격자의 2차 로그인 차단
  ☐ maxSessionsPreventsLogin=true: 이미 로그인 시 새 로그인 차단
       → 계정 공유 방지, 금융/보안 서비스

분산 환경
  ☐ 다중 서버: SpringSessionBackedSessionRegistry 사용 (Spring Session 연동)
  ☐ InMemorySessionRegistry는 단일 서버에서만 유효

세션 만료 처리
  ☐ expiredUrl 설정 (사용자 친화적 메시지)
  ☐ API 환경: SimpleRedirectSessionInformationExpiredStrategy 대신 JSON 응답 커스터마이징
```

---

## 🤔 트레이드오프

```
maxSessionsPreventsLogin false vs true:
  false (기본 — 기존 세션 만료):
    장점  다른 기기에서 로그인 시 이전 세션 자동 종료 → 잊고 켜둔 세션 정리
          새 로그인은 항상 가능 → UX 부드러움
    단점  비밀번호 탈취 시 공격자가 정상 사용자 로그인 가능
          피해자가 다음 요청 시 "/session-expired"로 알게 됨

  true (새 로그인 차단):
    장점  이미 로그인된 경우 새 로그인 불가 → 계정 공유 방지
          기존 세션 보호 (탈취된 자격증명으로 로그인 불가)
    단점  사용자가 이전 세션을 로그아웃하지 않으면 새 기기에서 로그인 불가
          "이미 로그인됨" 메시지 → 혼란 유발

InMemorySessionRegistry vs SpringSessionBackedSessionRegistry:
  InMemory:
    장점  별도 의존성 없음, 단순
    단점  서버 메모리에 저장 → 서버 재시작 시 모든 세션 정보 손실
          다중 서버에서 세션 공유 불가 → 동시 세션 제한 동작 안 함

  SpringSessionBackedSessionRegistry (Redis 등):
    장점  분산 환경에서 동시 세션 제한 동작
    단점  Spring Session 의존성 추가 필요
```

---

## 📌 핵심 정리

```
동시 세션 제어 흐름
  로그인 성공 → ConcurrentSessionControlAuthenticationStrategy
    → 기존 세션 수 초과 시:
       maxSessionsPreventsLogin=false → 기존 세션 expireNow()
       maxSessionsPreventsLogin=true → SessionAuthenticationException (로그인 차단)
  → RegisterSessionAuthenticationStrategy → SessionRegistry에 새 세션 등록

만료 세션 감지
  ConcurrentSessionFilter (순서 100 — 매 요청 초기에)
  → SessionRegistry.getSessionInformation(sessionId).isExpired()
  → true → 세션 무효화 + expiredUrl 리다이렉트

SessionRegistry 정리
  명시적 로그아웃 → LogoutHandler가 removeSessionInformation()
  세션 타임아웃 → HttpSessionEventPublisher → sessionDestroyed 이벤트
               → SessionRegistryImpl.removeSessionInformation()

필수 설정 세 가지
  ① @Bean SessionRegistry (공유)
  ② @Bean HttpSessionEventPublisher (타임아웃 정리)
  ③ 분산 환경: SpringSessionBackedSessionRegistry
```

---

## 🤔 생각해볼 문제

**Q1.** `maxSessionsPreventsLogin(false)` 설정에서 `allowableSessionsExceeded()`는 기존 세션을 `expireNow()`로 표시합니다. 이것은 실제 `HttpSession.invalidate()`가 아닌 플래그 설정입니다. 기존 세션에서 다음 요청이 올 때까지 `HttpSession`은 서버 메모리에 계속 남아있습니다. 이것이 메모리 문제가 될 수 있는 시나리오와 해결 방법은?

**Q2.** 사용자가 브라우저의 "탭 복제" 기능으로 같은 세션을 두 탭에서 사용하고 있을 때, 한 탭에서 `maximumSessions(1)` 설정으로 세션이 만료되면 다른 탭도 즉시 영향을 받는가?

**Q3.** Spring Security의 `ConcurrentSessionFilter`는 `SessionRegistry`를 통해 만료 여부를 확인합니다. 분산 환경에서 서버 A에서 세션이 만료 처리됐을 때, 서버 B에서 같은 세션으로 요청이 오면 올바르게 처리되는가? 어떤 조건에서 가능하고 불가능한가?

> 💡 **해설**
>
> **Q1.** `expireNow()`는 `SessionInformation.expired = true` 플래그만 설정하고 실제 `HttpSession.invalidate()`는 호출하지 않습니다. 따라서 기존 세션은 서버 메모리에 그대로 남아있다가 세션 타임아웃(기본 30분)이 돼야 정리됩니다. 공격자가 의도적으로 새 로그인을 반복해 기존 세션들을 `expired` 상태로 만들면 실제 메모리 해제 없이 `SessionInformation` 객체가 쌓입니다. 해결 방법으로는 `ConcurrentSessionControlAuthenticationStrategy.allowableSessionsExceeded()`를 오버라이드해 `expireNow()` 후 즉시 `session.invalidate()`를 호출하거나, 세션 타임아웃을 짧게 설정하거나, 스케줄러로 만료된 세션을 주기적으로 강제 정리합니다.
>
> **Q2.** 두 탭은 동일한 `JSESSIONID` 쿠키를 공유하므로 같은 세션입니다. 한 탭에서 세션이 만료된 것이 아니라, 해당 사용자의 `SessionInformation`에 `expired=true` 플래그가 설정된 것입니다. 두 탭 모두 같은 세션 ID를 사용하므로, 어느 탭에서 다음 요청을 보내든 `ConcurrentSessionFilter`가 `SessionRegistry`에서 `expired=true`를 감지해 두 탭 모두 `/session-expired`로 리다이렉트됩니다. 즉, 한 탭이 "만료된 것"이 아니라 세션 자체가 만료 표시된 것이므로 두 탭 모두 즉시 영향을 받습니다.
>
> **Q3.** `InMemorySessionRegistry`를 사용하는 단일 서버 환경에서는 서버 A의 메모리에서만 만료 처리되므로 서버 B의 메모리에는 `expired=false` 상태로 남아있어 서버 B에서는 만료를 감지하지 못합니다. 분산 환경에서 올바르게 동작하려면 `SpringSessionBackedSessionRegistry`(Spring Session + Redis)를 사용해야 합니다. 이 경우 Redis에 `SessionInformation`을 저장하므로 서버 A에서 `expireNow()`로 Redis의 `expired` 플래그를 `true`로 변경하면, 서버 B에서도 Redis를 조회해 `expired=true`를 확인하고 올바르게 세션을 만료 처리합니다.

---

<div align="center">

**[← 이전: Session Fixation 공격과 방어](./01-session-fixation-attack.md)** | **[홈으로 🏠](../README.md)** | **[다음: Session Timeout 처리 ➡️](./03-session-timeout.md)**

</div>
