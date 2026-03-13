# Session Fixation 공격과 방어 — changeSessionId()가 실행되는 정확한 시점

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- Session Fixation 공격의 구체적인 단계는 무엇이며 왜 위험한가?
- Spring Security가 인증 성공 후 세션을 교체하는 정확한 코드 경로는?
- `ChangeSessionIdAuthenticationStrategy`와 `NewSessionAuthenticationStrategy`의 차이는?
- `SessionFixationProtectionStrategy`가 세션 속성을 새 세션에 복사하는 이유는?
- `sessionFixation().none()`으로 방어를 비활성화해도 안전한 경우는 없는가?
- 세션 교체 후에도 세션 데이터(장바구니 등)가 유지되는 원리는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### Session Fixation 공격 전체 흐름

```
공격 시나리오:

  1단계: 공격자가 대상 서버에 접속해 유효한 Session ID 획득
     공격자 → GET http://bank.com
     서버 → Set-Cookie: JSESSIONID=ATTACKER_KNOWN_ID

  2단계: 공격자가 피해자에게 이 Session ID를 심는 방법
     링크: http://bank.com/login?jsessionid=ATTACKER_KNOWN_ID
     (URL 기반 세션 파라미터 허용 시)
     또는
     XSS로 document.cookie = "JSESSIONID=ATTACKER_KNOWN_ID"

  3단계: 피해자가 이 Session ID로 로그인
     피해자 → POST http://bank.com/login
              Cookie: JSESSIONID=ATTACKER_KNOWN_ID
     서버 → 인증 성공, ATTACKER_KNOWN_ID 세션에 사용자 정보 저장

  4단계: 공격자가 동일 Session ID로 피해자로 행동
     공격자 → GET http://bank.com/transfer
              Cookie: JSESSIONID=ATTACKER_KNOWN_ID
     서버 → ATTACKER_KNOWN_ID 세션 = 피해자의 인증 정보 포함 → 허용!

방어 핵심:
  로그인 성공 시 Session ID를 새 것으로 교체하면
  공격자가 알고 있는 ID는 무효화됨
  → 공격자가 같은 ID로 접속해도 인증 없는 새 세션에 불과
```

---

## 😱 흔한 보안 실수

### Before: sessionFixation().none()으로 방어 비활성화

```java
// ❌ 절대 금지: Session Fixation 방어 제거
http.sessionManagement(session -> session
    .sessionFixation(fixation -> fixation.none())
    // 인증 성공 후 Session ID 교체 안 함
    // → Session Fixation 공격에 완전 노출
);

// "SPA라서 쿠키 안 쓴다"는 이유로 비활성화 유혹:
// → URL 기반 세션 파라미터, 서브도메인 공격 등 다양한 벡터 존재
// → 방어 비용이 거의 없으므로 항상 활성화

// ✅ 기본값(changeSessionId) 유지
http.sessionManagement(session -> session
    .sessionFixation(fixation -> fixation.changeSessionId())
    // 또는 기본값이므로 sessionManagement 설정 자체 생략 가능
);
```

### Before: URL 기반 세션 파라미터 허용

```java
// ❌ Spring Boot에서 URL jsessionid 파라미터 허용 (기본값)
// http://site.com/page;jsessionid=FIXATED_ID
// → 공격자가 URL에 세션 ID 삽입 가능

// ✅ URL 세션 파라미터 비활성화 (web.xml 또는 Spring Boot 설정)
// application.properties:
// server.servlet.session.tracking-modes=cookie
// → 쿠키로만 세션 추적, URL 파라미터 무시

@Bean
public WebServerFactoryCustomizer<TomcatServletWebServerFactory> sessionTrackingMode() {
    return factory -> factory.addContextCustomizers(context ->
        context.setSessionTrackingModes(Set.of(SessionTrackingMode.COOKIE)));
}
```

---

## ✨ 올바른 보안 구현

### 세션 고정 방어 전략 선택

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(session -> session
        // ── 전략 1: changeSessionId (기본값, 권장) ───────────────────
        .sessionFixation(fixation -> fixation.changeSessionId())
        // Servlet 3.1+ HttpServletRequest.changeSessionId() 사용
        // 세션 ID만 새로 발급, 세션 데이터(속성) 보존
        // → 장바구니, SavedRequest 등 유지됨

        // ── 전략 2: migrateSession (Servlet 3.1 미만 호환) ──────────
        // .sessionFixation(fixation -> fixation.migrateSession())
        // 새 세션 생성 + 기존 속성을 새 세션에 복사
        // → changeSessionId()와 결과는 같지만 두 세션 객체 생성

        // ── 전략 3: newSession (기존 속성 삭제) ──────────────────────
        // .sessionFixation(fixation -> fixation.newSession())
        // 새 세션 생성, 기존 속성 복사 안 함 (Spring Security 속성만 복사)
        // → 장바구니 등 유실됨, 고보안 환경에서 고려

        // ── 전략 4: none (방어 없음, 절대 금지) ─────────────────────
        // .sessionFixation(fixation -> fixation.none())
    );
    return http.build();
}
```

---

## 🔬 내부 동작 원리

### 1. AbstractAuthenticationProcessingFilter에서 세션 교체 시점

```java
// AbstractAuthenticationProcessingFilter.java
// 인증 성공 후 → successfulAuthentication() 직전에 세션 교체

private void doFilter(HttpServletRequest request, HttpServletResponse response,
                       FilterChain chain) throws IOException, ServletException {
    try {
        Authentication authResult = attemptAuthentication(request, response);
        if (authResult == null) return;

        // ① 인증 성공 즉시 세션 교체
        // (successfulAuthentication() 호출 전에 실행)
        this.sessionStrategy.onAuthentication(authResult, request, response);

        // ② SecurityContext 저장, SuccessHandler 호출 등
        successfulAuthentication(request, response, chain, authResult);

    } catch (AuthenticationException ex) {
        unsuccessfulAuthentication(request, response, ex);
    }
}

// sessionStrategy는 CompositeSessionAuthenticationStrategy
// 여러 SessionAuthenticationStrategy의 체인
// 기본 구성:
// 1. ChangeSessionIdAuthenticationStrategy (세션 교체)
// 2. CsrfAuthenticationStrategy (CSRF 토큰 교체)
// 3. ConcurrentSessionControlAuthenticationStrategy (동시 세션 제한)
// 4. RegisterSessionAuthenticationStrategy (SessionRegistry 등록)
```

### 2. ChangeSessionIdAuthenticationStrategy — Servlet 3.1 방식

```java
// ChangeSessionIdAuthenticationStrategy.java
public final class ChangeSessionIdAuthenticationStrategy
        extends AbstractSessionFixationProtectionStrategy {

    @Override
    protected HttpSession applySessionFixation(HttpServletRequest request) {
        // Servlet 3.1: HttpServletRequest.changeSessionId()
        // 내부적으로 Tomcat/Jetty가 세션 저장소의 키를 새 ID로 교체
        // 세션 데이터(속성)는 그대로 유지됨
        request.changeSessionId();
        return request.getSession();
        // 반환된 세션은 같은 HttpSession 객체이지만 ID가 새 것
    }
}

// AbstractSessionFixationProtectionStrategy.java
public abstract class AbstractSessionFixationProtectionStrategy
        implements SessionAuthenticationStrategy {

    @Override
    public void onAuthentication(Authentication authentication,
                                  HttpServletRequest request,
                                  HttpServletResponse response) {

        HttpSession session = request.getSession(false); // 기존 세션 조회

        if (session == null) {
            // 세션 없으면 새 세션 생성 (보안 문제 없음)
            if (this.alwaysCreateSession) {
                request.getSession();
            }
            return;
        }

        // 기존 세션 ID 기록 (이벤트 발행용)
        String originalSessionId = session.getId();

        // 서브클래스에서 세션 교체 수행
        HttpSession newSession = applySessionFixation(request);

        // onSessionChange() 후크 호출
        onSessionChange(originalSessionId, newSession, authentication);
    }

    protected void onSessionChange(String originalSessionId,
                                    HttpSession newSession,
                                    Authentication auth) {
        // SessionFixationProtectionEvent 발행
        // → 로그, 감사 등에 활용
        if (this.applicationEventPublisher != null) {
            this.applicationEventPublisher.publishEvent(
                new SessionFixationProtectionEvent(auth, originalSessionId,
                    newSession.getId()));
        }
    }
}
```

### 3. SessionFixationProtectionStrategy (migrateSession) — 속성 복사

```java
// SessionFixationProtectionStrategy.java
public class SessionFixationProtectionStrategy
        extends AbstractSessionFixationProtectionStrategy {

    // true: Spring Security 속성만 복사 (장바구니 등 제거)
    // false: 모든 속성 복사 (기본값)
    private boolean migrateSessionAttributes = true;

    @Override
    protected HttpSession applySessionFixation(HttpServletRequest request) {
        HttpSession session = request.getSession();

        // 기존 세션의 모든 속성 추출
        List<String> attributesToMigrate = extractAttributes(session);
        Map<String, Object> attributesToMigrateMap = new HashMap<>();
        for (String attr : attributesToMigrate) {
            attributesToMigrateMap.put(attr, session.getAttribute(attr));
        }

        // 기존 세션 무효화 (보안: 기존 ID 완전 폐기)
        session.invalidate();

        // 새 세션 생성 (새 ID)
        HttpSession newSession = request.getSession(true);

        // 속성 복사
        attributesToMigrateMap.forEach(newSession::setAttribute);

        return newSession;
    }

    private List<String> extractAttributes(HttpSession session) {
        List<String> attrs = new ArrayList<>();
        Enumeration<String> names = session.getAttributeNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            // migrateSessionAttributes=false이면 Spring Security 관련 속성만 복사
            if (this.migrateSessionAttributes || name.startsWith("SPRING_SECURITY_")) {
                attrs.add(name);
            }
        }
        return attrs;
    }
}
```

### 4. 세션 교체 전후 타임라인

```
공격자: JSESSIONID=EVIL_ID 세션 생성
피해자: Cookie: JSESSIONID=EVIL_ID 상태로 로그인 시도

타임라인:
  t=0  POST /login (Cookie: JSESSIONID=EVIL_ID)
       UsernamePasswordAuthenticationFilter.attemptAuthentication()
       DaoAuthenticationProvider → 인증 성공 (Authentication 반환)

  t=1  AbstractAuthenticationProcessingFilter.sessionStrategy.onAuthentication()
       ChangeSessionIdAuthenticationStrategy.applySessionFixation()
       request.changeSessionId()
       → 서버: EVIL_ID 세션 → 새 세션 ID(SAFE_ID)로 키 변경
       → 클라이언트에 Set-Cookie: JSESSIONID=SAFE_ID 전송

  t=2  successfulAuthentication()
       SecurityContext.setAuthentication(인증된 사용자)
       HttpSession(SAFE_ID)에 SecurityContext 저장

  t=3  공격자가 EVIL_ID로 접근 시도
       Cookie: JSESSIONID=EVIL_ID
       → 서버에 EVIL_ID 세션 없음 → 새 익명 세션 발급
       → 피해자 세션 접근 불가 ✓
```

### 5. SessionFixationProtectionEvent 리스닝

```java
// 세션 교체 이벤트 감사 로그
@Component
@Slf4j
public class SessionFixationAuditListener {

    @EventListener
    public void onSessionFixationProtection(SessionFixationProtectionEvent event) {
        log.info("[SECURITY-AUDIT] Session Fixation Protection: " +
            "user={}, oldSessionId={}, newSessionId={}",
            event.getAuthentication().getName(),
            event.getOldSessionId(),
            event.getNewSessionId());
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 세션 ID 교체 확인

```bash
# 1. 로그인 전 세션 ID 획득
curl -c cookies_before.txt http://localhost:8080/login
BEFORE=$(grep JSESSIONID cookies_before.txt | awk '{print $7}')
echo "Before login: $BEFORE"

# 2. 로그인 수행
curl -c cookies_after.txt -b cookies_before.txt \
  -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"
AFTER=$(grep JSESSIONID cookies_after.txt | awk '{print $7}')
echo "After login: $AFTER"

# BEFORE != AFTER → 세션 ID 교체 확인
# changeSessionId: 세션 데이터 유지, ID만 변경
```

### 실험 2: 세션 교체 전략별 데이터 보존 확인

```java
@Test
void changeSessionId_preservesSessionAttributes() throws Exception {
    // given: 로그인 전 세션에 데이터 저장
    MockHttpSession session = new MockHttpSession();
    session.setAttribute("cart", List.of("item1", "item2"));

    // when: 로그인 수행
    MockHttpServletResponse response = mockMvc
        .perform(post("/login")
            .session(session)
            .param("username", "kim")
            .param("password", "1234"))
        .andReturn().getResponse();

    String newSessionId = extractSessionId(response);

    // then: 새 세션 ID로 접근 시 장바구니 유지
    mockMvc.perform(get("/cart").sessionAttr("cart", session.getAttribute("cart")))
        .andExpect(status().isOk());
    // newSession 전략 사용 시: cart 비어 있음
}
```

### 실험 3: Session Fixation 공격 시도 (방어 확인)

```bash
# 1. 공격자 세션 ID 획득
curl -c attacker.txt http://localhost:8080/
ATTACKER_ID=$(grep JSESSIONID attacker.txt | awk '{print $7}')

# 2. 피해자가 공격자 세션 ID로 로그인 (실제 공격 시나리오)
curl -c victim.txt -b "JSESSIONID=$ATTACKER_ID" \
  -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"

# 3. 공격자가 원래 ID로 접근 시도
curl -b "JSESSIONID=$ATTACKER_ID" http://localhost:8080/api/profile
# → 새 세션 발급됨 (인증 정보 없음) → 401 또는 로그인 리다이렉트
# → 방어 성공: 공격자 ID는 무효화됨 ✓
```

---

## 🔒 보안 체크리스트

```
세션 고정 방어
  ☐ sessionFixation().none() 절대 금지
  ☐ changeSessionId() (기본값) 유지 (Servlet 3.1+ 환경)
  ☐ Servlet 3.0 이하: migrateSession() 사용

URL 세션 파라미터 비활성화
  ☐ server.servlet.session.tracking-modes=cookie 설정
  ☐ ;jsessionid=XXX URL 파라미터 비활성화
  ☐ 로그에서 URL의 jsessionid 노출 방지

세션 쿠키 보안 속성
  ☐ HttpOnly: true (XSS로 쿠키 탈취 방지)
  ☐ Secure: true (HTTPS에서만 전송)
  ☐ SameSite: Strict 또는 Lax (CSRF 방어 보조)

감사 로그
  ☐ SessionFixationProtectionEvent 리스닝
  ☐ 비정상적인 세션 교체 패턴 모니터링
```

---

## 🤔 트레이드오프

```
changeSessionId vs migrateSession:
  changeSessionId (기본값):
    장점  Servlet 3.1 네이티브 → 세션 저장소 키만 변경
          단일 세션 객체 → 메모리 효율적
          분산 세션(Redis)에서 기존 세션 삭제 없이 ID 변경
    단점  Servlet 3.0 이하 미지원

  migrateSession:
    장점  Servlet 3.0 이하 호환
    단점  기존 세션 invalidate() + 새 세션 생성 → 두 번의 세션 저장소 I/O
          속성 복사 중 실패 시 데이터 손실 위험

changeSessionId vs newSession:
  changeSessionId:
    장점  세션 데이터(장바구니, SavedRequest) 보존 → UX 유지
  newSession:
    장점  로그인 전 세션 데이터 완전 격리 (혹시 모를 오염 방지)
    단점  SavedRequest 유실 → 로그인 전 접근 URL 복원 불가
          장바구니 등 UX 저하
    → 고보안 환경(금융, 의료)에서 미인증 데이터를 신뢰하지 않는 경우
```

---

## 📌 핵심 정리

```
Session Fixation 공격 원리
  공격자가 Session ID를 피해자에게 심기 → 피해자 로그인 후 공격자가 동일 ID 사용
  → 방어: 로그인 성공 시 Session ID 교체

Spring Security 방어 시점
  AbstractAuthenticationProcessingFilter.sessionStrategy.onAuthentication()
  → attemptAuthentication() 성공 직후, successfulAuthentication() 직전
  → ChangeSessionIdAuthenticationStrategy.applySessionFixation()
  → request.changeSessionId()

세 가지 방어 전략
  changeSessionId (기본): ID만 변경, 세션 데이터 유지
  migrateSession:         새 세션 생성 + 속성 복사
  newSession:             새 세션 생성, 속성 미복사

URL 세션 파라미터 제거
  ;jsessionid=XXX URL 파라미터 = 세션 고정 공격 주요 벡터
  server.servlet.session.tracking-modes=cookie로 차단
```

---

## 🤔 생각해볼 문제

**Q1.** `changeSessionId()`는 세션 저장소(메모리, Redis)에서 키만 변경합니다. 분산 환경에서 여러 서버가 Redis 세션 저장소를 공유할 때 `changeSessionId()`가 원자적으로 처리되지 않으면 어떤 레이스 컨디션이 발생할 수 있는가?

**Q2.** `newSession()` 전략을 사용하면 로그인 전에 저장된 `SavedRequest`(로그인 전 접근 URL)도 새 세션에 복사되지 않습니다. 그러면 로그인 성공 후 `SavedRequestAwareAuthenticationSuccessHandler`는 어떻게 동작하는가?

**Q3.** HTTPS 환경에서 `Secure` 쿠키 속성을 설정했어도 Session Fixation 공격이 가능한 시나리오가 있는가?

> 💡 **해설**
>
> **Q1.** 분산 Redis 세션에서 `changeSessionId()`는 내부적으로 기존 키 삭제 + 새 키 생성의 두 단계로 이루어집니다. 이 사이 짧은 순간에 같은 JSESSIONID로 다른 서버에 요청이 들어오면 기존 키는 이미 삭제됐고 새 키는 아직 클라이언트에게 전달되지 않아 세션을 찾지 못하는 상황이 발생할 수 있습니다. Spring Session의 경우 `RedisOperationsSessionRepository`가 이 과정을 처리하며, `RENAME` 명령으로 원자적으로 키를 변경합니다. 직접 Redis 세션을 구현하는 경우 RENAME 또는 Lua 스크립트로 원자성을 보장해야 합니다.
>
> **Q2.** `newSession()` 전략에서 새 세션은 기존 속성을 복사하지 않으므로 `HttpSessionRequestCache`에 저장된 `SavedRequest`도 유실됩니다. `SavedRequestAwareAuthenticationSuccessHandler`는 `requestCache.getRequest()`를 호출하지만 새 세션에 `SavedRequest`가 없으므로 `null`을 반환합니다. 그 결과 핸들러는 `defaultTargetUrl`(기본 `/`)로 리다이렉트합니다. 사용자는 원래 접근하려 했던 URL로 돌아가지 못합니다. 이 문제를 해결하려면 `SessionFixationProtectionStrategy`를 커스터마이징해 `SPRING_SECURITY_SAVED_REQUEST` 속성만 새 세션에 복사하는 방법을 고려할 수 있습니다.
>
> **Q3.** HTTPS + Secure 쿠키에서도 세션 고정 공격이 가능한 경우가 있습니다. 첫째, 동일 도메인의 서브도메인이 HTTP를 허용하면 서브도메인에서 쿠키를 설정해 상위 도메인에 전달할 수 있습니다(`domain=.example.com` 쿠키 범위). 둘째, URL 기반 세션 파라미터(`;jsessionid=`)를 허용하면 HTTPS와 무관하게 URL에 세션 ID를 삽입할 수 있습니다. 셋째, 사이트 내 XSS가 있으면 JavaScript로 쿠키 값을 읽거나 설정할 수 있습니다(HttpOnly가 없는 경우). 따라서 Secure 쿠키만으로는 충분하지 않으며 HttpOnly, SameSite, HSTS, URL 세션 파라미터 비활성화를 모두 조합해야 합니다.

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: Concurrent Session Control ➡️](./02-concurrent-session-control.md)**

</div>
