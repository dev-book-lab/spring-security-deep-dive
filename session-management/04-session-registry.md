# SessionRegistry 활용 — 세션 목록 조회와 강제 종료 구현

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `SessionRegistry`의 `getAllPrincipals()`와 `getAllSessions()` 메서드가 반환하는 데이터 구조는?
- `SessionInformation.expireNow()`가 호출된 후 실제 세션이 무효화되는 시점은 언제인가?
- 관리자가 특정 사용자의 모든 세션을 강제 종료하는 코드를 어떻게 구현하는가?
- `SessionRegistryImpl`의 데이터 구조와 스레드 안전성 구현 방식은?
- 분산 환경에서 `SessionRegistry`를 공유하려면 어떤 구현체를 사용해야 하는가?
- `SessionRegistry`에서 `includeExpiredSessions` 파라미터의 의미는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### SessionRegistry가 제공하는 가시성

```
SessionRegistry 없이는 알 수 없는 것들:
  - 현재 몇 명이 로그인 중인가?
  - 특정 사용자가 어디서(IP) 로그인 중인가?
  - 사용자 A가 로그인한 지 얼마나 됐는가?
  - 동시에 로그인된 기기 목록은?

관리 기능에 필수:
  관리자 대시보드:
    → 현재 활성 사용자 수 및 목록
    → 특정 사용자 강제 로그아웃
    → 의심스러운 세션 즉시 종료

보안 운영:
    → 비정상 로그인 감지 후 해당 세션 즉시 종료
    → 비밀번호 변경 후 다른 기기 세션 전체 종료
    → 계정 정지 시 기존 세션 즉시 무효화
```

---

## 😱 흔한 보안 실수

### Before: 강제 종료 후 기존 세션 쿠키 악용

```java
// ❌ 문제: expireNow()는 SessionInformation 플래그만 설정
//    → ConcurrentSessionFilter가 처리하기 전까지 실제 세션은 유효

@PostMapping("/admin/force-logout/{userId}")
public void forceLogout(@PathVariable Long userId) {
    sessionRegistry.getAllSessions(getPrincipal(userId), false)
        .forEach(SessionInformation::expireNow);
    // expireNow() 후 즉시 invalidate()를 안 하면:
    // 해당 세션으로 ConcurrentSessionFilter가 없는 엔드포인트 접근 시 여전히 유효
    // (예: /actuator/health 같은 경로가 ConcurrentSessionFilter 체인에서 제외된 경우)
}

// ✅ expireNow() + 즉시 invalidate() 조합
@PostMapping("/admin/force-logout/{userId}")
public ResponseEntity<Void> forceLogout(@PathVariable Long userId,
                                         HttpServletRequest request) {
    Object principal = getUserPrincipal(userId);
    sessionRegistry.getAllSessions(principal, false)
        .forEach(sessionInfo -> {
            sessionInfo.expireNow(); // 플래그 설정 (ConcurrentSessionFilter 처리용)
            // 세션 직접 무효화 (즉시 효과)
            HttpSession session = getSession(sessionInfo.getSessionId());
            if (session != null) {
                session.invalidate();
            }
        });
    return ResponseEntity.noContent().build();
}
```

### Before: includeExpiredSessions의 의미 오해

```java
// ❌ getAllSessions(principal, true)가 "모든 세션"을 반환한다고 오해
List<SessionInformation> allSessions =
    sessionRegistry.getAllSessions(principal, true);
// true = 만료(expired) 플래그가 설정된 세션도 포함
// 실제 의미: expireNow()가 호출됐지만 아직 invalidate()가 안 된 세션들도 포함
// "삭제된 세션 포함"이 아님!
// 이미 invalidate()된 세션은 SessionRegistry에서 제거됨

// ✅ 올바른 사용
List<SessionInformation> activeSessions =
    sessionRegistry.getAllSessions(principal, false);
// false = 만료 플래그가 없는 세션만 (실제 활성 세션)
```

---

## ✨ 올바른 보안 구현

### 관리자 세션 관리 기능 전체 구현

```java
@RestController
@RequestMapping("/admin/sessions")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class SessionManagementController {

    private final SessionRegistry sessionRegistry;
    private final UserRepository userRepository;

    // 현재 로그인한 모든 사용자 목록
    @GetMapping
    public List<ActiveUserDto> getActiveSessions() {
        return sessionRegistry.getAllPrincipals()
            .stream()
            .flatMap(principal -> {
                List<SessionInformation> sessions =
                    sessionRegistry.getAllSessions(principal, false);
                return sessions.stream()
                    .map(session -> ActiveUserDto.builder()
                        .username(getPrincipalName(principal))
                        .sessionId(maskSessionId(session.getSessionId()))
                        .lastRequest(session.getLastRequest())
                        .expired(session.isExpired())
                        .build());
            })
            .collect(Collectors.toList());
    }

    // 특정 사용자의 모든 세션 강제 종료
    @DeleteMapping("/users/{username}")
    public ResponseEntity<Void> forceLogoutUser(@PathVariable String username) {
        Object principal = findPrincipalByUsername(username);
        if (principal == null) {
            return ResponseEntity.notFound().build();
        }

        List<SessionInformation> sessions =
            sessionRegistry.getAllSessions(principal, false);

        sessions.forEach(session -> {
            session.expireNow();
            // SessionRegistry에서 즉시 제거
            sessionRegistry.removeSessionInformation(session.getSessionId());
        });

        log.warn("[ADMIN-AUDIT] Force logout: admin={}, target={}",
            SecurityContextHolder.getContext().getAuthentication().getName(),
            username);

        return ResponseEntity.noContent().build();
    }

    // 특정 세션 ID 강제 종료
    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> forceLogoutSession(@PathVariable String sessionId) {
        SessionInformation session = sessionRegistry.getSessionInformation(sessionId);
        if (session == null) {
            return ResponseEntity.notFound().build();
        }
        session.expireNow();
        return ResponseEntity.noContent().build();
    }

    // 현재 활성 세션 수 (대시보드용)
    @GetMapping("/count")
    public Map<String, Long> getSessionCount() {
        long total = sessionRegistry.getAllPrincipals()
            .stream()
            .mapToLong(p -> sessionRegistry.getAllSessions(p, false).size())
            .sum();
        return Map.of("activeSessionCount", total);
    }

    // 세션 ID 마스킹 (보안: 전체 노출 방지)
    private String maskSessionId(String sessionId) {
        if (sessionId.length() <= 8) return "****";
        return sessionId.substring(0, 4) + "****" + sessionId.substring(sessionId.length() - 4);
    }
}
```

---

## 🔬 내부 동작 원리

### 1. SessionRegistryImpl 데이터 구조

```java
// SessionRegistryImpl.java
public class SessionRegistryImpl implements SessionRegistry,
        ApplicationListener<AbstractSessionEvent> {

    // 세션 ID → SessionInformation 매핑
    // ConcurrentHashMap: 스레드 안전
    private final ConcurrentMap<String, SessionInformation> sessionIds =
        new ConcurrentHashMap<>();

    // Principal → 세션 ID Set 매핑
    // CopyOnWriteArraySet: 읽기 다수 / 쓰기 소수 환경에 최적
    private final ConcurrentMap<Object, Set<String>> principals =
        new ConcurrentHashMap<>();

    @Override
    public List<Object> getAllPrincipals() {
        return List.copyOf(principals.keySet());
    }

    @Override
    public List<SessionInformation> getAllSessions(Object principal,
                                                    boolean includeExpiredSessions) {
        Set<String> sessionsUsedByPrincipal = principals.get(principal);
        if (sessionsUsedByPrincipal == null) return List.of();

        return sessionsUsedByPrincipal.stream()
            .map(sessionIds::get)
            .filter(Objects::nonNull)
            .filter(s -> includeExpiredSessions || !s.isExpired())
            .collect(Collectors.toList());
    }

    @Override
    public void registerNewSession(String sessionId, Object principal) {
        // 기존 세션이 있으면 제거 (세션 ID 교체 시)
        if (getSessionInformation(sessionId) != null) {
            removeSessionInformation(sessionId);
        }

        sessionIds.put(sessionId,
            new SessionInformation(principal, sessionId, new Date()));

        principals.compute(principal, (key, existingSessions) -> {
            if (existingSessions == null) {
                existingSessions = new CopyOnWriteArraySet<>();
            }
            existingSessions.add(sessionId);
            return existingSessions;
        });
    }

    @Override
    public void removeSessionInformation(String sessionId) {
        SessionInformation info = getSessionInformation(sessionId);
        if (info == null) return;

        sessionIds.remove(sessionId);

        // principal 목록에서 이 세션 제거
        Set<String> sessionsForPrincipal = principals.get(info.getPrincipal());
        if (sessionsForPrincipal != null) {
            sessionsForPrincipal.remove(sessionId);
            // principal의 세션이 모두 없어지면 principal도 제거
            if (sessionsForPrincipal.isEmpty()) {
                principals.remove(info.getPrincipal());
            }
        }
    }

    @Override
    public void refreshLastRequest(String sessionId) {
        SessionInformation info = getSessionInformation(sessionId);
        if (info != null) {
            info.refreshLastRequest(); // lastRequest = new Date()
        }
    }

    // HttpSessionDestroyedEvent → 세션 정보 자동 제거
    @Override
    public void onApplicationEvent(AbstractSessionEvent event) {
        if (event instanceof SessionDestroyedEvent) {
            removeSessionInformation(event.getId());
        }
    }
}
```

### 2. SessionInformation — expireNow() 메커니즘

```java
// SessionInformation.java
public class SessionInformation implements Serializable {

    private Date lastRequest;
    private final Object principal;
    private final String sessionId;
    private boolean expired = false; // volatile로 변경 불가, 직접 수정만

    public void expireNow() {
        this.expired = true;
        // ✓ SessionRegistry의 sessionIds에서 제거하지 않음
        // ✓ 실제 HttpSession.invalidate() 호출하지 않음
        // ✓ 오직 expired 플래그만 true로 설정

        // ConcurrentSessionFilter가 다음 요청 시 expired=true 감지
        // → HttpSession.invalidate() 실행
        // → SessionInformationExpiredStrategy 호출 (리다이렉트 등)
    }

    public void refreshLastRequest() {
        this.lastRequest = new Date();
    }
}
```

### 3. 비밀번호 변경 후 다른 세션 전체 무효화 패턴

```java
@Service
@RequiredArgsConstructor
public class UserSecurityService {

    private final SessionRegistry sessionRegistry;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Transactional
    public void changePassword(String username, String newPassword,
                                HttpServletRequest currentRequest) {
        User user = userRepository.findByUsername(username).orElseThrow();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // 현재 세션 ID (비밀번호 변경 요청을 한 세션)
        String currentSessionId = currentRequest.getSession().getId();

        // 현재 사용자의 모든 세션 조회
        Object principal = getUserPrincipal(username);
        sessionRegistry.getAllSessions(principal, false)
            .stream()
            // 현재 세션은 유지 (현재 기기에서는 계속 사용)
            .filter(session -> !session.getSessionId().equals(currentSessionId))
            .forEach(session -> {
                session.expireNow();
                log.info("[SECURITY] Session expired after password change: " +
                    "user={}, sessionId={}", username,
                    maskSessionId(session.getSessionId()));
            });
    }
}
```

### 4. SpringSessionBackedSessionRegistry — 분산 환경

```java
// Spring Session + Redis를 사용한 분산 SessionRegistry
// Spring Session 의존성: spring-session-data-redis

@Configuration
@EnableRedisHttpSession
public class DistributedSessionConfig {

    // SpringSessionBackedSessionRegistry:
    // → getAllPrincipals(): Redis에서 조회
    // → getAllSessions(): Redis에서 조회
    // → expireNow(): Redis의 세션 정보 업데이트
    // → 모든 서버가 같은 Redis를 보므로 분산 환경에서 동작

    @Bean
    public SpringSessionBackedSessionRegistry<?> sessionRegistry(
            FindByIndexNameSessionRepository<?> sessionRepository) {
        return new SpringSessionBackedSessionRegistry<>(sessionRepository);
    }
}

// FindByIndexNameSessionRepository 사용:
// → Spring Session이 PRINCIPAL_NAME_INDEX_NAME으로 세션 인덱싱
// → username으로 세션 목록 조회 가능
// Redis 키 구조:
// spring:session:sessions:{sessionId} → 세션 데이터
// spring:session:index:{principal}    → 세션 ID Set
```

---

## 💻 실험으로 확인하기

### 실험 1: 현재 로그인 사용자 목록 API 테스트

```bash
# 여러 계정으로 로그인 후
curl -H "Authorization: Bearer <admin-token>" \
  http://localhost:8080/admin/sessions
# 응답:
# [
#   {"username":"kim","sessionId":"abcd****efgh","lastRequest":"2024-01-01T10:00:00"},
#   {"username":"lee","sessionId":"wxyz****mnop","lastRequest":"2024-01-01T10:05:00"}
# ]

curl -H "Authorization: Bearer <admin-token>" \
  http://localhost:8080/admin/sessions/count
# {"activeSessionCount": 2}
```

### 실험 2: 강제 로그아웃 후 동작 확인

```bash
# 1. kim으로 로그인
curl -c kim.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"

# 2. kim이 리소스 접근 (정상)
curl -b kim.txt http://localhost:8080/api/orders
# → 200 OK

# 3. 관리자가 kim 강제 로그아웃
curl -X DELETE -H "Authorization: Bearer <admin-token>" \
  http://localhost:8080/admin/sessions/users/kim
# → 204 No Content

# 4. kim의 기존 세션으로 접근 → 만료됨
curl -b kim.txt http://localhost:8080/api/orders
# → 302 /session-expired 또는 401
```

### 실험 3: SessionInformation 데이터 확인

```java
@GetMapping("/debug/my-session")
public Map<String, Object> mySessionInfo(Authentication authentication,
                                          HttpServletRequest request) {
    String sessionId = request.getSession().getId();
    SessionInformation info = sessionRegistry.getSessionInformation(sessionId);
    return Map.of(
        "sessionId", maskSessionId(sessionId),
        "lastRequest", info != null ? info.getLastRequest() : "unknown",
        "isExpired", info != null ? info.isExpired() : false
    );
}
```

---

## 🔒 보안 체크리스트

```
SessionRegistry 관리
  ☐ 세션 ID를 API 응답에 노출 시 마스킹 처리
  ☐ 관리자 엔드포인트에 @PreAuthorize("hasRole('ADMIN')") 적용
  ☐ 강제 로그아웃 작업은 감사 로그 기록

데이터 정확도
  ☐ HttpSessionEventPublisher @Bean 등록 (타임아웃 세션 자동 정리)
  ☐ 분산 환경: SpringSessionBackedSessionRegistry 사용
  ☐ InMemorySessionRegistry의 메모리 누수 주기 모니터링

강제 종료 구현
  ☐ expireNow() 후 즉시 invalidate()를 같이 호출 (즉각적 효과)
  ☐ 비밀번호 변경 → 다른 기기 세션 전체 만료
  ☐ 계정 정지 → 모든 세션 즉시 만료 + SessionRegistry 제거
```

---

## 🤔 트레이드오프

```
InMemorySessionRegistry vs SpringSessionBackedSessionRegistry:
  InMemory:
    장점  설정 간단, 추가 인프라 없음
    단점  단일 서버에서만 유효, 서버 재시작 시 정보 소실
          메모리 사용량 증가 (세션 많을수록)

  SpringSessionBackedSessionRegistry (Redis):
    장점  분산 환경 지원, 영속적 세션 정보
          Spring Session의 index 기능으로 빠른 조회
    단점  Redis 의존성, 네트워크 지연, 추가 설정

expireNow() vs 즉시 invalidate():
  expireNow()만:
    장점  ConcurrentSessionFilter와 일관된 처리
    단점  다음 요청이 올 때까지 세션이 메모리에 유지
          ConcurrentSessionFilter가 없는 경로로 접근 시 효과 없음

  expireNow() + invalidate():
    장점  즉각적인 세션 무효화, 메모리 즉시 해제
    단점  HttpSession 참조가 필요 (SessionId → HttpSession 조회 구현 필요)
```

---

## 📌 핵심 정리

```
SessionRegistryImpl 데이터 구조
  sessionIds: ConcurrentHashMap<sessionId, SessionInformation>
  principals: ConcurrentHashMap<principal, CopyOnWriteArraySet<sessionId>>

주요 메서드
  getAllPrincipals()           → 현재 등록된 모든 principal
  getAllSessions(p, false)     → 활성(만료 플래그 없는) 세션 목록
  getAllSessions(p, true)      → 만료 플래그 포함 모든 세션
  getSessionInformation(id)   → 특정 세션의 SessionInformation
  refreshLastRequest(id)      → 마지막 요청 시간 갱신
  removeSessionInformation(id)→ SessionRegistry에서 완전 제거
  expireNow()                 → 만료 플래그 설정 (실제 invalidate 아님)

강제 로그아웃 패턴
  getAllSessions(principal, false)
  → 각 session.expireNow()  → ConcurrentSessionFilter 처리
  → 즉각 효과 필요 시: invalidate()도 함께 호출
  → 비밀번호 변경: 현재 세션 제외 나머지 만료

분산 환경
  SpringSessionBackedSessionRegistry + Spring Session + Redis
  → 모든 서버가 동일 Redis를 보므로 전체 세션 관리 가능
```

---

## 🤔 생각해볼 문제

**Q1.** `SessionRegistryImpl`은 `principals` Map에 실제 `principal` 객체를 키로 사용합니다. `UserDetails`를 구현한 커스텀 클래스가 `equals()`와 `hashCode()`를 오버라이드하지 않으면 어떤 문제가 발생하는가?

**Q2.** 관리자가 `expireNow()`로 사용자 세션을 만료시켰습니다. 그 사용자가 만료된 세션으로 다음 요청을 보내기 전에 비밀번호를 변경하면, 만료된 세션 정보는 `SessionRegistry`에 언제까지 남아 있는가?

**Q3.** `SpringSessionBackedSessionRegistry`를 사용하는 분산 환경에서 Redis가 일시적으로 다운됐을 때, 로그인한 사용자의 요청 처리와 강제 로그아웃 기능은 어떻게 동작하는가? 장애 복구 설계 방법은?

> 💡 **해설**
>
> **Q1.** `SessionRegistryImpl.principals`는 `principal` 객체를 `Map` 키로 사용합니다. Java `HashMap`/`ConcurrentHashMap`은 키의 `equals()`와 `hashCode()`에 의존합니다. 커스텀 `UserDetails` 구현체가 이를 오버라이드하지 않으면 기본 `Object.equals()`(참조 동일성 비교)가 사용됩니다. 로그인 후 새 `UserDetails` 객체가 생성될 때마다 같은 사용자도 다른 키로 인식됩니다. 결과적으로 같은 사용자의 세션이 `principals` Map에 여러 개의 다른 키로 쌓이고, `getAllSessions()`에서 이전 세션을 찾지 못하게 됩니다. 동시 세션 제한도 올바르게 동작하지 않습니다. `UserDetails` 구현 시 반드시 `username` 기반으로 `equals()`와 `hashCode()`를 구현해야 합니다.
>
> **Q2.** `expireNow()`는 `SessionInformation.expired = true` 플래그만 설정하고 `SessionRegistry`에서 제거하지 않습니다. 세션이 `SessionRegistry`에서 제거되는 시점은 실제 `HttpSession.invalidate()`가 호출되고 `HttpSessionDestroyedEvent`가 발행될 때입니다. 사용자가 만료된 세션으로 다음 요청을 보내면 `ConcurrentSessionFilter`가 `session.invalidate()`를 호출하고 그 시점에 이벤트가 발행되어 `SessionRegistry`에서 제거됩니다. 사용자가 다음 요청을 보내지 않으면 세션 타임아웃(Tomcat의 `maxInactiveInterval`)이 지나야 Tomcat이 세션을 삭제하고 이벤트가 발행됩니다. 비밀번호 변경은 이 흐름과 무관합니다.
>
> **Q3.** Redis 다운 시 `SpringSessionBackedSessionRegistry`의 Redis 접근이 실패합니다. 로그인한 사용자의 요청 처리에서 `ConcurrentSessionFilter`가 `sessionRegistry.getSessionInformation()`을 호출할 때 Redis 접근 실패로 예외가 발생하거나 `null`을 반환합니다. `null` 반환 시 만료 체크를 건너뛰고 정상 처리됩니다. 강제 로그아웃은 Redis에 쓰기가 실패하므로 동작하지 않습니다. 장애 복구 설계로는 Redis Sentinel 또는 Cluster로 고가용성 구성, Circuit Breaker 패턴(Redis 장애 시 로컬 인메모리로 임시 폴백), Spring Session의 `flush-mode=immediate` + connection timeout 짧게 설정으로 빠른 장애 감지, 그리고 강제 로그아웃이 실패한 경우를 감사 로그에 기록하고 재시도 큐에 등록하는 방법이 있습니다.

---

<div align="center">

**[← 이전: Session Timeout 처리](./03-session-timeout.md)** | **[홈으로 🏠](../README.md)** | **[다음: Stateless Session (JWT 환경) ➡️](./05-stateless-session.md)**

</div>
