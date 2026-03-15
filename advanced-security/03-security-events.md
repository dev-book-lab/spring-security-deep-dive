# Security Events & Listeners — 로그인 실패 제한과 보안 감사 구현

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- Spring Security가 발행하는 보안 이벤트의 종류와 각 이벤트가 발생하는 시점은?
- `ApplicationListener`로 `AuthenticationFailureBadCredentialsEvent`를 처리해 로그인 실패 횟수를 제한하는 구현은?
- `DefaultAuthenticationEventPublisher`가 예외 타입별로 이벤트를 매핑하는 방법은?
- `AuthorizationDeniedEvent`와 `AuthorizationGrantedEvent`를 활용한 접근 감사 로그 구현은?
- 로그인 실패 제한 구현 시 Redis 기반과 DB 기반의 차이와 선택 기준은?
- Spring Security 이벤트와 Spring Application Event의 관계는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 보안 이벤트 모니터링이 필요한 이유

```
이벤트 없이 보안 운영의 문제점:
  - 누가 로그인 시도했는지 알 수 없음
  - 무차별 대입(Brute Force) 공격 감지 불가
  - 특정 사용자가 반복적으로 권한 오류를 낸다면?
    → 내부 침투 시도? → 알 수 없음

보안 이벤트가 해결하는 것:
  ① 감사 로그: "누가, 언제, 무엇에 접근했는가"
  ② 실시간 이상 감지: 동일 IP에서 N회 실패 → 계정 잠금
  ③ 보안 운영 지표: 실패/성공 비율, 의심 패턴 통계
  ④ 법적 요건: 금융, 의료 시스템의 감사 추적

Spring Security 이벤트 활용:
  ApplicationEventPublisher → Security Event 발행
  → @EventListener 또는 ApplicationListener<E>로 처리
  → 비동기로 처리 가능 (@Async)
  → 이벤트 소비자는 인증 흐름에 영향 없음 (느슨한 결합)
```

---

## 😱 흔한 보안 실수

### Before: 로그인 실패 제한 없음 — Brute Force 공격 취약

```java
// ❌ 실패 횟수 제한 없음 → 무차별 대입 공격 허용
// 공격자: 자동화 도구로 초당 1000번 시도 가능
// → 8자리 숫자 비밀번호: 100,000,000 / 1,000 = 100,000초 = 약 28시간

// ✅ 5회 실패 시 계정 잠금 + 점진적 지연
@Component
@RequiredArgsConstructor
public class LoginFailureLimiter {

    private final RedisTemplate<String, String> redisTemplate;

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(30);

    public void recordFailure(String username) {
        String key = "login:fail:" + username;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count == 1) {
            redisTemplate.expire(key, LOCKOUT_DURATION);
        }
        if (count >= MAX_ATTEMPTS) {
            // 계정 DB 잠금 또는 Redis 잠금 설정
            lockAccount(username);
        }
    }

    public boolean isLocked(String username) {
        return redisTemplate.hasKey("login:locked:" + username);
    }
}
```

### Before: 이벤트 핸들러에서 예외를 던져 인증 흐름 방해

```java
// ❌ 이벤트 핸들러에서 예외 → ApplicationContext 전체 전파 가능
@EventListener
public void onAuthSuccess(AuthenticationSuccessEvent event) {
    String username = event.getAuthentication().getName();
    // DB 저장 실패 시 예외 발생
    auditRepository.save(new AuditLog(username, "LOGIN"));
    // → 이 예외가 인증 성공 흐름을 방해할 수 있음
}

// ✅ 이벤트 핸들러는 try-catch로 감싸거나 @Async로 분리
@EventListener
@Async  // 별도 스레드에서 실행 → 인증 흐름에 영향 없음
public void onAuthSuccess(AuthenticationSuccessEvent event) {
    try {
        auditRepository.save(new AuditLog(...));
    } catch (Exception e) {
        log.error("Failed to save audit log: {}", e.getMessage());
        // 예외를 삼킴 → 인증 성공은 정상 진행
    }
}
```

---

## ✨ 올바른 보안 구현

### 완전한 보안 이벤트 처리 시스템

```java
// ① 로그인 실패 횟수 제한 (Redis 기반)
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    private final StringRedisTemplate redisTemplate;
    private final UserRepository userRepository;

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(30);

    // 실패 기록
    public void recordFailure(String username, String ipAddress) {
        String usernameKey = "login:fail:user:" + username;
        String ipKey       = "login:fail:ip:" + ipAddress;

        // 사용자 기준 실패 횟수
        Long userCount = redisTemplate.opsForValue().increment(usernameKey);
        if (userCount == 1) redisTemplate.expire(usernameKey, WINDOW);

        // IP 기준 실패 횟수 (IP 기반 차단용)
        Long ipCount = redisTemplate.opsForValue().increment(ipKey);
        if (ipCount == 1) redisTemplate.expire(ipKey, WINDOW);

        if (userCount >= MAX_ATTEMPTS) {
            log.warn("[SECURITY] Account locked: username={}, ip={}", username, ipAddress);
            lockAccount(username);
        }

        if (ipCount >= 20) { // IP 기준 임계값
            log.warn("[SECURITY] IP blocked: ip={}", ipAddress);
            blockIp(ipAddress);
        }
    }

    // 성공 시 초기화
    public void recordSuccess(String username) {
        redisTemplate.delete("login:fail:user:" + username);
        // IP 카운터는 초기화하지 않음 (다른 계정 시도 방지)
    }

    public boolean isUserLocked(String username) {
        return Boolean.TRUE.equals(
            redisTemplate.hasKey("login:locked:" + username));
    }

    public long getFailureCount(String username) {
        String val = redisTemplate.opsForValue()
            .get("login:fail:user:" + username);
        return val != null ? Long.parseLong(val) : 0L;
    }

    private void lockAccount(String username) {
        redisTemplate.opsForValue().set(
            "login:locked:" + username, "1", WINDOW);
        // 선택: DB에도 잠금 상태 반영
        userRepository.lockAccount(username, WINDOW);
    }

    private void blockIp(String ip) {
        redisTemplate.opsForValue().set("login:blocked:ip:" + ip, "1", WINDOW);
    }
}

// ② 이벤트 리스너 모음
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityEventListener {

    private final LoginAttemptService loginAttemptService;
    private final AuditLogRepository auditLogRepository;

    // ─── 인증 성공 ─────────────────────────────────────────────
    @EventListener
    @Async
    public void onAuthSuccess(AuthenticationSuccessEvent event) {
        Authentication auth = event.getAuthentication();
        String username = auth.getName();

        loginAttemptService.recordSuccess(username);

        log.info("[AUTH-SUCCESS] user={}, type={}",
            username, auth.getClass().getSimpleName());

        auditLogRepository.save(AuditLog.success(username, getIp(event)));
    }

    // ─── 잘못된 자격증명 (비밀번호 오류) ─────────────────────
    @EventListener
    @Async
    public void onBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
        String username = (String) event.getAuthentication().getPrincipal();
        String ip = getIp(event);

        log.warn("[AUTH-FAIL] BAD_CREDENTIALS user={}, ip={}", username, ip);
        loginAttemptService.recordFailure(username, ip);

        long remaining = LoginAttemptService.MAX_ATTEMPTS
            - loginAttemptService.getFailureCount(username);
        log.warn("[AUTH-FAIL] Remaining attempts: {}", Math.max(0, remaining));
    }

    // ─── 잠긴 계정 시도 ──────────────────────────────────────
    @EventListener
    @Async
    public void onLockedAccount(AuthenticationFailureLockedEvent event) {
        String username = (String) event.getAuthentication().getPrincipal();
        log.warn("[AUTH-FAIL] LOCKED_ACCOUNT user={}", username);
    }

    // ─── 계정 비활성화 ───────────────────────────────────────
    @EventListener
    @Async
    public void onDisabledAccount(AuthenticationFailureDisabledEvent event) {
        String username = (String) event.getAuthentication().getPrincipal();
        log.warn("[AUTH-FAIL] DISABLED_ACCOUNT user={}", username);
    }

    // ─── 권한 거부 (접근 거부) ────────────────────────────────
    @EventListener
    @Async
    public void onAuthorizationDenied(AuthorizationDeniedEvent event) {
        Authentication auth = event.getAuthentication().get();
        log.warn("[AUTHZ-DENIED] user={}, resource={}",
            auth.getName(), event.getSource());
    }

    // ─── 권한 부여 (접근 허용) ────────────────────────────────
    @EventListener
    @Async
    public void onAuthorizationGranted(AuthorizationGrantedEvent event) {
        // 보통 DEBUG 레벨 (너무 많음)
        if (log.isDebugEnabled()) {
            Authentication auth = event.getAuthentication().get();
            log.debug("[AUTHZ-GRANTED] user={}, resource={}",
                auth.getName(), event.getSource());
        }
    }

    private String getIp(AbstractAuthenticationFailureEvent event) {
        if (event.getAuthentication().getDetails()
                instanceof WebAuthenticationDetails details) {
            return details.getRemoteAddress();
        }
        return "unknown";
    }
}

// ③ UserDetailsService에서 잠금 체크 연동
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // Redis에서 잠금 여부 확인
        boolean locked = loginAttemptService.isUserLocked(username)
            || user.isLocked(); // DB 잠금도 확인

        return CustomUserDetails.builder()
            .userId(user.getId())
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(...)
            .accountNonLocked(!locked)  // ← 잠금 상태 반영
            .build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. Spring Security 이벤트 전체 목록

```java
// 인증 이벤트 계층:
// AbstractAuthenticationEvent
// ├── AuthenticationSuccessEvent
// └── AbstractAuthenticationFailureEvent
//     ├── AuthenticationFailureBadCredentialsEvent (잘못된 비밀번호)
//     ├── AuthenticationFailureCredentialsExpiredEvent (비밀번호 만료)
//     ├── AuthenticationFailureDisabledEvent (계정 비활성화)
//     ├── AuthenticationFailureExpiredEvent (계정 만료)
//     ├── AuthenticationFailureLockedEvent (계정 잠김)
//     ├── AuthenticationFailureProviderNotFoundEvent (Provider 없음)
//     ├── AuthenticationFailureServiceExceptionEvent (서비스 예외)
//     └── AuthenticationFailureUnknownAccountEvent (계정 없음)

// 인가 이벤트 계층 (Spring Security 5.8+):
// AuthorizationEvent
// ├── AuthorizationGrantedEvent (접근 허용)
// └── AuthorizationDeniedEvent (접근 거부)
```

### 2. DefaultAuthenticationEventPublisher — 예외 → 이벤트 매핑

```java
// DefaultAuthenticationEventPublisher.java
public class DefaultAuthenticationEventPublisher
        implements AuthenticationEventPublisher, ApplicationEventPublisherAware {

    // 예외 클래스 → 이벤트 클래스 매핑
    private final HashMap<String, Constructor<? extends AbstractAuthenticationEvent>>
        exceptionMappings = new HashMap<>();

    public DefaultAuthenticationEventPublisher(ApplicationEventPublisher publisher) {
        // 기본 매핑:
        addMapping(BadCredentialsException.class.getName(),
            AuthenticationFailureBadCredentialsEvent.class);
        addMapping(AccountExpiredException.class.getName(),
            AuthenticationFailureExpiredEvent.class);
        addMapping(LockedException.class.getName(),
            AuthenticationFailureLockedEvent.class);
        addMapping(DisabledException.class.getName(),
            AuthenticationFailureDisabledEvent.class);
        addMapping(CredentialsExpiredException.class.getName(),
            AuthenticationFailureCredentialsExpiredEvent.class);
        // 등...
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException exception,
                                              Authentication authentication) {
        // 예외 클래스로 이벤트 클래스 조회
        Constructor<? extends AbstractAuthenticationEvent> constructor =
            exceptionMappings.get(exception.getClass().getName());

        if (constructor != null) {
            AbstractAuthenticationEvent event =
                constructor.newInstance(authentication, exception);
            applicationEventPublisher.publishEvent(event); // Spring Event 발행
        }
    }
}
```

### 3. AuthenticationEventPublisher 커스터마이징

```java
// 커스텀 예외 → 이벤트 매핑 추가
@Bean
public DefaultAuthenticationEventPublisher authenticationEventPublisher(
        ApplicationEventPublisher eventPublisher) {

    DefaultAuthenticationEventPublisher publisher =
        new DefaultAuthenticationEventPublisher(eventPublisher);

    // 커스텀 예외 → 기존 이벤트 타입으로 매핑
    publisher.setAdditionalExceptionMappings(Map.of(
        // JWT 만료 예외 → 기존 이벤트로 매핑
        "io.jsonwebtoken.ExpiredJwtException",
        AuthenticationFailureCredentialsExpiredEvent.class
    ));

    return publisher;
}

// 커스텀 인증 실패 이벤트 정의
public class MfaFailedEvent extends AbstractAuthenticationFailureEvent {
    public MfaFailedEvent(Authentication auth, AuthenticationException exception) {
        super(auth, exception);
    }
}
```

### 4. 이벤트 기반 로그인 실패 제한 흐름

```
POST /login (username=kim, password=wrong)
  ↓
UsernamePasswordAuthenticationFilter
  → DaoAuthenticationProvider.authenticate()
  → 비밀번호 불일치 → BadCredentialsException 발생
  ↓
AbstractAuthenticationProcessingFilter.unsuccessfulAuthentication()
  → DefaultAuthenticationEventPublisher.publishAuthenticationFailure()
  → BadCredentialsException → AuthenticationFailureBadCredentialsEvent 발행
  ↓
SecurityEventListener.onBadCredentials(@EventListener)
  → loginAttemptService.recordFailure("kim", "192.168.1.1")
  → Redis: login:fail:user:kim = 1
  ↓
5번째 실패 시:
  → loginAttemptService.lockAccount("kim")
  → Redis: login:locked:kim = "1" (30분 TTL)
  ↓
6번째 시도:
  CustomUserDetailsService.loadUserByUsername("kim")
  → loginAttemptService.isUserLocked("kim") → true
  → accountNonLocked = false
  → DaoAuthenticationProvider.additionalAuthenticationChecks()
  → LockedException 발생
  → AuthenticationFailureLockedEvent 발행
  → 403 응답
```

---

## 💻 실험으로 확인하기

### 실험 1: 연속 실패 시 잠금 확인

```bash
# 5번 실패 시도
for i in {1..5}; do
  curl -X POST http://localhost:8080/login \
    -d "username=kim&password=wrong"
  echo "Attempt $i"
done

# 6번째 시도 → 잠금
curl -X POST http://localhost:8080/login \
  -d "username=kim&password=correctpassword"
# → 403 Account locked
# 로그: [SECURITY] Account locked: username=kim, ip=127.0.0.1
```

### 실험 2: Redis에서 실패 카운터 확인

```bash
redis-cli GET "login:fail:user:kim"
# "3"

redis-cli TTL "login:fail:user:kim"
# 1547 (초, 30분에서 경과 시간 차감)

# 잠금 후:
redis-cli EXISTS "login:locked:kim"
# "1"
redis-cli TTL "login:locked:kim"
# 1800 (30분)
```

### 실험 3: 이벤트 수신 확인 (테스트)

```java
@SpringBootTest
class SecurityEventListenerTest {

    @Autowired ApplicationEventPublisher eventPublisher;
    @MockBean LoginAttemptService loginAttemptService;

    @Test
    void badCredentials_event_triggers_failure_recording() {
        Authentication auth = new UsernamePasswordAuthenticationToken("kim", "wrong");
        AuthenticationException exception =
            new BadCredentialsException("Bad credentials");

        eventPublisher.publishEvent(
            new AuthenticationFailureBadCredentialsEvent(auth, exception));

        // 이벤트 리스너가 실패 기록 메서드를 호출했는지 확인
        verify(loginAttemptService, timeout(1000))
            .recordFailure(eq("kim"), any());
    }
}
```

---

## 🔒 보안 체크리스트

```
로그인 실패 제한
  ☐ 사용자 기준 최대 시도 횟수 설정 (5~10회)
  ☐ IP 기준 차단도 병행 (한 IP에서 여러 계정 공격 방지)
  ☐ 잠금 기간 설정 (30분 또는 점진적 증가)
  ☐ 잠금 해제 메커니즘 (관리자 해제 또는 이메일 인증)

이벤트 핸들러
  ☐ @Async 사용으로 인증 흐름에 영향 없도록
  ☐ try-catch로 이벤트 핸들러 예외 처리
  ☐ 민감 정보(비밀번호) 로그 포함 금지

감사 로그
  ☐ 성공: 사용자, IP, 시각, 인증 방식
  ☐ 실패: 사용자명, IP, 실패 이유, 시각
  ☐ 접근 거부: 사용자, 대상 리소스, 시각
  ☐ 로그 변조 방지 (write-once 저장소)
```

---

## 🤔 트레이드오프

```
Redis 기반 실패 카운터 vs DB 기반:
  Redis:
    장점  TTL 자동 처리, 빠름, 분산 환경 자연스럽게 공유
    단점  Redis 장애 시 카운터 소실 → 제한 없어짐 (fail-open)
    → Redis 다중화 권장

  DB:
    장점  영속적, Redis 장애에 무관
    단점  느림, 동시성 처리 필요, TTL 관리 별도 스케줄러 필요

@Async 이벤트 핸들러 vs 동기 처리:
  @Async:
    장점  인증 흐름에 영향 없음 (감사 로그 저장이 느려도 로그인 지연 없음)
    단점  트랜잭션 공유 불가 (별도 트랜잭션)
          예외가 인증 흐름에 전달 안 됨

  동기:
    장점  트랜잭션 공유 가능, 예외 전파 가능
    단점  DB/Redis 지연이 인증 응답 시간에 직접 영향

실패 횟수 기준 (사용자 vs IP):
  사용자 기준만: 공격자가 여러 사용자 공격 시 IP 차단 불가
  IP 기준만: 공유 IP(사무실, NAT) 오탐 가능
  → 두 기준 병행 (사용자 5회 + IP 20회)
```

---

## 📌 핵심 정리

```
Spring Security 이벤트 흐름
  인증 예외 발생
  → DefaultAuthenticationEventPublisher.publishAuthenticationFailure()
  → 예외 타입 → 이벤트 클래스 매핑
  → ApplicationContext.publishEvent()
  → @EventListener 핸들러 실행

주요 이벤트
  AuthenticationSuccessEvent: 인증 성공
  AuthenticationFailureBadCredentialsEvent: 비밀번호 오류
  AuthenticationFailureLockedEvent: 잠긴 계정
  AuthorizationDeniedEvent: 권한 거부

로그인 실패 제한 구현
  @EventListener(BadCredentials) → Redis 카운터 증가
  MAX_ATTEMPTS 초과 → 계정 잠금 (Redis TTL)
  UserDetailsService: isLocked 확인 → accountNonLocked=false
  LockedException 발생 → AuthenticationFailureLockedEvent

@Async 사용 이유
  이벤트 핸들러가 느려도 인증 흐름 지연 없음
  DB/외부 시스템 저장 실패가 인증 성공에 영향 없음
```

---

## 🤔 생각해볼 문제

**Q1.** Redis를 사용한 로그인 실패 카운터에서 Redis가 다운됐을 때 `redisTemplate.opsForValue().increment(key)`가 예외를 발생시킵니다. 이 예외가 `@EventListener` 핸들러까지 전파되면 어떻게 되는가? 그리고 Redis 장애 시 실패 제한 기능이 동작하지 않는 "fail-open" 동작을 어떻게 처리해야 하는가?

**Q2.** `@Async` 이벤트 핸들러에서 `@Transactional`을 함께 사용할 때 주의사항은? `@EventListener`로 수신한 이벤트 데이터를 DB에 저장하는 작업이 인증 성공과 동일한 트랜잭션에서 처리돼야 하는 시나리오가 있다면 어떻게 처리하는가?

**Q3.** 한 IP에서 여러 사용자 계정을 순환하며 공격하는 "크리덴셜 스터핑(Credential Stuffing)" 공격에서, IP당 실패 횟수 임계값(20회)이 너무 낮으면 정상 공유 네트워크(사무실, 학교) 사용자들이 차단될 수 있습니다. 공유 네트워크를 보호하면서 크리덴셜 스터핑을 방어하는 더 지능적인 차단 전략은?

> 💡 **해설**
>
> **Q1.** `@Async` 이벤트 핸들러에서 발생한 예외는 기본적으로 `AsyncUncaughtExceptionHandler`로 전달되고 인증 흐름에 전파되지 않습니다. 따라서 Redis 장애로 인한 예외가 로그인 자체를 방해하지 않습니다(fail-open). Redis 장애 시 카운터가 증가하지 않으므로 실패 제한 기능이 작동하지 않고 Brute Force 공격이 허용됩니다. 완화 방법: Circuit Breaker 패턴(Resilience4j)으로 Redis 장애를 감지하고, 장애 시 인메모리 카운터로 폴백합니다. 또는 Redis 고가용성(Sentinel, Cluster)을 구성합니다. 보수적 접근으로는 Redis 장애 시 모든 로그인을 일시적으로 차단하는 fail-closed 전략도 있으나 UX 저하가 있습니다.
>
> **Q2.** `@Async` + `@Transactional`은 각 비동기 실행마다 새 트랜잭션을 시작합니다. 부모 트랜잭션(인증 흐름)과는 별개입니다. 이벤트 데이터를 인증 성공과 동일 트랜잭션에서 저장해야 한다면, `@Async`를 제거하고 동기적으로 처리하거나, `TransactionalEventListener`를 사용합니다. `@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)`은 현재 트랜잭션이 커밋된 후 이벤트를 처리합니다. 이 경우 트랜잭션 공유는 안 되지만 커밋 성공이 보장된 후 처리됩니다. 인증 성공과 감사 로그 저장을 같은 트랜잭션에서 처리하려면 이벤트 대신 직접 서비스 메서드 호출이 더 적합합니다.
>
> **Q3.** 지능적 차단 전략으로는 다음을 조합합니다. 첫째, IP 평판 기반 차단: 알려진 악성 IP 목록(AbuseIPDB, Cloudflare 등)과 연동합니다. 둘째, 행동 분석: IP에서 시도된 고유 사용자명 수를 추적합니다. 정상 사용자는 1~2개 계정, 공격자는 수백 개 계정을 시도합니다. 임계값: 5분 내 10개 이상 고유 사용자명 시도 시 의심. 셋째, 슬라이딩 윈도우 + 점진적 지연: 단순 차단 대신 응답 시간을 점진적으로 늘립니다(1초, 5초, 30초). 공격자에게는 효과적이고 정상 사용자에게는 최소 영향. 넷째, CAPTCHA 트리거: 동일 IP에서 실패 N회 시 CAPTCHA 요구. 다섯째, X-Forwarded-For 처리: 프록시 뒤 실제 IP를 추출하되 헤더 스푸핑 방지를 위해 신뢰된 프록시 목록에서만 처리합니다.

---

<div align="center">

**[← 이전: Security Headers](./02-security-headers.md)** | **[홈으로 🏠](../README.md)** | **[다음: Method Security SpEL 고급 활용 ➡️](./04-method-security-spel-advanced.md)**

</div>
