# Custom Authorization Logic — AuthorizationManager 구현과 동적 권한 검사

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `AuthorizationManager<MethodInvocation>` 직접 구현이 `@PreAuthorize`보다 적합한 상황은?
- `AuthorizationDecision`과 `AuthorizationResult`의 차이는 무엇인가?
- 어노테이션 없이 메서드 이름이나 파라미터 타입으로 동적 권한 검사를 구현하는 방법은?
- `Supplier<Authentication>`을 사용한 지연 로딩이 성능에 어떤 영향을 주는가?
- 커스텀 어노테이션을 만들어 `@PreAuthorize`의 대안으로 사용하는 방법은?
- `AuthorizationEventPublisher`를 활용한 권한 결정 감사 로그 구현 방법은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 어노테이션 기반의 한계

```
@PreAuthorize로 처리하기 어려운 시나리오:

  1. 런타임 DB에서 권한 규칙을 동적으로 로드:
     → 어노테이션 값은 컴파일 타임 상수 → 동적 변경 불가
     @PreAuthorize("hasRole('ADMIN')")  // "ADMIN"은 하드코딩됨

  2. 특정 파라미터 타입이 있는 모든 메서드에 적용:
     → 각 메서드마다 동일한 어노테이션 중복
     모든 Command 객체를 받는 메서드에 동일한 검사 적용

  3. 어노테이션을 붙일 수 없는 서드파티 라이브러리 메서드:
     → 소스 코드가 없어서 @PreAuthorize 추가 불가

  4. 메서드 시그니처 기반 규칙:
     → get/find로 시작하는 메서드는 READ 권한 검사
     → save/update로 시작하는 메서드는 WRITE 권한 검사

해결: AuthorizationManager 직접 구현
  → 런타임에 DB에서 규칙 로드
  → 메서드 시그니처/파라미터 타입 기반 동적 적용
  → 어노테이션 없이 AOP Pointcut으로 일괄 적용
```

---

## 😱 흔한 보안 실수

### Before: 커스텀 AuthorizationManager에서 Authentication을 항상 로드

```java
// ❌ 모든 요청에서 Authentication 즉시 로드
@Component
public class EagerAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication, // Supplier인데
            MethodInvocation invocation) {

        // 메서드 이름만 확인해도 되는 경우에도 Authentication을 즉시 로드
        Authentication auth = authentication.get(); // 항상 호출!
        String methodName = invocation.getMethod().getName();

        if (methodName.startsWith("public")) {
            return new AuthorizationDecision(true); // Authentication 불필요했음
        }
        return checkAuthority(auth, methodName);
    }
}

// ✅ 필요할 때만 Authentication 로드
@Override
public AuthorizationDecision check(
        Supplier<Authentication> authentication,
        MethodInvocation invocation) {

    String methodName = invocation.getMethod().getName();

    // public 메서드는 Authentication 없이 판단 가능
    if (methodName.startsWith("public")) {
        return new AuthorizationDecision(true); // Supplier 호출 안 함
    }

    // 여기서만 Authentication 로드 (HttpSession 접근 등 비용 발생)
    Authentication auth = authentication.get();
    return checkAuthority(auth, methodName);
}
```

### Before: 커스텀 어노테이션을 처리하는 Manager가 null 반환 처리 안 함

```java
// ❌ null 반환 시 ProviderNotFoundException과 유사한 문제
@Override
public AuthorizationDecision check(...) {
    RequiresPermission annotation = findAnnotation(invocation);
    if (annotation == null) {
        return null; // 어노테이션 없으면 null 반환 → AuthorizationManager 체인에서 허용됨
        // 위험: 어노테이션이 없는 메서드가 모두 허용됨
    }
    ...
}

// ✅ 어노테이션 없는 메서드의 처리 정책 명확히
@Override
public AuthorizationDecision check(...) {
    RequiresPermission annotation = findAnnotation(invocation);
    if (annotation == null) {
        // 옵션 A: null 반환 → 다음 Manager에게 위임 (체인)
        return null;
        // 옵션 B: 명시적으로 거부 (화이트리스트 전략)
        // return new AuthorizationDecision(false);
        // 옵션 C: 명시적으로 허용 (어노테이션 없으면 허용)
        // return new AuthorizationDecision(true);
    }
    ...
}
```

---

## ✨ 올바른 보안 구현

### 패턴 1: DB 기반 동적 권한 규칙

```java
// 권한 규칙을 DB에서 관리하는 AuthorizationManager
@Component
@RequiredArgsConstructor
public class DynamicRuleAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    private final PermissionRuleRepository ruleRepository;
    private final LoadingCache<String, List<PermissionRule>> rulesCache =
        Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build(this::loadRulesFromDb);

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            MethodInvocation invocation) {

        // 메서드 식별자 (패키지.클래스.메서드)
        String methodKey = getMethodKey(invocation);

        // 캐시된 규칙 조회
        List<PermissionRule> rules = rulesCache.get(methodKey);
        if (rules == null || rules.isEmpty()) {
            return null; // 규칙 없음 → 다음 처리로
        }

        // 규칙에 해당하는 경우에만 Authentication 로드
        Authentication auth = authentication.get();
        Set<String> authorities = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

        // DB 규칙 평가: 하나라도 매칭되면 허용
        boolean granted = rules.stream()
            .anyMatch(rule -> authorities.contains(rule.getRequiredAuthority()));

        return new AuthorizationDecision(granted);
    }

    private String getMethodKey(MethodInvocation invocation) {
        Method method = invocation.getMethod();
        return method.getDeclaringClass().getName() + "." + method.getName();
    }

    private List<PermissionRule> loadRulesFromDb(String methodKey) {
        return ruleRepository.findByMethodKey(methodKey);
    }

    // 규칙 변경 시 캐시 무효화
    public void invalidateCache(String methodKey) {
        rulesCache.invalidate(methodKey);
    }
}
```

### 패턴 2: 커스텀 어노테이션 기반 AuthorizationManager

```java
// 커스텀 어노테이션 정의
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresPermission {
    String[] value();                   // 필요한 권한 목록
    boolean allRequired() default false; // true=AND, false=OR
    String resource() default "";        // 리소스 타입
}

// AuthorizationManager 구현
@Component
@RequiredArgsConstructor
public class RequiresPermissionAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    private final PermissionService permissionService;

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            MethodInvocation invocation) {

        RequiresPermission annotation = findAnnotation(invocation);
        if (annotation == null) return null; // 어노테이션 없으면 위임

        Authentication auth = authentication.get();
        String[] required = annotation.value();
        boolean allRequired = annotation.allRequired();

        Set<String> userPermissions = permissionService
            .getPermissions(auth.getName()); // DB에서 사용자 권한 조회

        boolean granted;
        if (allRequired) {
            // AND: 모든 권한 필요
            granted = Arrays.stream(required)
                .allMatch(userPermissions::contains);
        } else {
            // OR: 하나만 있으면 됨
            granted = Arrays.stream(required)
                .anyMatch(userPermissions::contains);
        }

        return new AuthorizationDecision(granted);
    }

    private RequiresPermission findAnnotation(MethodInvocation invocation) {
        // 메서드 레벨 어노테이션 먼저, 없으면 클래스 레벨
        RequiresPermission ann = AnnotationUtils.findAnnotation(
            invocation.getMethod(), RequiresPermission.class);
        if (ann == null) {
            ann = AnnotationUtils.findAnnotation(
                invocation.getMethod().getDeclaringClass(),
                RequiresPermission.class);
        }
        return ann;
    }
}

// SecurityConfig에 등록
@Configuration
@EnableMethodSecurity(prePostEnabled = false) // 기본 비활성화 후 커스텀만 사용
public class CustomMethodSecurityConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor requiresPermissionAdvisor(
            RequiresPermissionAuthorizationManager manager) {
        // AuthorizationManagerBeforeMethodInterceptor로 래핑
        AuthorizationManagerBeforeMethodInterceptor interceptor =
            new AuthorizationManagerBeforeMethodInterceptor(
                Pointcuts.union(
                    new AnnotationMatchingPointcut(null, RequiresPermission.class),
                    new AnnotationMatchingPointcut(RequiresPermission.class, null)
                ),
                manager
            );
        interceptor.setOrder(500);
        return interceptor;
    }
}

// 사용:
@RequiresPermission(value = {"ORDER_READ", "ORDER_WRITE"}, allRequired = false)
public Order getOrder(Long id) { ... }

@RequiresPermission(value = {"REPORT_READ", "REPORT_EXPORT"}, allRequired = true)
public ReportExport exportReport(ReportRequest request) { ... }
```

---

## 🔬 내부 동작 원리

### 1. AuthorizationManager 인터페이스

```java
// AuthorizationManager.java (Spring Security 6.x 핵심 인터페이스)
@FunctionalInterface
public interface AuthorizationManager<T> {

    /**
     * 접근 허용 여부 결정
     * @param authentication 현재 사용자 (지연 로딩 Supplier)
     * @param object 보호 대상 (MethodInvocation, HttpServletRequest 등)
     * @return null → 판단 보류 (다음 Manager에 위임 또는 기본 정책 적용)
     *         AuthorizationDecision(true) → 허용
     *         AuthorizationDecision(false) → 거부
     */
    @Nullable
    AuthorizationDecision check(Supplier<Authentication> authentication, T object);

    /**
     * check() 결과가 거부이면 AccessDeniedException throw
     * 기본 구현: check() 호출 후 denied이면 예외
     */
    default void verify(Supplier<Authentication> authentication, T object) {
        AuthorizationDecision decision = check(authentication, object);
        if (decision != null && !decision.isGranted()) {
            throw new AccessDeniedException("Access Denied");
        }
    }
}
```

### 2. AuthorizationDecision 계층

```java
// AuthorizationDecision: 기본 허용/거부
public class AuthorizationDecision {
    private final boolean granted;
    public AuthorizationDecision(boolean granted) { this.granted = granted; }
    public boolean isGranted() { return this.granted; }
}

// ExpressionAttributeAuthorizationDecision: SpEL 표현식 포함 (디버깅용)
public class ExpressionAttributeAuthorizationDecision extends AuthorizationDecision {
    private final EvaluationContext evaluationContext;
    // SpEL 평가 결과와 컨텍스트 정보 포함
}

// null 반환의 의미:
// AuthorizationManagerBeforeMethodInterceptor에서:
//   check() → null
//   → verify()에서는 null이면 허용 (예외 미발생)
//   → 실제로는 다음 Interceptor 또는 기본 정책에 의존
```

### 3. 여러 AuthorizationManager 체인 구성

```java
// 여러 Manager를 합성하는 패턴
public class CompositeAuthorizationManager<T>
        implements AuthorizationManager<T> {

    private final List<AuthorizationManager<T>> managers;
    private final boolean requireAll; // true=AND, false=OR

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication, T object) {

        AuthorizationDecision lastDecision = null;

        for (AuthorizationManager<T> manager : managers) {
            AuthorizationDecision decision = manager.check(authentication, object);

            if (decision == null) continue; // 기권 → 다음으로

            if (requireAll) {
                // AND: 하나라도 거부 → 즉시 거부
                if (!decision.isGranted()) return decision;
                lastDecision = decision;
            } else {
                // OR: 하나라도 허용 → 즉시 허용
                if (decision.isGranted()) return decision;
                lastDecision = decision;
            }
        }

        return lastDecision; // 마지막 결정 또는 null
    }
}

// 사용 예:
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/**")
        .access(new CompositeAuthorizationManager<>(
            List.of(
                new RoleAuthorizationManager("ROLE_API_USER"),
                new IpRangeAuthorizationManager("192.168.0.0/16"),
                new BusinessHoursAuthorizationManager()
            ),
            true // AND: 역할 + IP + 시간 모두 만족
        ))
    );
    return http.build();
}
```

### 4. AuthorizationEventPublisher — 감사 로그

```java
// Spring Security 5.8+에서 AuthorizationEvent 발행 설정
@Configuration
public class AuthorizationEventConfig {

    @Bean
    public AuthorizationEventPublisher authorizationEventPublisher(
            ApplicationEventPublisher eventPublisher) {
        return new SpringAuthorizationEventPublisher(eventPublisher);
    }
}

// 감사 로그 리스너
@Component
@Slf4j
public class AuthorizationAuditListener {

    @EventListener
    public void onDenied(AuthorizationDeniedEvent event) {
        Authentication auth = event.getAuthentication().get();
        String methodName = "";
        if (event.getSource() instanceof MethodInvocation mi) {
            methodName = mi.getMethod().getDeclaringClass().getSimpleName()
                + "." + mi.getMethod().getName();
        }
        log.warn("[SECURITY-AUDIT] Access DENIED: user={}, method={}, reason={}",
            auth.getName(), methodName,
            event.getAuthorizationDecision());
    }

    @EventListener
    public void onGranted(AuthorizationGrantedEvent event) {
        // DEBUG 레벨 (너무 많은 로그 방지)
        if (log.isDebugEnabled()) {
            Authentication auth = event.getAuthentication().get();
            log.debug("[SECURITY-AUDIT] Access GRANTED: user={}", auth.getName());
        }
    }
}
```

### 5. 메서드 시그니처 기반 자동 권한 매핑

```java
// 메서드 이름 접두사로 권한 자동 결정
@Component
public class MethodNameBasedAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    private static final Map<String, String> PREFIX_PERMISSION_MAP = Map.of(
        "get", "READ",
        "find", "READ",
        "list", "READ",
        "create", "WRITE",
        "save", "WRITE",
        "update", "WRITE",
        "delete", "DELETE",
        "remove", "DELETE"
    );

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            MethodInvocation invocation) {

        String methodName = invocation.getMethod().getName();

        // 메서드 이름에서 권한 결정
        String requiredPermission = PREFIX_PERMISSION_MAP.entrySet().stream()
            .filter(entry -> methodName.startsWith(entry.getKey()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElse(null);

        if (requiredPermission == null) return null; // 판단 보류

        Authentication auth = authentication.get();
        String expectedAuthority = "PERMISSION_" + requiredPermission;

        boolean granted = auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals(expectedAuthority));

        return new AuthorizationDecision(granted);
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: AuthorizationManager 단위 테스트

```java
class DynamicRuleAuthorizationManagerTest {

    @Mock PermissionRuleRepository ruleRepository;
    @InjectMocks DynamicRuleAuthorizationManager manager;

    @Test
    void noRules_returnsNull_delegatesToNext() {
        when(ruleRepository.findByMethodKey(any())).thenReturn(List.of());
        MethodInvocation invocation = mockInvocation("OrderService", "getOrder");

        AuthorizationDecision result = manager.check(
            mockAuthentication("ROLE_USER"), invocation);

        assertNull(result); // null → 다음 Manager로 위임
    }

    @Test
    void matchingRule_grantedAuthority_returnsGranted() {
        when(ruleRepository.findByMethodKey("OrderService.getOrder"))
            .thenReturn(List.of(new PermissionRule("ROLE_USER")));
        MethodInvocation invocation = mockInvocation("OrderService", "getOrder");

        AuthorizationDecision result = manager.check(
            mockAuthentication("ROLE_USER"), invocation);

        assertNotNull(result);
        assertTrue(result.isGranted());
    }
}
```

### 실험 2: 커스텀 어노테이션 @RequiresPermission 통합 테스트

```java
@SpringBootTest
@WithMockUser(username = "kim")
class RequiresPermissionTest {

    @Autowired OrderService orderService;
    @MockBean PermissionService permissionService;

    @Test
    void withRequiredPermission_allowed() {
        when(permissionService.getPermissions("kim"))
            .thenReturn(Set.of("ORDER_READ"));

        assertDoesNotThrow(() -> orderService.getOrder(1L));
    }

    @Test
    void withoutRequiredPermission_denied() {
        when(permissionService.getPermissions("kim"))
            .thenReturn(Set.of("ORDER_WRITE")); // READ 없음

        assertThatThrownBy(() -> orderService.getOrder(1L))
            .isInstanceOf(AccessDeniedException.class);
    }
}
```

### 실험 3: 감사 이벤트 확인

```java
@Test
void accessDenied_publishesAuditEvent() {
    // given: 이벤트 캡처
    List<AuthorizationDeniedEvent> events = new ArrayList<>();
    applicationEventPublisher.addApplicationListener(events::add);

    // when: 권한 없는 접근
    assertThatThrownBy(() -> orderService.getOrder(1L))
        .isInstanceOf(AccessDeniedException.class);

    // then: 이벤트 발행 확인
    assertThat(events).hasSize(1);
    assertThat(events.get(0).getAuthentication().get().getName())
        .isEqualTo("kim");
}
```

---

## 🔒 보안 체크리스트

```
AuthorizationManager 구현
  ☐ null 반환 정책 명확히 정의 (위임 vs 기본 거부 vs 기본 허용)
  ☐ Supplier<Authentication> 지연 로딩 활용 (불필요한 SecurityContext 접근 최소화)
  ☐ 결과 캐싱 시 사용자별 캐시 키 설계 (공유 캐시 오염 방지)

커스텀 어노테이션
  ☐ 어노테이션 없는 메서드의 기본 처리 정책 문서화
  ☐ @Role(ROLE_INFRASTRUCTURE) 설정 → Advisor가 Spring Bean 후처리에서 제외
  ☐ 어노테이션 처리 순서(@Order) 설정

감사 로그
  ☐ 거부 이벤트: 사용자, 대상 메서드, 이유 기록
  ☐ 허용 이벤트: DEBUG 레벨 (대량 트래픽에서 성능 고려)
  ☐ PII(개인정보)가 메서드 파라미터에 있으면 로그에 포함 금지
```

---

## 🤔 트레이드오프

```
@PreAuthorize vs 커스텀 AuthorizationManager:
  @PreAuthorize:
    장점  메서드마다 명시적 선언 → 의도 명확
          SpEL로 간단한 조건 표현, IDE 지원
    단점  동적 규칙 불가 (컴파일 타임 상수)
          서드파티 메서드에 적용 불가

  커스텀 AuthorizationManager:
    장점  DB 기반 동적 규칙, 런타임 변경 가능
          서드파티 코드에도 AOP로 적용 가능
          어노테이션 없는 메서드 일괄 처리
    단점  구현 복잡도 증가
          보안 정책이 코드가 아닌 DB에 → 가시성 저하

DB 기반 동적 권한:
  장점  운영 중 권한 변경 가능 (배포 없이)
  단점  DB 의존성 → 캐싱 필수
        캐시 무효화 전략 관리 필요 (변경 즉시 반영 지연)
```

---

## 📌 핵심 정리

```
AuthorizationManager<T> 인터페이스
  check(): null(위임) / AuthorizationDecision(true/false)
  verify(): check() 후 거부 시 AccessDeniedException throw
  Supplier<Authentication>: 필요할 때만 Authentication 로드 (성능)

커스텀 AuthorizationManager 활용 시나리오
  DB 기반 동적 권한 규칙 (런타임 변경)
  커스텀 어노테이션 처리
  메서드 시그니처 기반 자동 권한 매핑
  서드파티 코드 보안 적용

등록 방법
  method security: @Bean Advisor + AuthorizationManagerBeforeMethodInterceptor
  URL security: authorizeHttpRequests().access(customManager)

감사 로그
  AuthorizationEventPublisher 등록
  @EventListener(AuthorizationDeniedEvent) 처리
  거부: WARN, 허용: DEBUG
```

---

## 🤔 생각해볼 문제

**Q1.** `AuthorizationManager.check()`가 `null`을 반환할 때와 `new AuthorizationDecision(true)`를 반환할 때의 실질적인 차이는? 여러 `AuthorizationManager`가 체인으로 구성되어 있을 때 `null`이 미치는 영향을 `AuthorizationManagerBeforeMethodInterceptor`의 소스 레벨에서 설명하라.

**Q2.** DB 기반 동적 권한 규칙을 캐싱할 때, 사용자 A의 권한이 DB에서 변경되는 순간 캐시는 아직 이전 값을 가지고 있습니다. 캐시 무효화 전략을 이벤트 기반으로 설계하라.

**Q3.** `@EnableMethodSecurity(prePostEnabled = false)`로 기본 Method Security를 비활성화하고 커스텀 `AuthorizationManager`만 사용하는 경우, `@PreAuthorize`가 붙은 서드파티 라이브러리 메서드의 보안은 어떻게 되는가?

> 💡 **해설**
>
> **Q1.** `AuthorizationManagerBeforeMethodInterceptor.invoke()` 내부에서 `authorizationManager.verify()`를 호출합니다. `verify()`의 기본 구현은 `check()` 결과가 `null`이면 예외를 발생시키지 않습니다. 즉, `null`은 "판단 안 함 → 기본 허용"입니다. 반면 `new AuthorizationDecision(true)`는 명시적으로 "이 Manager가 허용을 결정했다"는 의미입니다. 여러 Manager가 체인으로 구성될 때: 첫 번째 Manager가 `null`을 반환하면 `verify()`는 예외를 발생시키지 않고 메서드를 실행합니다. 두 번째 Manager는 호출되지 않습니다. 체인 중 누구라도 `AuthorizationDecision(false)`를 반환하면 즉시 `AccessDeniedException`이 발생합니다. 따라서 "화이트리스트 전략"을 원하면 어노테이션 없는 메서드에 `null`이 아닌 `new AuthorizationDecision(false)`를 반환해야 합니다.
>
> **Q2.** 이벤트 기반 캐시 무효화 설계는 다음과 같습니다. 권한 변경 Service에서 `PermissionChangedEvent`를 발행합니다. `AuthorizationCacheEvictionListener`가 이 이벤트를 수신해 해당 사용자의 캐시 항목을 제거합니다. 분산 환경에서는 Redis Pub/Sub로 이벤트를 전파해 모든 서버 인스턴스의 캐시를 무효화합니다. 또한 최악의 경우를 대비해 캐시 TTL을 짧게(1~5분) 설정합니다. 보안 민감도가 높은 경우 캐시를 사용하지 않거나, 무효화를 동기적으로 처리해 변경과 적용 사이 지연을 0으로 만드는 방법도 있습니다.
>
> **Q3.** `@EnableMethodSecurity(prePostEnabled = false)`를 설정하면 `PreAuthorizeAuthorizationManager`와 관련 `Advisor`가 등록되지 않습니다. 서드파티 라이브러리의 `@PreAuthorize`는 이제 처리되지 않아 어노테이션이 무시됩니다. 즉, 보안이 적용되지 않습니다. 이 경우 커스텀 `AuthorizationManager`로 서드파티 메서드를 보호하려면 해당 클래스와 메서드를 포함하는 `Pointcut`을 정의하고 커스텀 `Advisor`를 등록해야 합니다. 또는 서드파티 라이브러리 클래스를 래핑하는 Facade 클래스를 만들고 거기에 커스텀 어노테이션을 붙이는 방법도 있습니다. 근본적으로는 `prePostEnabled = true`를 유지하면서 추가 커스텀 Manager를 병행 등록하는 것이 서드파티 코드 보안을 잃지 않는 안전한 방법입니다.

---

<div align="center">

**[← 이전: SpEL을 활용한 복잡한 권한 검사](./05-spel-authorization.md)** | **[홈으로 🏠](../README.md)** | **[Chapter 4으로 이동: Session Fixation Attack ➡️](../session-management/01-session-fixation-attack.md)**

</div>
