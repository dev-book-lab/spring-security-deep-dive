# @PreAuthorize vs @Secured vs @RolesAllowed — 세 어노테이션의 처리 메커니즘 차이

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `@PreAuthorize`, `@Secured`, `@RolesAllowed` 각각을 처리하는 클래스는 무엇이며 어떻게 다른가?
- SpEL을 지원하는 어노테이션과 지원하지 않는 어노테이션의 차이가 실무에서 왜 중요한가?
- `@EnableMethodSecurity`와 `@EnableGlobalMethodSecurity(deprecated)`의 핵심 차이는?
- `@PostAuthorize`는 `@PreAuthorize`와 무엇이 다르며 어떤 상황에 적합한가?
- `@PreFilter`와 `@PostFilter`는 컬렉션에 어떻게 작동하는가?
- 같은 메서드에 여러 어노테이션을 중첩하면 어떤 순서로 검사하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: URL 기반 접근 제어만으로는 메서드 수준 보안을 보장할 수 없다

```
URL 기반 접근 제어의 한계:

  http.authorizeHttpRequests(auth -> auth
      .requestMatchers("/orders/**").hasRole("USER")
  );

  문제:
  → /orders/42를 ROLE_USER가 요청했을 때 통과
  → 하지만 order 42가 다른 사용자의 주문일 수 있음
  → "인증됨" ≠ "이 리소스에 대한 권한 있음"

  Service 레이어에서 수동 검사:
  public Order getOrder(Long orderId) {
      Order order = orderRepository.findById(orderId).orElseThrow();
      if (!order.getOwnerId().equals(currentUserId())) {
          throw new AccessDeniedException("Not your order");
      }
      return order;
  }
  → 모든 메서드마다 반복적인 보안 코드
  → 누락 가능성 (개발자 실수)
  → 비즈니스 로직과 보안 로직 혼재

해결: Method Security 어노테이션
  @PreAuthorize("#order.ownerId == authentication.principal.userId")
  public Order getOrder(Long orderId) { ... }
  → 보안 정책을 선언적으로 표현
  → AOP로 일관되게 적용
  → 비즈니스 로직 순수하게 유지
```

---

## 😱 흔한 보안 실수

### Before: @Secured에 ROLE_ 접두사 없이 사용

```java
// ❌ @Secured는 ROLE_ 접두사를 자동 추가하지 않음
@Secured("ADMIN")         // "ADMIN" 문자열 그대로 비교
public void adminMethod() { ... }
// getAuthorities()에 "ADMIN"이 있어야 통과
// 대부분 "ROLE_ADMIN"으로 저장하므로 항상 403

// ✅ ROLE_ 명시
@Secured("ROLE_ADMIN")
public void adminMethod() { ... }

// 또는 더 명확한 @PreAuthorize 사용
@PreAuthorize("hasRole('ADMIN')") // 내부: "ROLE_ADMIN" 자동 추가
public void adminMethod() { ... }
```

### Before: @EnableGlobalMethodSecurity의 deprecated 동작 차이를 모르고 마이그레이션

```java
// ❌ Spring Security 5.x 방식 (deprecated in 5.6)
@EnableGlobalMethodSecurity(
    prePostEnabled = true,  // @Pre/@PostAuthorize 활성화
    securedEnabled = true,  // @Secured 활성화
    jsr250Enabled = true    // @RolesAllowed 활성화
)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    // GlobalMethodSecurityConfiguration 상속으로 커스터마이징
}

// ✅ Spring Security 6.x 방식
@EnableMethodSecurity(
    // prePostEnabled = true (기본값, 명시 불필요)
    securedEnabled = true,   // @Secured 필요 시
    jsr250Enabled = true     // @RolesAllowed 필요 시
)
public class SecurityConfig {
    // @Bean으로 커스터마이징 (상속 불필요)
}

// 핵심 차이:
// @EnableGlobalMethodSecurity: AspectJ Advisor 방식
// @EnableMethodSecurity: AuthorizationManager 방식 (더 유연, 타입 안전)
```

---

## ✨ 올바른 보안 구현

### 어노테이션별 선택 가이드

```java
@RestController
@RequiredArgsConstructor
public class OrderController {

    // ── @PreAuthorize: 가장 강력, SpEL 완전 지원 (권장) ──────────────
    @GetMapping("/orders/{id}")
    @PreAuthorize("hasRole('USER') and @orderSecurity.isOwner(#id, authentication)")
    public Order getOrder(@PathVariable Long id) { ... }

    // ── @PostAuthorize: 반환값 기반 검사 ─────────────────────────────
    @GetMapping("/orders/{id}/detail")
    @PostAuthorize("returnObject.ownerId == authentication.principal.userId")
    public Order getOrderDetail(@PathVariable Long id) {
        // 메서드가 먼저 실행 → 반환값에 대해 권한 검사
        // 실패 시 AccessDeniedException (이미 실행됐으므로 DB 조회는 발생)
        return orderRepository.findById(id).orElseThrow();
    }

    // ── @PreFilter: 컬렉션 파라미터 필터링 ─────────────────────────
    @PostMapping("/orders/batch-cancel")
    @PreFilter("filterObject.ownerId == authentication.principal.userId")
    public void cancelOrders(@RequestBody List<Order> orders) {
        // orders 리스트에서 현재 사용자 소유 주문만 남김
        // 다른 사용자 주문은 리스트에서 제거
        orders.forEach(orderService::cancel);
    }

    // ── @PostFilter: 컬렉션 반환값 필터링 ──────────────────────────
    @GetMapping("/orders")
    @PostFilter("filterObject.ownerId == authentication.principal.userId")
    public List<Order> getAllOrders() {
        // 모든 주문 조회 후, 현재 사용자 소유 주문만 반환
        // 대용량 데이터에서는 성능 문제 가능 → DB 쿼리 레벨 필터링 권장
        return orderRepository.findAll();
    }

    // ── @Secured: 단순 역할 검사 (SpEL 없음) ─────────────────────────
    @DeleteMapping("/orders/{id}")
    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"}) // OR 조건
    public void deleteOrder(@PathVariable Long id) { ... }

    // ── @RolesAllowed: JSR-250 표준 (Jakarta EE 호환) ────────────────
    @PutMapping("/orders/{id}")
    @RolesAllowed("ROLE_USER")
    public Order updateOrder(@PathVariable Long id,
                              @RequestBody OrderUpdateRequest request) { ... }
}
```

---

## 🔬 내부 동작 원리

### 1. 각 어노테이션의 처리 클래스 구조

```java
// @EnableMethodSecurity 활성화 시 등록되는 Interceptor들

// ① @PreAuthorize / @PostAuthorize / @PreFilter / @PostFilter 처리
// → PreAuthorizeAuthorizationManager (SpEL 평가)
// → PostAuthorizeAuthorizationManager
// → PreFilterAuthorizationMethodInterceptor
// → PostFilterAuthorizationMethodInterceptor

// ② @Secured 처리 (securedEnabled=true 시)
// → SecuredAuthorizationManager
// → 단순 문자열 비교 (SpEL 없음)

// ③ @RolesAllowed 처리 (jsr250Enabled=true 시)
// → Jsr250AuthorizationManager
// → @PermitAll, @DenyAll도 처리

// 처리 흐름:
// 메서드 호출
//   → AOP Proxy 인터셉트
//   → AuthorizationManagerBeforeMethodInterceptor
//      → PreAuthorizeAuthorizationManager.check()
//         → MethodSecurityExpressionHandler로 SpEL 평가
//         → ACCESS_GRANTED or ACCESS_DENIED
//   → 실제 메서드 실행
//   → AuthorizationManagerAfterMethodInterceptor (PostAuthorize)
```

### 2. PreAuthorizeAuthorizationManager — SpEL 평가 과정

```java
// PreAuthorizeAuthorizationManager.java
public final class PreAuthorizeAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    private final MethodSecurityExpressionHandler expressionHandler;

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            MethodInvocation invocation) {

        // ① 메서드에서 @PreAuthorize 어노테이션 추출
        PreAuthorize preAuthorize = findAnnotation(invocation);
        if (preAuthorize == null) {
            return null; // 어노테이션 없음 → 다음 처리로
        }

        // ② SpEL 표현식 컴파일 (캐시됨)
        ExpressionSource expressionSource = expressionHandler
            .getExpressionParser()
            .parseExpression(preAuthorize.value());

        // ③ EvaluationContext 생성 (Authentication, 메서드 파라미터 바인딩)
        EvaluationContext ctx = expressionHandler.createEvaluationContext(
            authentication,   // SecurityContextHolder.getContext().getAuthentication()
            invocation        // 메서드 파라미터 (#id, #order 등 접근 가능)
        );

        // ④ SpEL 평가
        boolean granted = (boolean) expressionSource.getValue(ctx);
        return new ExpressionAttributeAuthorizationDecision(granted, expressionSource);
    }
}
```

### 3. @Secured와 @PreAuthorize의 처리 비교

```java
// SecuredAuthorizationManager.java (@Secured 처리)
public final class SecuredAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            MethodInvocation invocation) {

        Secured secured = findAnnotation(invocation);
        if (secured == null) return null;

        // SpEL 없이 단순 문자열 비교
        // @Secured({"ROLE_ADMIN", "ROLE_USER"}) → OR 조건
        Set<String> allowedRoles = Set.of(secured.value());

        // getAuthorities()에서 정확히 일치하는 문자열 검색
        // → "ROLE_" 접두사 자동 추가 없음!
        boolean granted = authentication.get()
            .getAuthorities()
            .stream()
            .map(GrantedAuthority::getAuthority)
            .anyMatch(allowedRoles::contains);

        return new AuthorizationDecision(granted);
    }
}

// 차이 정리:
// @PreAuthorize("hasRole('ADMIN')")    → SpEL → "ROLE_ADMIN" 자동 추가
// @Secured("ROLE_ADMIN")              → 단순 비교 → "ROLE_ADMIN" 그대로
// @RolesAllowed("ROLE_ADMIN")         → Jsr250와 동일 → "ROLE_ADMIN" 그대로
```

### 4. @EnableMethodSecurity vs @EnableGlobalMethodSecurity 내부 차이

```java
// @EnableGlobalMethodSecurity (5.x, deprecated)
// → MethodSecurityInterceptor (AOP Alliance MethodInterceptor)
// → GlobalMethodSecurityConfiguration 클래스를 상속해서 커스터마이징
// → AccessDecisionManager + AfterInvocationManager 구조

// @EnableMethodSecurity (6.x, 현재)
// → AuthorizationManagerBeforeMethodInterceptor
//   + AuthorizationManagerAfterMethodInterceptor
// → @Bean으로 커스터마이징 (상속 불필요)
// → AuthorizationManager<MethodInvocation> 타입 안전 API

// @EnableMethodSecurity의 기본 활성화 설정:
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(MethodSecuritySelector.class)
public @interface EnableMethodSecurity {
    boolean prePostEnabled() default true;   // @Pre/@PostAuthorize 기본 ON
    boolean securedEnabled() default false;  // @Secured 기본 OFF
    boolean jsr250Enabled() default false;   // @RolesAllowed 기본 OFF
    boolean proxyTargetClass() default false;
    AdviceMode mode() default AdviceMode.PROXY; // PROXY 또는 ASPECTJ
}
```

### 5. 어노테이션 중첩 시 실행 순서

```java
// 같은 메서드에 여러 어노테이션:
@PreAuthorize("hasRole('USER')")     // 먼저 검사
@Secured("ROLE_ADMIN")               // 다음 검사
@RolesAllowed("ROLE_USER")           // 마지막 검사
public void multiAnnotatedMethod() { ... }

// 실행 순서:
// 1. @PreAuthorize (PreAuthorizeAuthorizationManager)
// 2. @Secured (SecuredAuthorizationManager)
// 3. @RolesAllowed (Jsr250AuthorizationManager)
// 셋 중 하나라도 AccessDeniedException → 메서드 실행 안 됨

// Interceptor 순서는 @Order로 결정:
// AuthorizationManagerBeforeMethodInterceptor for @PreAuthorize: 500
// AuthorizationManagerBeforeMethodInterceptor for @Secured:      500 (same)
// → 실제 순서는 등록 순서에 따라 결정 (일반적으로 @PreAuthorize 먼저)

// 권장: 한 메서드에 하나의 어노테이션만 사용 (혼용 시 혼란)
```

### 6. @PostFilter 내부 동작 — 주의 필요

```java
// @PostFilter 처리 흐름:
@GetMapping("/orders")
@PostFilter("filterObject.status == 'ACTIVE'")
public List<Order> getOrders() {
    return orderRepository.findAll(); // 10,000개 반환
}

// ① 메서드 실행 → 10,000개 Order 로드
// ② PostFilterAuthorizationMethodInterceptor가 반환값 인터셉트
// ③ 각 filterObject에 대해 SpEL 평가
// ④ false인 항목 제거 → ACTIVE 상태만 반환

// ⚠️ 성능 주의:
// DB에서 10,000개 로드 후 메모리에서 필터링 → 비효율
// 대용량 데이터: DB 쿼리 레벨에서 필터링 권장
// @PostFilter는 소량 데이터나 캐시된 데이터에 적합
```

---

## 💻 실험으로 확인하기

### 실험 1: 세 어노테이션 동작 비교

```java
@SpringBootTest
@WithMockUser(roles = "ADMIN")
class AnnotationComparisonTest {

    @Autowired
    TestService testService;

    @Test
    void preAuthorize_hasRole_withRolePrefix_works() {
        // @PreAuthorize("hasRole('ADMIN')") → "ROLE_ADMIN" 검색 → 통과
        assertDoesNotThrow(() -> testService.preAuthorizeMethod());
    }

    @Test
    void secured_withoutRolePrefix_fails() {
        // @Secured("ADMIN") → "ADMIN" 검색 → @WithMockUser(roles="ADMIN")은
        // "ROLE_ADMIN"으로 권한 부여 → "ADMIN" 미일치 → 403
        assertThatThrownBy(() -> testService.securedWithoutPrefix())
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void secured_withRolePrefix_works() {
        // @Secured("ROLE_ADMIN") → "ROLE_ADMIN" 검색 → 통과
        assertDoesNotThrow(() -> testService.securedWithPrefix());
    }
}
```

### 실험 2: @PostAuthorize 실행 흐름 확인

```java
@Service
public class TestService {

    @PostAuthorize("returnObject.ownerId == 1L")
    public Order getOrderPostAuth(Long id) {
        System.out.println("메서드 실행됨"); // 반드시 출력됨
        return orderRepository.findById(id).orElseThrow();
    }
}
```

```java
@Test
@WithMockUser(username = "user", roles = "USER")
void postAuthorize_methodExecutesFirst_thenChecks() {
    // 메서드가 먼저 실행(DB 조회 발생)된 후 returnObject 검사
    // ownerId가 1L이 아니면 AccessDeniedException
    assertThatThrownBy(() -> testService.getOrderPostAuth(99L))
        .isInstanceOf(AccessDeniedException.class);
    // 하지만 "메서드 실행됨" 로그는 이미 출력됨
}
```

### 실험 3: @PreFilter 동작 확인

```java
@Service
public class OrderService {

    @PreFilter(value = "filterObject.ownerId == authentication.principal.userId",
               filterTarget = "orders") // 여러 파라미터일 때 명시
    public void cancelOrders(List<Order> orders) {
        System.out.println("Filtered count: " + orders.size());
        orders.forEach(this::cancel);
    }
}
```

```java
@Test
@WithMockUser(username = "user1")
void preFilter_removesOtherUsersOrders() {
    List<Order> mixed = List.of(
        new Order(1L, "user1"),  // 남아야 함
        new Order(2L, "user2"),  // 제거됨
        new Order(3L, "user1")   // 남아야 함
    );
    orderService.cancelOrders(new ArrayList<>(mixed));
    // 내부에서 "Filtered count: 2" 출력
}
```

---

## 🔒 보안 체크리스트

```
어노테이션 선택
  ☐ SpEL 표현식이 필요하면 @PreAuthorize 사용
  ☐ 단순 역할 검사면 @Secured 또는 @PreAuthorize("hasRole") 사용
  ☐ Jakarta EE 표준 호환 필요 시 @RolesAllowed 사용
  ☐ @Secured, @RolesAllowed에 ROLE_ 접두사 명시

활성화 설정
  ☐ @EnableMethodSecurity 사용 (6.x 프로젝트)
  ☐ securedEnabled=true, jsr250Enabled=true 필요 시만 활성화

@PostAuthorize 사용 주의
  ☐ 메서드가 먼저 실행됨을 인지 (부작용 가능)
  ☐ 읽기 전용 작업에만 적용 (DB 수정 후 권한 실패 시 롤백 필요)

@PostFilter 성능
  ☐ 대용량 컬렉션에 @PostFilter 적용 금지
  ☐ DB 쿼리에서 조건 처리 후 소량 결과에만 사용
```

---

## 🤔 트레이드오프

```
@PreAuthorize vs @Secured:
  @PreAuthorize:
    장점  SpEL로 복잡한 조건 표현 가능 (도메인 객체 기반, 파라미터 참조)
          hasRole() 자동 접두사 처리
    단점  SpEL 실수 시 런타임 오류 (컴파일 타임 검증 없음)
          복잡한 표현식은 가독성 저하

  @Secured:
    장점  단순하고 명확, 컴파일 타임 오류 없음
    단점  SpEL 없음 → 복잡한 조건 표현 불가
          ROLE_ 접두사 수동 관리

@PostAuthorize vs @PreAuthorize (읽기 보안):
  @PreAuthorize:
    장점  메서드 실행 전 차단 → DB 조회 발생 안 함 (효율적)
    단점  파라미터(ID)만 가지고 권한 판단 → 추가 DB 조회 필요할 수 있음

  @PostAuthorize:
    장점  반환 객체를 직접 검사 → 추가 DB 조회 없음
    단점  메서드는 항상 실행됨 → DB 조회 발생 (효율적이지 않을 수 있음)
    → 간단한 소유권 검사는 @PostAuthorize가 코드 간결
    → 복잡한 검사나 부작용 있는 메서드는 @PreAuthorize 권장
```

---

## 📌 핵심 정리

```
세 어노테이션 처리 클래스
  @PreAuthorize   → PreAuthorizeAuthorizationManager (SpEL 지원)
  @Secured        → SecuredAuthorizationManager (단순 문자열 비교)
  @RolesAllowed   → Jsr250AuthorizationManager (단순 문자열 비교)

접두사 처리 차이
  @PreAuthorize("hasRole('ADMIN')")  → "ROLE_ADMIN" 자동 추가
  @Secured("ROLE_ADMIN")            → ROLE_ 명시 필요
  @RolesAllowed("ROLE_ADMIN")       → ROLE_ 명시 필요

@EnableMethodSecurity (6.x) 기본값
  prePostEnabled=true, securedEnabled=false, jsr250Enabled=false
  커스터마이징: @Bean 방식 (GlobalMethodSecurityConfiguration 상속 불필요)

@PreFilter / @PostFilter
  컬렉션 파라미터/반환값에서 조건을 만족하지 않는 항목 제거
  @PostFilter는 메서드 실행 후 동작 → 대용량 데이터에 성능 주의
```

---

## 🤔 생각해볼 문제

**Q1.** `@PreAuthorize`를 사용하는 Service Bean에 대해 Spring이 Proxy를 생성합니다. `UserService` 내부에서 `this.adminMethod()`를 호출하면 `@PreAuthorize`가 동작하는가? 동작하지 않는다면 그 이유는 무엇인가?

**Q2.** `@PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.userId")`에서 `#userId`는 어떻게 메서드 파라미터와 바인딩되는가? Java 컴파일 시 `-parameters` 옵션이 없으면 어떤 문제가 발생하는가?

**Q3.** `@PostAuthorize`로 보호된 메서드에서 DB를 수정하는 작업(`@Transactional`과 함께)을 수행했을 때 권한 검사 실패로 `AccessDeniedException`이 발생하면 트랜잭션은 어떻게 되는가?

> 💡 **해설**
>
> **Q1.** `this.adminMethod()` 직접 호출은 AOP Proxy를 거치지 않습니다. Spring AOP는 Proxy 패턴 기반으로, 외부에서 Bean을 주입받아 호출할 때만 Proxy가 인터셉트합니다. 같은 클래스 내부 `this.` 호출은 Proxy를 우회해 실제 객체 메서드를 직접 호출하므로 `@PreAuthorize` 검사가 실행되지 않습니다. 해결 방법은 자신을 `@Autowired`로 주입받아(`self injection`) 호출하거나, `ApplicationContext.getBean()`으로 Proxy를 거쳐 호출하거나, AspectJ 위빙(`mode=ASPECTJ`)을 사용하는 것입니다.
>
> **Q2.** SpEL에서 `#userId`는 `MethodSecurityExpressionHandler`가 `MethodInvocation`의 파라미터 이름을 통해 바인딩합니다. Java 컴파일 시 `-parameters` 옵션이 없으면 바이트코드에 파라미터 이름이 포함되지 않아 `#userId` 대신 `#arg0`처럼 인덱스로만 접근 가능합니다. Spring Boot는 기본적으로 `-parameters` 옵션을 활성화하므로 대부분 문제없지만, Gradle/Maven 설정을 직접 다루는 경우 명시적으로 확인이 필요합니다. 대안으로 `@P("userId")` 어노테이션으로 파라미터 이름을 명시할 수 있습니다.
>
> **Q3.** `@Transactional`과 `@PostAuthorize`가 함께 사용될 때 AOP Interceptor 순서가 중요합니다. 기본적으로 `@Transactional`의 `TransactionInterceptor`와 `AuthorizationManagerAfterMethodInterceptor`의 순서에 따라 달라집니다. `@PostAuthorize` Interceptor가 트랜잭션 범위 바깥에서 실행되면 DB 수정 후 커밋된 상태에서 `AccessDeniedException`이 발생해 롤백이 안 됩니다. `@PostAuthorize` Interceptor가 트랜잭션 범위 안에서 실행되면 예외 발생 시 트랜잭션이 롤백됩니다. 이 모호성 때문에 부작용이 있는 메서드에는 `@PostAuthorize`보다 `@PreAuthorize`를 사용하는 것이 안전합니다.

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: Method Security 동작 원리 (AOP Proxy) ➡️](./02-method-security-aop.md)**

</div>
