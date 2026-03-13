# SpEL을 활용한 복잡한 권한 검사 — PermissionEvaluator와 도메인 객체 기반 권한

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `hasPermission(targetDomainObject, permission)` SpEL이 `PermissionEvaluator`를 어떻게 호출하는가?
- `PermissionEvaluator`의 두 가지 `hasPermission` 메서드 시그니처의 차이는?
- `@beanName.method()` 패턴과 `PermissionEvaluator` 중 어떤 경우에 무엇을 선택해야 하는가?
- `@PreAuthorize`의 SpEL에서 Spring Bean, 메서드 파라미터, 반환값을 모두 조합하는 방법은?
- 커스텀 `SecurityExpressionRoot`를 만들어 `@PreAuthorize`에서 사용할 수 있는 새 메서드를 추가하는 방법은?
- SpEL 표현식 테스트를 효과적으로 작성하는 방법은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 단순 역할 검사를 넘어선 도메인 객체 기반 권한

```
일반적인 권한 체계:
  ROLE_USER → 모든 사용자 공통 기능
  ROLE_ADMIN → 관리자 기능

  한계: "kim은 ROLE_USER이므로 모든 주문에 접근 가능"
       → 실제로는 자신의 주문만 보거나 수정할 수 있어야 함

도메인 객체 기반 권한 (Object-level Security):
  "kim은 order#42를 READ할 수 있는가?"
  → 역할뿐 아니라 구체적인 객체와 작업을 결합해서 판단

Spring Security 지원:
  hasPermission(targetObject, 'read')
  hasPermission(targetId, 'Order', 'delete')
  → PermissionEvaluator 인터페이스로 이 로직을 구현
```

---

## 😱 흔한 보안 실수

### Before: SpEL에 직접 복잡한 로직 작성

```java
// ❌ 너무 복잡한 SpEL → 테스트 불가, 가독성 최악
@PreAuthorize(
    "hasRole('ADMIN') or " +
    "(hasRole('USER') and " +
    " T(com.example.SecurityUtils).getCurrentUserId() == " +
    " @orderRepository.findById(#orderId).orElseThrow().getOwnerId() and " +
    " @orderRepository.findById(#orderId).orElseThrow().getStatus() != " +
    " T(com.example.OrderStatus).CANCELLED)"
)
public Order updateOrder(Long orderId, OrderUpdateRequest request) { ... }

// 문제:
// → orderRepository.findById() 두 번 호출 (N+1 성 문제)
// → 단위 테스트 시 모든 의존성 Mock 필요
// → SpEL 오류는 런타임에서만 발견

// ✅ 복잡한 로직은 PermissionEvaluator 또는 @Bean으로 위임
@PreAuthorize("hasPermission(#orderId, 'Order', 'update')")
public Order updateOrder(Long orderId, OrderUpdateRequest request) { ... }
```

### Before: hasPermission에서 N+1 조회 발생

```java
// ❌ PermissionEvaluator에서 같은 객체를 여러 번 로드
@Component
public class OrderPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication auth,
                                  Object targetDomainObject,
                                  Object permission) {
        if (targetDomainObject instanceof Long orderId) {
            // DB 조회 발생 → 메서드 내에서 또 조회하면 중복
            Order order = orderRepository.findById(orderId).orElseThrow();
            ...
        }
    }
}

// ✅ hasPermission(domainObject, permission) 시그니처 활용
// 이미 로드된 객체를 전달하면 추가 조회 없음
@PostAuthorize("hasPermission(returnObject, 'read')")
public Order getOrder(Long id) {
    return orderRepository.findById(id).orElseThrow(); // 한 번만 조회
}
// returnObject(Order)가 PermissionEvaluator로 전달됨 → 추가 DB 조회 없음
```

---

## ✨ 올바른 보안 구현

### PermissionEvaluator 구현 패턴

```java
@Component
public class DomainPermissionEvaluator implements PermissionEvaluator {

    private final OrderRepository orderRepository;
    private final ProjectRepository projectRepository;

    /**
     * 이미 로드된 도메인 객체에 대한 권한 검사
     * @PostAuthorize("hasPermission(returnObject, 'read')")
     */
    @Override
    public boolean hasPermission(Authentication authentication,
                                  Object targetDomainObject,
                                  Object permission) {
        if (targetDomainObject == null) return false;

        String targetType = targetDomainObject.getClass().getSimpleName();
        return checkPermission(authentication, targetDomainObject,
            targetType, permission.toString());
    }

    /**
     * ID와 타입으로 도메인 객체를 지연 로드 후 권한 검사
     * @PreAuthorize("hasPermission(#orderId, 'Order', 'write')")
     */
    @Override
    public boolean hasPermission(Authentication authentication,
                                  Serializable targetId,
                                  String targetType,
                                  Object permission) {
        Object domainObject = loadDomainObject(targetId, targetType);
        if (domainObject == null) return false;
        return checkPermission(authentication, domainObject,
            targetType, permission.toString());
    }

    private boolean checkPermission(Authentication auth,
                                     Object domainObject,
                                     String targetType,
                                     String permission) {
        CustomUserDetails user = (CustomUserDetails) auth.getPrincipal();

        return switch (targetType) {
            case "Order" -> checkOrderPermission(user, (Order) domainObject, permission);
            case "Project" -> checkProjectPermission(user, (Project) domainObject, permission);
            default -> false;
        };
    }

    private boolean checkOrderPermission(CustomUserDetails user,
                                          Order order, String permission) {
        // ADMIN은 모든 작업 가능
        if (hasRole(user, "ADMIN")) return true;

        return switch (permission) {
            case "read" -> order.getOwnerId().equals(user.getUserId())
                || order.isPublic();
            case "write", "update" -> order.getOwnerId().equals(user.getUserId())
                && order.getStatus() != OrderStatus.CANCELLED;
            case "delete" -> order.getOwnerId().equals(user.getUserId())
                && hasRole(user, "PREMIUM");
            default -> false;
        };
    }

    private Object loadDomainObject(Serializable id, String type) {
        return switch (type) {
            case "Order" -> orderRepository.findById((Long) id).orElse(null);
            case "Project" -> projectRepository.findById((Long) id).orElse(null);
            default -> null;
        };
    }

    private boolean hasRole(CustomUserDetails user, String role) {
        return user.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + role));
    }
}

// PermissionEvaluator를 MethodSecurityExpressionHandler에 등록
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            DomainPermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler =
            new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }
}
```

---

## 🔬 내부 동작 원리

### 1. hasPermission() SpEL 평가 흐름

```java
// @PreAuthorize("hasPermission(#orderId, 'Order', 'read')")
// 실행 시:

// ① SpEL: hasPermission(#orderId, 'Order', 'read')
// ② MethodSecurityExpressionRoot.hasPermission() 호출
public boolean hasPermission(Object targetId, String targetType, Object permission) {
    // PermissionEvaluator로 위임
    return this.permissionEvaluator.hasPermission(
        this.authentication.get(), // 현재 Authentication
        (Serializable) targetId,   // #orderId 값
        targetType,                 // "Order"
        permission                  // "read"
    );
}

// ③ DomainPermissionEvaluator.hasPermission() 실행
// ④ Order 객체 로드 → 권한 검사 → boolean 반환
// ⑤ false → AccessDeniedException
```

### 2. 두 가지 hasPermission 시그니처

```java
// 시그니처 1: 이미 로드된 객체 전달
// hasPermission(targetDomainObject, permission)
// 사용 위치: @PostAuthorize (returnObject 전달)
@PostAuthorize("hasPermission(returnObject, 'read')")
public Order getOrder(Long id) { ... }
// returnObject = 이미 DB에서 로드된 Order 객체
// → PermissionEvaluator.hasPermission(auth, order, "read")

// 시그니처 2: ID + 타입으로 지연 로드
// hasPermission(targetId, targetType, permission)
// 사용 위치: @PreAuthorize (ID만 있을 때)
@PreAuthorize("hasPermission(#orderId, 'Order', 'write')")
public void updateOrder(Long orderId, ...) { ... }
// → PermissionEvaluator.hasPermission(auth, orderId, "Order", "write")
// → PermissionEvaluator 내부에서 orderRepository.findById(orderId) 실행

// 선택 기준:
// @PreAuthorize + 시그니처 2: 메서드 실행 전 차단 (DB 조회 발생)
// @PostAuthorize + 시그니처 1: 반환값 재사용 (추가 DB 조회 없음)
```

### 3. 커스텀 SecurityExpressionRoot — 새 메서드 추가

```java
// 커스텀 표현식 루트
public class CustomMethodSecurityExpressionRoot
        extends SecurityExpressionRoot
        implements MethodSecurityExpressionOperations {

    private final SubscriptionService subscriptionService;
    private Object filterObject;
    private Object returnObject;

    public CustomMethodSecurityExpressionRoot(
            Supplier<Authentication> authentication,
            SubscriptionService subscriptionService) {
        super(authentication);
        this.subscriptionService = subscriptionService;
    }

    // @PreAuthorize에서 isPremiumUser()로 직접 호출 가능
    public boolean isPremiumUser() {
        CustomUserDetails user = (CustomUserDetails) getAuthentication().getPrincipal();
        return subscriptionService.isPremium(user.getUserId());
    }

    // @PreAuthorize("hasFeatureAccess('advanced-analytics')")
    public boolean hasFeatureAccess(String featureName) {
        CustomUserDetails user = (CustomUserDetails) getAuthentication().getPrincipal();
        return subscriptionService.hasFeature(user.getUserId(), featureName);
    }

    // MethodSecurityExpressionOperations 구현
    @Override public void setFilterObject(Object filterObject) { this.filterObject = filterObject; }
    @Override public Object getFilterObject() { return filterObject; }
    @Override public void setReturnObject(Object returnObject) { this.returnObject = returnObject; }
    @Override public Object getReturnObject() { return returnObject; }
    @Override public Object getThis() { return null; }
}

// 커스텀 ExpressionHandler 등록
@Configuration
@EnableMethodSecurity
public class CustomMethodSecurityConfig {

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            SubscriptionService subscriptionService) {

        return new DefaultMethodSecurityExpressionHandler() {
            @Override
            protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
                    Authentication authentication, MethodInvocation invocation) {
                CustomMethodSecurityExpressionRoot root =
                    new CustomMethodSecurityExpressionRoot(
                        () -> authentication, subscriptionService);
                root.setPermissionEvaluator(getPermissionEvaluator());
                root.setTrustResolver(getTrustResolver());
                root.setRoleHierarchy(getRoleHierarchy());
                return root;
            }
        };
    }
}

// 사용:
@GetMapping("/analytics/advanced")
@PreAuthorize("isPremiumUser() and hasFeatureAccess('advanced-analytics')")
public AnalyticsReport getAdvancedAnalytics() { ... }
```

### 4. SpEL 표현식 전체 변수 레퍼런스

```java
// Method Security SpEL에서 사용 가능한 모든 것:

// ── 내장 메서드 ────────────────────────────────────────────────────
// hasRole('ADMIN')                  → "ROLE_ADMIN" 검사
// hasAnyRole('USER', 'ADMIN')       → OR 조건
// hasAuthority('READ_ORDERS')       → 정확한 문자열 검사
// isAuthenticated()                 → 익명 아님
// isFullyAuthenticated()            → 폼 로그인 (Remember-Me 아님)
// isAnonymous()                     → 익명 사용자
// isRememberMe()                    → Remember-Me 인증
// permitAll()                       → 항상 true
// denyAll()                         → 항상 false
// hasPermission(obj, perm)          → PermissionEvaluator 호출
// hasPermission(id, type, perm)     → PermissionEvaluator 호출
// hasIpAddress('192.168.0.0/24')    → IP 범위 검사 (HTTP 컨텍스트)

// ── 변수 ──────────────────────────────────────────────────────────
// authentication                    → Authentication 객체
// principal                         → authentication.getPrincipal()
// #paramName                        → 메서드 파라미터
// returnObject                      → @PostAuthorize: 반환값
// filterObject                      → @Pre/@PostFilter: 컬렉션 각 요소

// ── @Bean 참조 ────────────────────────────────────────────────────
// @beanName.method(args)            → ApplicationContext의 Bean 직접 호출

// ── 정적 클래스 참조 ──────────────────────────────────────────────
// T(java.time.LocalTime).now().hour → 정적 메서드/필드 접근
// T(com.example.Status).ACTIVE      → enum 상수 참조
```

---

## 💻 실험으로 확인하기

### 실험 1: PermissionEvaluator 단위 테스트

```java
@ExtendWith(MockitoExtension.class)
class DomainPermissionEvaluatorTest {

    @Mock OrderRepository orderRepository;
    @InjectMocks DomainPermissionEvaluator evaluator;

    @Test
    void owner_canRead_ownOrder() {
        // given
        Order order = new Order(42L, 1L, OrderStatus.ACTIVE); // id, ownerId, status
        Authentication auth = mockAuthentication(1L, "ROLE_USER");

        // when
        boolean result = evaluator.hasPermission(auth, order, "read");

        // then
        assertTrue(result);
        verifyNoInteractions(orderRepository); // 이미 로드된 객체 → DB 조회 없음
    }

    @Test
    void nonOwner_cannotWrite_othersOrder() {
        Order order = new Order(42L, 2L, OrderStatus.ACTIVE); // ownerId=2, requester=1
        Authentication auth = mockAuthentication(1L, "ROLE_USER");

        boolean result = evaluator.hasPermission(auth, order, "write");
        assertFalse(result);
    }

    @Test
    void admin_canDelete_anyOrder() {
        Order order = new Order(42L, 99L, OrderStatus.ACTIVE);
        Authentication auth = mockAuthentication(1L, "ROLE_USER", "ROLE_ADMIN");

        boolean result = evaluator.hasPermission(auth, order, "delete");
        assertTrue(result);
    }
}
```

### 실험 2: 커스텀 SpEL 메서드 테스트

```java
// @PreAuthorize("isPremiumUser()") 테스트
@SpringBootTest
class CustomSpElMethodTest {

    @Autowired TestService testService;
    @MockBean SubscriptionService subscriptionService;

    @Test
    @WithMockUser("kim")
    void premiumUser_canAccessPremiumFeature() {
        when(subscriptionService.isPremium(anyLong())).thenReturn(true);
        assertDoesNotThrow(() -> testService.premiumMethod());
    }

    @Test
    @WithMockUser("lee")
    void freeUser_cannotAccessPremiumFeature() {
        when(subscriptionService.isPremium(anyLong())).thenReturn(false);
        assertThatThrownBy(() -> testService.premiumMethod())
            .isInstanceOf(AccessDeniedException.class);
    }
}
```

### 실험 3: @beanName 패턴 vs PermissionEvaluator 비교

```bash
# @beanName 패턴:
@PreAuthorize("@orderSecurity.canUpdate(#orderId, authentication)")
# → OrderSecurity.canUpdate() 메서드 내에서 로직 구현
# → 단위 테스트 용이, IDE 지원

# PermissionEvaluator:
@PreAuthorize("hasPermission(#orderId, 'Order', 'update')")
# → DomainPermissionEvaluator.hasPermission() 위임
# → 타입(Order)별로 중앙 집중 관리
# → 여러 어노테이션에서 동일 평가기 재사용
```

---

## 🔒 보안 체크리스트

```
PermissionEvaluator 구현
  ☐ null targetDomainObject → false 반환 (예외 throw 금지)
  ☐ 알 수 없는 targetType → false 반환 (기본 거부)
  ☐ 알 수 없는 permission → false 반환 (기본 거부)
  ☐ ADMIN 권한 처리 명시적으로 구현 (잊기 쉬움)

SpEL 표현식 설계
  ☐ 복잡한 로직은 @beanName 또는 PermissionEvaluator로 위임
  ☐ DB 조회를 포함한 로직을 SpEL에 직접 작성 금지
  ☐ T(Class).static... 패턴은 테스트하기 어려움 → Bean 주입 방식으로 대체

테스트
  ☐ PermissionEvaluator 단위 테스트 (각 경우의 수)
  ☐ @WithMockUser, @WithUserDetails로 다양한 역할 테스트
  ☐ 경계 케이스: 소유자, 비소유자, 관리자, 만료된 리소스 등
```

---

## 🤔 트레이드오프

```
@beanName.method() vs PermissionEvaluator:
  @beanName.method():
    장점  메서드 이름이 의도를 표현, IDE 자동완성, 직관적
          각 도메인마다 별도 Bean 분리 가능
    단점  Bean이 많아지면 관리 복잡, 이름 충돌 가능
          hasPermission() SpEL과 방식이 달라 혼용 시 혼란

  PermissionEvaluator:
    장점  중앙 집중 관리, 도메인 객체 전달로 N+1 방지
          @PostAuthorize의 returnObject와 자연스럽게 연동
          ACL(Access Control List) 시스템과 통합 용이
    단점  타입 분기 로직(instanceof/switch)이 비대해질 수 있음
          새 도메인 타입 추가마다 PermissionEvaluator 수정 필요

커스텀 SecurityExpressionRoot:
  장점  도메인 특화 메서드를 SpEL에서 직접 사용 가능
        코드 재사용, 가독성 향상
  단점  구현이 복잡 (DefaultMethodSecurityExpressionHandler 확장)
        Spring 내부 클래스에 의존 → 업그레이드 시 주의
```

---

## 📌 핵심 정리

```
hasPermission() SpEL 두 가지 형태
  hasPermission(domainObject, permission)
    → 이미 로드된 객체 전달 (@PostAuthorize의 returnObject 등)
    → PermissionEvaluator.hasPermission(auth, domainObject, perm)
  hasPermission(targetId, targetType, permission)
    → ID+타입으로 PermissionEvaluator 내에서 지연 로드
    → PermissionEvaluator.hasPermission(auth, id, type, perm)

PermissionEvaluator 설계 원칙
  알 수 없는 입력 → false (기본 거부)
  ADMIN 처리 명시
  @PostAuthorize + domainObject 전달 → 추가 DB 조회 없음

커스텀 SpEL 메서드 추가
  CustomMethodSecurityExpressionRoot 작성
  DefaultMethodSecurityExpressionHandler 확장 + @Bean 등록
  → @PreAuthorize("isPremiumUser()") 등 커스텀 메서드 사용 가능

복잡도 관리 원칙
  SpEL은 간단한 조합만 (1~2개 조건)
  복잡한 로직 → @beanName.method() 또는 PermissionEvaluator
  PermissionEvaluator → 도메인 객체 수준 ACL 통합에 적합
```

---

## 🤔 생각해볼 문제

**Q1.** `@PreAuthorize("hasPermission(#orderId, 'Order', 'read')")`에서 `PermissionEvaluator`가 `orderRepository.findById(orderId)`를 호출합니다. 이후 실제 메서드 본문에서도 `orderRepository.findById(orderId)`를 호출합니다. 이 두 번의 DB 조회를 줄이는 방법을 두 가지 이상 제시하라.

**Q2.** `PermissionEvaluator.hasPermission(Authentication auth, Object targetDomainObject, Object permission)`에서 `targetDomainObject`가 JPA `@Proxy`(지연 로딩 프록시)일 때 `instanceof` 검사가 실패하는 이유와 해결 방법은?

**Q3.** `@PreFilter`와 `@PostFilter`에서 `filterObject`는 컬렉션의 각 요소를 나타냅니다. `hasPermission(filterObject, 'read')`를 `@PostFilter`에서 사용하면 각 요소마다 `PermissionEvaluator`가 호출됩니다. 1000개 결과에서 `hasPermission`이 1000번 DB 조회를 한다면 어떻게 최적화하는가?

> 💡 **해설**
>
> **Q1.** 첫 번째 방법은 `@PostAuthorize`와 `returnObject` 사용입니다. `@PostAuthorize("hasPermission(returnObject, 'read')")`로 전환하면 메서드가 먼저 한 번 조회하고 그 결과를 `PermissionEvaluator`에 전달합니다. 두 번째 방법은 Spring Cache를 활용하는 것입니다. `@Cacheable("orders")`를 `findById()`에 적용해 같은 요청 내에서 첫 번째 호출 결과를 캐시하면 두 번째 호출이 캐시에서 반환됩니다. 세 번째 방법은 `PermissionEvaluator`에서 이미 확인한 결과를 request-scoped Bean에 저장해두고 메서드에서 재사용하는 것입니다.
>
> **Q2.** JPA 지연 로딩 프록시는 `Order$$HibernateProxyXXX` 같은 서브클래스 프록시입니다. `targetDomainObject instanceof Order`는 `true`를 반환하지만 `targetDomainObject.getClass().getSimpleName()`은 `"Order$$HibernateProxyXXX"`를 반환합니다. `switch (targetType)` 에서 `"Order"` 케이스에 매칭되지 않아 처리가 실패합니다. 해결 방법은 `Hibernate.getClass(domainObject).getSimpleName()`을 사용하거나, `ClassUtils.getUserClass(domainObject.getClass()).getSimpleName()`(Spring 유틸리티)을 사용해 프록시의 실제 타입 이름을 얻는 것입니다. 또는 `instanceof` 패턴 매칭으로 타입 분기를 하면 Hibernate 프록시도 `Order`의 서브클래스이므로 올바르게 처리됩니다.
>
> **Q3.** 배치 최적화 전략이 필요합니다. `@PostFilter`를 제거하고 Service 계층에서 직접 배치 처리하는 방법이 있습니다. 조회된 1000개의 ID 목록을 한 번에 권한 DB에서 조회해(`WHERE id IN (...)`) 허용된 ID Set을 만들고, Java Stream으로 필터링합니다. 또는 DB 쿼리 자체에 권한 조건을 포함하는 것이 가장 효율적입니다. `findAllByIdInAndOwnerId(ids, currentUserId)` 쿼리로 처음부터 소유한 항목만 가져오면 `@PostFilter`가 불필요해집니다. `@PostFilter`는 소량 데이터나 메모리 내 필터링이 적합한 경우에만 사용하고, 대용량 데이터는 쿼리 레벨 필터링을 권장합니다.

---

<div align="center">

**[← 이전: AccessDecisionManager와 Voter 체인](./04-access-decision-manager.md)** | **[홈으로 🏠](../README.md)** | **[다음: Custom Authorization Logic ➡️](./06-custom-authorization.md)**

</div>
