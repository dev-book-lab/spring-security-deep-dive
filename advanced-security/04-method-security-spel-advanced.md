# Method Security with SpEL 고급 활용 — @PostFilter, @PreFilter와 커스텀 ExpressionRoot

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `@PostFilter`와 `@PreFilter`로 컬렉션 반환값/파라미터를 필터링하는 정확한 동작 방식은?
- `returnObject`와 `filterObject` 내장 변수는 SpEL에서 어떻게 바인딩되는가?
- 커스텀 `SecurityExpressionRoot`를 만들어 도메인 특화 SpEL 함수를 추가하는 방법은?
- `@PostFilter`가 대용량 컬렉션에서 성능 문제를 일으키는 이유와 대안은?
- `@PreFilter`의 `filterTarget` 속성은 언제 사용하는가?
- 커스텀 SpEL 함수에서 Spring Bean을 주입받을 때 주의사항은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### @PostFilter와 @PreFilter가 필요한 이유

```
단순 @PreAuthorize의 한계:
  @PreAuthorize("hasRole('USER')")
  public List<Order> getOrders() { ... }
  → ROLE_USER이면 모든 주문 반환 (다른 사용자 주문도 포함)
  → "내 주문만 볼 수 있어야 한다"는 비즈니스 규칙 위반

@PostFilter로 해결:
  @PostFilter("filterObject.ownerId == authentication.principal.userId")
  public List<Order> getOrders() { ... }
  → 모든 주문을 DB에서 조회 후
  → 현재 사용자 소유 주문만 필터링해서 반환

@PreFilter로 해결:
  @PreFilter("filterObject.ownerId == authentication.principal.userId")
  public void cancelOrders(List<Order> orders) { ... }
  → 파라미터의 orders 중 현재 사용자 소유 주문만 남기고 나머지 제거
  → 메서드는 필터링된 리스트만 받음

커스텀 SpEL 함수:
  @PreAuthorize("isPremiumUser() and hasFeatureAccess('export')")
  → isPremiumUser(): DB 조회 로직을 SpEL 함수로 캡슐화
  → 가독성 향상, 복잡한 로직 재사용
```

---

## 😱 흔한 보안 실수

### Before: @PostFilter로 대용량 데이터 필터링 시도

```java
// ❌ 대용량 데이터에 @PostFilter → 메모리 오버헤드
@PostFilter("filterObject.status == 'ACTIVE'")
public List<Order> getAllOrders() {
    return orderRepository.findAll(); // 수십만 건 조회
    // → 모두 메모리에 로드 후 하나씩 SpEL 평가 → OOM 가능
}

// ✅ DB 쿼리 레벨에서 필터링
public List<Order> getAllOrders(Authentication auth) {
    Long userId = ((CustomUserDetails) auth.getPrincipal()).getUserId();
    return orderRepository.findByOwnerIdAndStatus(userId, "ACTIVE");
}
// → DB에서 필터링 → 필요한 데이터만 반환 → 메모리 효율적
// @PostFilter는 소량 데이터 또는 이미 로드된 컬렉션에만 사용
```

### Before: @PreFilter를 List가 아닌 타입에 사용

```java
// ❌ @PreFilter는 컬렉션(List, Set, Array) 타입에만 동작
@PreFilter("filterObject.status == 'PENDING'")
public void processOrder(Order order) { // 단일 객체 → 오류
    ...
}
// → IllegalArgumentException: @PreFilter expects a Collection

// ✅ 단일 객체: @PreAuthorize 사용
@PreAuthorize("@orderSecurity.canProcess(#order, authentication)")
public void processOrder(Order order) { ... }
```

---

## ✨ 올바른 보안 구현

### 커스텀 SecurityExpressionRoot — 도메인 특화 SpEL 함수

```java
// ① 커스텀 Expression Root 정의
public class CustomMethodSecurityExpressionRoot
        extends SecurityExpressionRoot
        implements MethodSecurityExpressionOperations {

    // 도메인 서비스 주입
    private final SubscriptionService subscriptionService;
    private final TenantService tenantService;

    // MethodSecurityExpressionOperations 구현
    private Object filterObject;
    private Object returnObject;

    public CustomMethodSecurityExpressionRoot(
            Authentication authentication,
            SubscriptionService subscriptionService,
            TenantService tenantService) {
        super(authentication);
        this.subscriptionService = subscriptionService;
        this.tenantService = tenantService;
    }

    // ─── 커스텀 SpEL 함수들 ────────────────────────────────
    // 프리미엄 구독 여부 확인
    public boolean isPremiumUser() {
        CustomUserDetails user = (CustomUserDetails) getAuthentication().getPrincipal();
        return subscriptionService.isPremium(user.getUserId());
    }

    // 특정 기능 접근 권한 확인
    public boolean hasFeatureAccess(String featureName) {
        CustomUserDetails user = (CustomUserDetails) getAuthentication().getPrincipal();
        return subscriptionService.hasFeature(user.getUserId(), featureName);
    }

    // 테넌트 내 리소스 소유 여부
    public boolean isResourceOwner(Long resourceId, String resourceType) {
        CustomUserDetails user = (CustomUserDetails) getAuthentication().getPrincipal();
        return tenantService.isOwner(user.getTenantId(), user.getUserId(),
            resourceId, resourceType);
    }

    // 현재 사용자 ID 반환 (SpEL에서 편리하게 사용)
    public Long currentUserId() {
        return ((CustomUserDetails) getAuthentication().getPrincipal()).getUserId();
    }

    // 현재 테넌트 ID
    public String currentTenantId() {
        return ((CustomUserDetails) getAuthentication().getPrincipal()).getTenantId();
    }

    // MethodSecurityExpressionOperations 필수 구현
    @Override public void setFilterObject(Object o)     { this.filterObject = o; }
    @Override public Object getFilterObject()           { return filterObject; }
    @Override public void setReturnObject(Object o)     { this.returnObject = o; }
    @Override public Object getReturnObject()           { return returnObject; }
    @Override public Object getThis()                   { return null; }
}

// ② 커스텀 ExpressionHandler 등록
@Configuration
@EnableMethodSecurity
public class CustomMethodSecurityConfig {

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            SubscriptionService subscriptionService,
            TenantService tenantService) {

        return new DefaultMethodSecurityExpressionHandler() {
            @Override
            protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
                    Authentication authentication, MethodInvocation invocation) {

                CustomMethodSecurityExpressionRoot root =
                    new CustomMethodSecurityExpressionRoot(
                        authentication, subscriptionService, tenantService);

                root.setPermissionEvaluator(getPermissionEvaluator());
                root.setTrustResolver(getTrustResolver());
                root.setRoleHierarchy(getRoleHierarchy());
                return root;
            }
        };
    }
}

// ③ 사용 예시
@RestController
public class ReportController {

    // 커스텀 함수 사용
    @GetMapping("/api/reports/export")
    @PreAuthorize("isPremiumUser() and hasFeatureAccess('export')")
    public ReportExport exportReport() { ... }

    // 현재 사용자 ID 활용
    @GetMapping("/api/reports/{id}")
    @PreAuthorize("isResourceOwner(#id, 'REPORT') or hasRole('ADMIN')")
    public Report getReport(@PathVariable Long id) { ... }

    // @PostFilter: 현재 테넌트 데이터만 반환
    @GetMapping("/api/reports")
    @PreAuthorize("isAuthenticated()")
    @PostFilter("filterObject.tenantId == currentTenantId()")
    public List<Report> getAllReports() { ... }
}
```

---

## 🔬 내부 동작 원리

### 1. @PostFilter 동작 상세

```java
// PostFilterAuthorizationMethodInterceptor.java
// @PostFilter 처리 인터셉터

@Override
public Object invoke(MethodInvocation invocation) throws Throwable {
    // ① 실제 메서드 먼저 실행
    Object returnValue = invocation.proceed();

    if (returnValue == null) return null;

    // ② @PostFilter 어노테이션 확인
    PostFilter postFilter = findAnnotation(invocation);
    if (postFilter == null) return returnValue;

    // ③ 컬렉션 타입 확인
    // List, Set, Collection, Array 지원
    // 단일 객체: UnsupportedOperationException

    // ④ 각 요소에 대해 SpEL 평가
    EvaluationContext ctx = expressionHandler
        .createEvaluationContext(authentication, invocation);

    Iterator<?> iter = getIterator(returnValue);
    while (iter.hasNext()) {
        Object element = iter.next();

        // filterObject를 현재 요소로 바인딩
        ((MethodSecurityExpressionRoot) ctx.getRootObject().getValue())
            .setFilterObject(element);

        // SpEL 평가: filterObject.ownerId == authentication.principal.userId
        boolean keep = ExpressionUtils.evaluateAsBoolean(expression, ctx);

        if (!keep) {
            iter.remove(); // 조건 불충족 요소 제거
        }
    }

    return returnValue; // 필터링된 컬렉션 반환
}
```

### 2. @PreFilter 동작 상세

```java
// @PreFilter: 메서드 실행 전 파라미터 컬렉션 필터링

@PreFilter(value = "filterObject.active == true",
           filterTarget = "items") // 여러 파라미터 중 특정 파라미터 지정
public void processItems(List<Item> items, String reason) {
    // items: 필터링된 List (active=true인 것만)
    // reason: 그대로
}

// filterTarget:
//   파라미터가 하나면 생략 가능
//   여러 파라미터 중 컬렉션 파라미터를 명시할 때 사용
//   파라미터 이름으로 지정 (-parameters 컴파일 옵션 필요)

// 내부 동작:
// 1. filterTarget으로 지정된 파라미터 찾기 (또는 유일한 컬렉션 타입)
// 2. Iterator를 통해 각 filterObject에 대해 SpEL 평가
// 3. false인 요소 제거
// 4. 필터링된 컬렉션으로 메서드 실행
```

### 3. returnObject vs filterObject 바인딩 시점

```java
// returnObject: @PostAuthorize, @PostFilter에서 사용 가능
@PostAuthorize("returnObject.ownerId == authentication.principal.userId")
public Order getOrder(Long id) {
    return repository.findById(id).orElseThrow();
    // returnObject = 반환된 Order 객체
}

@PostFilter("filterObject.ownerId == authentication.principal.userId")
public List<Order> getOrders() {
    return repository.findAll();
    // filterObject = 각 Order 요소 (루프마다 교체됨)
}

// filterObject: @PreFilter, @PostFilter에서 사용 가능
@PreFilter("filterObject.active && filterObject.version > 2")
public void processOrders(List<Order> orders) {
    // orders: active=true && version>2 인 것만
}

// 바인딩 메커니즘:
// MethodSecurityExpressionRoot.setFilterObject(currentElement)
// → SpEL 평가 시 'filterObject' 키워드로 접근
// → 루프마다 setFilterObject() 호출로 현재 요소 교체
```

### 4. 커스텀 SpEL 함수 성능 고려사항

```java
// 성능 주의: SpEL 함수가 DB를 조회하면 컬렉션 크기만큼 실행됨

// ❌ DB 조회가 포함된 SpEL 함수를 @PostFilter에서 사용
@PostFilter("@orderService.canAccess(filterObject.id, authentication)")
// → 각 주문마다 DB 조회 → N번 쿼리 (N+1 문제)

// ✅ 캐시를 활용하거나 배치 조회
public boolean canAccess(Long orderId, Authentication auth) {
    // Caffeine 캐시 적용
    return cacheManager.getCache("orderAccess")
        .get(auth.getName() + ":" + orderId, Boolean.class);
}

// 또는: @PostFilter 제거하고 서비스 레이어에서 배치 처리
@GetMapping("/api/orders")
public List<Order> getOrders(Authentication auth) {
    Long userId = getUserId(auth);
    // DB에서 한 번에 현재 사용자 주문만 조회
    return orderRepository.findByOwnerId(userId);
    // @PostFilter 불필요
}
```

---

## 💻 실험으로 확인하기

### 실험 1: @PostFilter 동작 확인

```java
@Service
public class OrderService {
    @PostFilter("filterObject.ownerId == authentication.principal.userId")
    public List<Order> getAllOrders() {
        return orderRepository.findAll(); // 전체 조회
    }
}

@Test
@WithUserDetails("kim") // userId=1인 사용자
void postFilter_returnsOnlyOwnOrders() {
    List<Order> allOrders = List.of(
        new Order(1L, 1L), // kim의 주문
        new Order(2L, 2L), // lee의 주문
        new Order(3L, 1L)  // kim의 주문
    );
    when(orderRepository.findAll()).thenReturn(allOrders);

    List<Order> result = orderService.getAllOrders();

    assertThat(result).hasSize(2); // kim의 주문만
    assertThat(result).allMatch(o -> o.getOwnerId().equals(1L));
}
```

### 실험 2: 커스텀 SpEL 함수 테스트

```java
@SpringBootTest
@WithMockUser("kim")
class CustomSpelFunctionTest {

    @Autowired ReportController reportController;
    @MockBean SubscriptionService subscriptionService;
    @MockBean TenantService tenantService;

    @Test
    void premiumUser_canExport() {
        when(subscriptionService.isPremium(anyLong())).thenReturn(true);
        when(subscriptionService.hasFeature(anyLong(), eq("export"))).thenReturn(true);

        assertDoesNotThrow(() -> reportController.exportReport());
    }

    @Test
    void freeUser_cannotExport() {
        when(subscriptionService.isPremium(anyLong())).thenReturn(false);

        assertThatThrownBy(() -> reportController.exportReport())
            .isInstanceOf(AccessDeniedException.class);
    }
}
```

### 실험 3: @PreFilter filterTarget 사용

```java
@PreFilter(value = "filterObject.ownerId == authentication.principal.userId",
           filterTarget = "orders") // 'reason' 파라미터와 구분
public BatchResult cancelOrders(List<Order> orders, String reason) {
    System.out.println("Processing " + orders.size() + " orders");
    return batchService.cancel(orders, reason);
}

@Test
@WithUserDetails("kim") // userId=1
void preFilter_removesOtherUsersOrders() {
    List<Order> mixed = new ArrayList<>(List.of(
        new Order(1L, 1L),  // kim
        new Order(2L, 2L),  // lee
        new Order(3L, 1L)   // kim
    ));
    orderService.cancelOrders(mixed, "고객 요청");
    // 내부에서 orders.size() = 2 (kim의 것만)
}
```

---

## 🔒 보안 체크리스트

```
@PostFilter 사용
  ☐ 대용량 컬렉션에 사용 금지 (DB 쿼리 레벨에서 필터링)
  ☐ 소량 데이터(100건 이하) 또는 이미 로드된 캐시에만 사용
  ☐ DB 조회 포함 SpEL 함수 → N+1 쿼리 방지를 위해 캐시 적용

@PreFilter 사용
  ☐ filterTarget 명시 (여러 파라미터가 있는 경우)
  ☐ 컬렉션 타입 파라미터에만 사용
  ☐ -parameters 컴파일 옵션 확인 (파라미터 이름 바인딩 필요)

커스텀 SpEL 함수
  ☐ SpEL 함수 내 DB 조회 → 캐시(@Cacheable) 적용
  ☐ 예외 처리: 함수 내 예외가 SpEL 평가 실패로 이어지지 않도록
  ☐ 단위 테스트: 각 SpEL 함수를 독립적으로 테스트
  ☐ ExpressionHandler @Bean 등록 확인
```

---

## 🤔 트레이드오프

```
@PostFilter vs DB 쿼리 필터링:
  @PostFilter:
    장점  코드 간결, 추가 쿼리 메서드 불필요
    단점  N건 데이터를 모두 로드 후 메모리에서 필터
          대용량 데이터 = OOM 위험

  DB 쿼리:
    장점  필요한 데이터만 조회 (성능, 메모리 효율)
    단점  쿼리 메서드 또는 JPQL 추가 필요
    → 항상 DB 쿼리 필터링이 우선, @PostFilter는 최후 수단

커스텀 SpEL 함수 vs @beanName.method():
  커스텀 함수:
    장점  간결한 문법 (isOwner() vs @security.isOwner())
          SecurityExpressionRoot를 통해 auth에 직접 접근
    단점  ExpressionHandler 구현 필요, 복잡도 증가

  @beanName:
    장점  설정 없이 바로 사용, 명시적
    단점  SpEL이 길어짐
    → 자주 재사용되는 복잡 로직: 커스텀 함수
    → 일회성 간단 로직: @beanName
```

---

## 📌 핵심 정리

```
@PostFilter
  메서드 실행 후 반환 컬렉션 각 요소에 filterObject로 SpEL 평가
  false → 제거 / true → 유지
  대용량 데이터 금지 (메모리에서 필터링)

@PreFilter
  메서드 실행 전 파라미터 컬렉션 각 요소에 filterObject로 SpEL 평가
  false → 제거 → 메서드는 필터링된 컬렉션을 받음
  filterTarget: 여러 파라미터 중 필터링 대상 지정

returnObject / filterObject 바인딩
  returnObject: @PostAuthorize, @PostFilter에서 반환값/각 요소
  filterObject: @PreFilter, @PostFilter에서 컬렉션 각 요소
  MethodSecurityExpressionRoot.set*Object()로 루프마다 교체

커스텀 SecurityExpressionRoot
  SecurityExpressionRoot 상속 + MethodSecurityExpressionOperations 구현
  도메인 서비스 주입 → isPremiumUser(), isResourceOwner() 등 함수 추가
  DefaultMethodSecurityExpressionHandler @Bean으로 등록
```

---

## 🤔 생각해볼 문제

**Q1.** `@PostFilter("filterObject.ownerId == authentication.principal.userId")`에서 반환 타입이 `List<Order>`일 때, 내부적으로 `iterator.remove()`로 요소를 제거합니다. 그런데 반환 타입이 `Collections.unmodifiableList()` 또는 JPA의 지연 로딩 컬렉션(`PersistentBag`)이라면 어떤 문제가 발생하는가?

**Q2.** 커스텀 `SecurityExpressionRoot`에서 `subscriptionService.isPremium(userId)`를 DB 조회로 구현했습니다. 하나의 API 요청에서 `isPremiumUser()`를 포함한 `@PreAuthorize`가 붙은 메서드를 여러 번 호출하면 DB 조회가 여러 번 발생합니다. Request Scope 캐시를 활용해 같은 요청 내에서 한 번만 조회하도록 최적화하는 방법은?

**Q3.** `@PreFilter`와 `@Transactional`을 함께 사용하는 메서드에서, 필터링된 컬렉션의 요소 중 하나가 DB 처리 중 오류가 발생하면 롤백이 어떻게 동작하는가? 필터링으로 제거된 요소는 트랜잭션 롤백에 어떤 영향을 받는가?

> 💡 **해설**
>
> **Q1.** `PostFilterAuthorizationMethodInterceptor`는 반환된 컬렉션에 대해 `Iterator.remove()`를 호출합니다. `Collections.unmodifiableList()` 래핑된 리스트는 `remove()`가 `UnsupportedOperationException`을 발생시킵니다. JPA의 `PersistentBag`은 수정 가능하지만 영속성 컨텍스트에서 제거하면 DB에도 영향을 줄 수 있습니다. 방어 방법: 반환 전에 `new ArrayList<>(list)`로 가변 복사본을 만들거나, Service 레이어에서 명시적으로 `new ArrayList<>()` 형태로 반환합니다. Spring Data JPA Repository의 `findAll()`은 `ArrayList`를 반환하므로 대부분 문제없지만, JPQL `FETCH JOIN` 결과가 중복 포함될 수 있어 주의합니다.
>
> **Q2.** Request Scope 캐시 패턴: `@RequestScope` 빈을 만들어 요청 범위에서 캐시를 관리합니다. `RequestScopedSecurityCache`를 Spring Bean으로 등록하고, `SecurityExpressionRoot`에서 이 빈을 주입받습니다. `isPremiumUser()` 호출 시 캐시 빈에서 먼저 확인하고, 없으면 DB 조회 후 캐시에 저장합니다. 또는 `Caffeine`의 `Cache<String, Boolean>` 대신 `ThreadLocal`에 맵을 저장해 요청-스레드 범위에서 캐시합니다(주의: @Async, 멀티 스레드에서 ThreadLocal 오염 방지 필요). Spring Cache의 `@Cacheable(key = "#userId + ':premium'", cacheManager = "requestScopedCacheManager")` 방식도 가능합니다.
>
> **Q3.** `@PreFilter`는 파라미터 컬렉션에서 요소를 제거하는 것으로, 이 자체는 DB 변경이 없습니다. 트랜잭션은 메서드 실행 후 커밋/롤백 여부를 결정합니다. 필터링으로 제거된 요소는 메서드 내에서 처리되지 않으므로 트랜잭션 롤백과 무관합니다. 즉, 롤백이 발생해도 필터링된 요소들은 "처리 시도조차 하지 않은 것"이므로 아무 영향 없습니다. 롤백은 메서드 내에서 실제 처리(DB INSERT, UPDATE 등)된 항목들에 대한 변경 사항을 되돌립니다. 주의할 점: `@PreFilter`가 적용된 메서드의 트랜잭션 내에서 일부 요소는 성공하고 일부는 실패하면 `REQUIRED` 전파 방식에서는 모두 롤백됩니다. 부분 성공이 필요하다면 각 요소를 별도 트랜잭션(`REQUIRES_NEW`)으로 처리해야 합니다.

---

<div align="center">

**[← 이전: Security Events & Listeners](./03-security-events.md)** | **[홈으로 🏠](../README.md)** | **[다음: Multi-tenancy Security 전략 ➡️](./05-multi-tenancy-security.md)**

</div>
