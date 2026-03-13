# Method Security 동작 원리 (AOP Proxy) — Interceptor가 SpEL을 평가하는 과정

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `@PreAuthorize`가 붙은 Bean을 Spring이 어떻게 Proxy로 감싸는가?
- `AuthorizationManagerBeforeMethodInterceptor`는 AOP 체인에서 어떤 역할을 하는가?
- `MethodSecurityExpressionHandler`는 SpEL 컨텍스트에 무엇을 바인딩하는가?
- `authentication`, `#paramName`, `returnObject`, `filterObject`는 SpEL에서 어떻게 사용 가능한가?
- 인터페이스 기반 Proxy(JDK)와 서브클래스 Proxy(CGLIB)의 차이가 Method Security에 영향을 주는가?
- `@PreAuthorize` 평가 결과가 캐시되는가, 매 호출마다 평가되는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### AOP Proxy 없이 Method Security를 구현한다면

```
❌ Proxy 없이 직접 구현:
  public class OrderService {
      public Order getOrder(Long id) {
          // 모든 메서드 첫 줄에 직접 권한 검사 코드
          Authentication auth = SecurityContextHolder.getContext().getAuthentication();
          if (!auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER"))) {
              throw new AccessDeniedException("...");
          }
          // 실제 비즈니스 로직
          return orderRepository.findById(id).orElseThrow();
      }
  }

  문제:
  → 모든 보호 메서드에 동일 코드 반복 (DRY 위반)
  → Security 로직 변경 시 모든 메서드 수정
  → 실수로 빠뜨리면 보안 구멍

✅ AOP Proxy로 해결:
  @PreAuthorize("hasRole('USER') and @orderSecurity.isOwner(#id)")
  public Order getOrder(Long id) {
      return orderRepository.findById(id).orElseThrow(); // 순수 비즈니스 로직
  }
  → 보안 로직 선언적으로 분리
  → Spring이 Proxy 생성 → 메서드 호출 전 자동으로 권한 검사
```

---

## 😱 흔한 보안 실수

### Before: Proxy 동작을 이해하지 못한 self-invocation

```java
// ❌ 문제: 같은 Bean 내부에서 this.로 호출하면 Proxy가 동작하지 않음
@Service
public class OrderService {

    public void processOrder(Long orderId) {
        // this.로 호출 → Proxy 우회 → @PreAuthorize 무시됨!
        Order order = this.getOrder(orderId);
        // ... 처리
    }

    @PreAuthorize("hasRole('USER')")
    public Order getOrder(Long orderId) {
        return orderRepository.findById(orderId).orElseThrow();
    }
}

// ✅ 해결 방법들:

// 방법 1: Self-injection (권장하지 않지만 가능)
@Service
public class OrderService {
    @Lazy
    @Autowired
    private OrderService self; // Proxy 주입

    public void processOrder(Long orderId) {
        Order order = self.getOrder(orderId); // Proxy 통해 호출 → 권한 검사 실행
    }
}

// 방법 2: 별도 Bean으로 분리 (권장)
@Service
public class OrderProcessingService {
    @Autowired
    private OrderQueryService orderQueryService; // 다른 Bean

    public void processOrder(Long orderId) {
        Order order = orderQueryService.getOrder(orderId); // Proxy 통해 호출
    }
}

// 방법 3: AspectJ 위빙 (Proxy 없이 직접 바이트코드 조작)
@EnableMethodSecurity(mode = AdviceMode.ASPECTJ)
// → self-invocation에서도 동작하지만 설정 복잡도 증가
```

### Before: final 메서드에 @PreAuthorize 적용

```java
// ❌ CGLIB Proxy는 final 메서드를 오버라이드할 수 없음
@Service
public class OrderService {

    @PreAuthorize("hasRole('ADMIN')")
    public final Order getOrder(Long id) { // final → CGLIB가 오버라이드 불가
        return orderRepository.findById(id).orElseThrow();
    }
}
// 결과: @PreAuthorize가 무시되거나 예외 발생
// UnsatisfiedDependencyException 또는 silent 무시

// ✅ final 제거
@PreAuthorize("hasRole('ADMIN')")
public Order getOrder(Long id) { ... }
```

---

## ✨ 올바른 보안 구현

### SpEL 컨텍스트에서 사용 가능한 변수들

```java
@Service
public class SecureService {

    // authentication: 현재 사용자 Authentication 객체
    @PreAuthorize("authentication.name == 'admin'")
    public void checkByAuthName() { ... }

    // principal: authentication.getPrincipal()
    @PreAuthorize("principal.userId == 42")
    public void checkByUserId() { ... }

    // hasRole(), hasAuthority(), isAuthenticated() 등 메서드
    @PreAuthorize("isAuthenticated() and hasRole('USER')")
    public void checkMultiple() { ... }

    // #paramName: 메서드 파라미터 참조
    @PreAuthorize("#userId == authentication.principal.userId")
    public UserProfile getProfile(Long userId) { ... }

    // returnObject: @PostAuthorize에서 반환값 참조
    @PostAuthorize("returnObject.ownerId == authentication.principal.userId")
    public Order getOrder(Long id) { ... }

    // filterObject: @PreFilter/@PostFilter에서 컬렉션 각 요소
    @PostFilter("filterObject.active == true")
    public List<Item> getItems() { ... }

    // @beanName: 다른 Spring Bean 참조 (커스텀 권한 로직)
    @PreAuthorize("@orderPermissionEvaluator.canRead(#orderId, authentication)")
    public Order readOrder(Long orderId) { ... }
}
```

---

## 🔬 내부 동작 원리

### 1. Proxy 생성 과정 — @EnableMethodSecurity가 등록하는 것들

```java
// MethodSecuritySelector.java
// @EnableMethodSecurity 처리 시 등록하는 구성 클래스들

// PrePostMethodSecurityConfiguration 등록:
// → AnnotationAwareAspectJAutoProxyCreator (없으면 활성화)
// → AuthorizationManagerBeforeMethodInterceptor.preAuthorize()
// → AuthorizationManagerAfterMethodInterceptor.postAuthorize()
// → PreFilterAuthorizationMethodInterceptor
// → PostFilterAuthorizationMethodInterceptor

// Spring이 OrderService Bean을 생성할 때:
// 1. AnnotationAwareAspectJAutoProxyCreator가 Bean 후처리
// 2. @PreAuthorize가 붙은 메서드 감지
// 3. CGLIB(기본) 또는 JDK Proxy 생성
// 4. Proxy가 Bean으로 등록됨

// 다른 Bean이 OrderService를 주입받으면:
// → 실제 OrderService가 아닌 CGLIB Proxy를 주입받음
// → Proxy.getOrder() 호출 → Interceptor 실행 → 권한 검사 → 실제 메서드
```

### 2. AuthorizationManagerBeforeMethodInterceptor — 핵심 인터셉터

```java
// AuthorizationManagerBeforeMethodInterceptor.java
public final class AuthorizationManagerBeforeMethodInterceptor
        implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

    private final Pointcut pointcut;
    private final AuthorizationManager<MethodInvocation> authorizationManager;

    // @PreAuthorize 전용 인스턴스 생성 팩토리 메서드
    public static AuthorizationManagerBeforeMethodInterceptor preAuthorize() {
        return preAuthorize(new PreAuthorizeAuthorizationManager());
    }

    // AOP Advice 실행 — 메서드 호출을 가로챔
    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {

        // ① AuthorizationManager에 권한 검사 위임
        this.authorizationManager.verify(
            SecurityContextHolder::getContext,          // Authentication 공급자
            invocation                                  // 메서드 호출 정보
        );
        // verify(): check() 결과가 ACCESS_DENIED이면 AccessDeniedException throw

        // ② 권한 통과 → 실제 메서드 실행
        return invocation.proceed();
    }

    @Override
    public int getOrder() {
        return AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder(); // 500
    }
}
```

### 3. MethodSecurityExpressionHandler — SpEL 컨텍스트 초기화

```java
// DefaultMethodSecurityExpressionHandler.java
public class DefaultMethodSecurityExpressionHandler
        extends AbstractSecurityExpressionHandler<MethodInvocation>
        implements MethodSecurityExpressionHandler {

    private ParameterNameDiscoverer parameterNameDiscoverer =
        new DefaultSecurityParameterNameDiscoverer();

    @Override
    public EvaluationContext createEvaluationContext(
            Supplier<Authentication> authentication,
            MethodInvocation invocation) {

        // ① MethodSecurityExpressionRoot 생성
        MethodSecurityExpressionRoot root =
            new MethodSecurityExpressionRoot(authentication);

        // ② 메서드 파라미터를 SpEL 변수로 등록
        // @PreAuthorize에서 #userId, #orderId 등으로 참조 가능
        StandardEvaluationContext ctx = new StandardEvaluationContext(root);

        // 파라미터 이름 → 값 매핑
        Object[] args = invocation.getArguments();
        String[] paramNames = getParameterNames(invocation.getMethod());
        for (int i = 0; i < paramNames.length; i++) {
            ctx.setVariable(paramNames[i], args[i]);
            // → #userId = args[0] 바인딩
        }

        // ③ filterObject, returnObject 등 특수 변수 설정
        root.setFilterObject(null); // @PreFilter에서 설정됨
        root.setReturnObject(null); // @PostAuthorize에서 설정됨

        // ④ @beanName 참조를 위한 Bean Resolver 설정
        ctx.setBeanResolver(new BeanFactoryResolver(this.applicationContext));
        // → @orderSecurity.isOwner() 에서 Bean 조회 가능

        return ctx;
    }

    // 파라미터 이름 추출 (컴파일 시 -parameters 옵션 필요)
    private String[] getParameterNames(Method method) {
        String[] names = parameterNameDiscoverer.getParameterNames(method);
        if (names == null) {
            // -parameters 없으면 null → #arg0, #arg1 형태로만 접근 가능
            names = new String[method.getParameterCount()];
            Arrays.fill(names, ""); // 빈 이름
        }
        return names;
    }
}
```

### 4. MethodSecurityExpressionRoot — SpEL에서 사용 가능한 변수와 메서드

```java
// MethodSecurityExpressionRoot.java
public class MethodSecurityExpressionRoot
        extends SecurityExpressionRoot
        implements MethodSecurityExpressionOperations {

    private Object filterObject;
    private Object returnObject;
    private Object target; // 보호된 Bean 자체

    // SecurityExpressionRoot에서 상속:
    // - hasRole(String role)
    // - hasAnyRole(String... roles)
    // - hasAuthority(String authority)
    // - isAuthenticated()
    // - isFullyAuthenticated()
    // - isAnonymous()
    // - isRememberMe()
    // - permitAll()
    // - denyAll()

    // MethodSecurityExpressionOperations 추가:
    // - getFilterObject() / setFilterObject()
    // - getReturnObject() / setReturnObject()
    // - getThis() → 보호된 Bean 참조

    // authentication 변수: SecurityExpressionRoot.authentication
    // principal 변수: authentication.getPrincipal()
}
```

### 5. JDK Proxy vs CGLIB Proxy 차이

```java
// JDK 동적 Proxy:
// - 인터페이스 기반 (OrderService가 OrderServiceInterface를 구현해야 함)
// - InvocationHandler로 메서드 위임
// - final 클래스도 Proxy 가능 (인터페이스만 있으면)

// CGLIB Proxy (기본):
// - 서브클래스 기반 (OrderService의 서브클래스 생성)
// - 메서드 오버라이드로 Interceptor 호출
// - final 클래스/메서드는 오버라이드 불가 → @PreAuthorize 무시!
// - proxyTargetClass=true (기본값)

@EnableMethodSecurity(proxyTargetClass = false) // JDK Proxy 사용
// → 인터페이스 없는 Bean에 적용 불가

// 권장: 기본값(CGLIB) 유지, final 메서드 피하기

// Spring Boot 3.x: 기본적으로 proxyTargetClass=true (CGLIB)
```

### 6. SpEL 표현식 캐싱

```java
// DefaultMethodSecurityExpressionHandler.java 내부
// SpEL 표현식은 파싱 비용이 있으므로 캐시됨

private final Map<String, Expression> expressionCache =
    new ConcurrentHashMap<>();

protected Expression getExpression(ExpressionParser parser,
                                    Annotation methodAnnotation) {
    String expressionString = getExpressionText(methodAnnotation);
    // 캐시에 있으면 재사용
    return expressionCache.computeIfAbsent(expressionString,
        key -> parser.parseExpression(key));
}
// → @PreAuthorize("hasRole('ADMIN')") 파싱 결과는 캐시됨
// → EvaluationContext(Authentication, 파라미터 값)는 매 호출마다 새로 생성됨
// → 즉: 표현식 구조는 캐시, 실제 값 평가는 매번 수행
```

---

## 💻 실험으로 확인하기

### 실험 1: Proxy 타입 확인

```java
@Autowired
OrderService orderService;

@GetMapping("/debug/proxy-type")
public String proxyType() {
    return orderService.getClass().getName();
    // CGLIB: "com.example.OrderService$$SpringCGLIB$$0"
    // JDK:   "com.sun.proxy.$Proxy42" (인터페이스 구현 시)
}
```

### 실험 2: self-invocation Proxy 우회 확인

```java
@Service
public class InvocationTestService {

    @PreAuthorize("hasRole('ADMIN')")
    public String adminOnly() {
        return "admin result";
    }

    public String callAdminDirectly() {
        // this.adminOnly() → Proxy 우회 → @PreAuthorize 무시
        return this.adminOnly(); // 권한 없어도 실행됨!
    }
}

@SpringBootTest
@WithMockUser(roles = "USER") // ADMIN 아님
class SelfInvocationTest {

    @Autowired InvocationTestService service;

    @Test
    void directCall_throwsException() {
        assertThatThrownBy(() -> service.adminOnly())
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void selfInvocation_bypassesProxy() {
        // self-invocation → Proxy 우회 → 권한 검사 없이 실행됨
        assertDoesNotThrow(() -> service.callAdminDirectly());
    }
}
```

### 실험 3: SpEL 평가 TRACE 로그

```yaml
logging:
  level:
    org.springframework.security.access.expression: TRACE
    org.springframework.security.authorization: DEBUG
```

```
# @PreAuthorize("hasRole('ADMIN')") 메서드 호출 시:
TRACE PreAuthorizeAuthorizationManager - Authorizing method invocation
DEBUG PreAuthorizeAuthorizationManager - Authorized
# 또는
DEBUG PreAuthorizeAuthorizationManager - Failed to authorize ReflectiveMethodInvocation ...
```

### 실험 4: @Bean 참조로 커스텀 권한 로직 연결

```java
@Component("orderPermission")
public class OrderPermissionEvaluator {

    private final OrderRepository orderRepository;

    public boolean canRead(Long orderId, Authentication auth) {
        CustomUserDetails user = (CustomUserDetails) auth.getPrincipal();
        return orderRepository.existsByIdAndOwnerId(orderId, user.getUserId());
    }
}

@Service
public class OrderService {

    // @orderPermission Bean의 canRead() 메서드를 SpEL에서 직접 호출
    @PreAuthorize("@orderPermission.canRead(#orderId, authentication)")
    public Order getOrder(Long orderId) {
        return orderRepository.findById(orderId).orElseThrow();
    }
}
```

---

## 🔒 보안 체크리스트

```
AOP Proxy 설정
  ☐ final 클래스/메서드에 @PreAuthorize 사용 금지
  ☐ self-invocation(this.method()) 호출 패턴 코드 리뷰로 감지
  ☐ @EnableMethodSecurity 설정이 올바른 config 클래스에 있는지 확인

SpEL 표현식
  ☐ #paramName 사용 시 -parameters 컴파일 옵션 활성화 확인
  ☐ 복잡한 표현식은 @beanName.method() 패턴으로 별도 Bean에 위임
  ☐ SpEL 표현식에 로직이 많으면 테스트하기 어려움 → Bean 분리 권장

@PostAuthorize 사용
  ☐ 메서드 실행 후 권한 검사 → 읽기 전용 메서드에만 사용
  ☐ 쓰기 작업 + @PostAuthorize 조합 시 트랜잭션 롤백 여부 확인
```

---

## 🤔 트레이드오프

```
CGLIB vs JDK Proxy:
  CGLIB (기본):
    장점  인터페이스 없어도 Proxy 가능 (구체 클래스 직접 Proxy)
    단점  final 클래스/메서드 Proxy 불가, 클래스 로딩 비용 증가

  JDK Proxy:
    장점  표준 Java 방식, 인터페이스 분리 강제
    단점  반드시 인터페이스 구현 필요

SpEL vs Java 코드:
  SpEL 표현식:
    장점  어노테이션으로 선언적, 별도 클래스 불필요
    단점  런타임 오류 (컴파일 타임 검증 없음), 복잡 로직 가독성 저하

  @Bean 메서드 위임:
    장점  Java로 작성 → IDE 지원, 컴파일 타임 검증, 단위 테스트 가능
    단점  @Bean 클래스 추가 필요
    → 복잡한 권한 로직은 반드시 @beanName.method() 패턴 사용
```

---

## 📌 핵심 정리

```
Method Security AOP Proxy 동작 흐름
  @EnableMethodSecurity → Proxy Creator 등록
  → Bean 생성 시 @PreAuthorize 감지 → CGLIB Proxy 생성
  → Proxy.method() 호출
  → AuthorizationManagerBeforeMethodInterceptor.invoke()
  → PreAuthorizeAuthorizationManager.check()
  → MethodSecurityExpressionHandler로 SpEL 평가
  → ACCESS_GRANTED → invocation.proceed() (실제 메서드)
  → ACCESS_DENIED → AccessDeniedException throw

self-invocation 문제
  this.method() → Proxy 우회 → @PreAuthorize 무시
  → 별도 Bean 분리 또는 self-injection으로 해결

SpEL 컨텍스트 변수
  authentication, principal  현재 사용자 정보
  #paramName                 메서드 파라미터
  returnObject               @PostAuthorize 반환값
  filterObject               @Pre/@PostFilter 컬렉션 요소
  @beanName                  Spring Bean 참조

표현식 캐시
  SpEL 파싱 결과는 캐시됨 (표현식 구조)
  Authentication, 파라미터 값은 매 호출마다 새로 평가됨
```

---

## 🤔 생각해볼 문제

**Q1.** `@PreAuthorize`가 붙은 메서드를 `@Transactional`과 함께 사용할 때, 두 Interceptor의 실행 순서는 어떻게 결정되는가? 권한 검사가 트랜잭션 시작 전에 실행되도록 보장하는 방법은?

**Q2.** `SecurityContextHolder.MODE_INHERITABLETHREADLOCAL` 설정 없이 `@PreAuthorize`가 붙은 `@Async` 메서드를 호출하면 어떻게 되는가? Proxy가 메서드를 실행하기 전에 새 스레드에서 `SecurityContextHolder`가 비어있다면?

**Q3.** `@PreAuthorize` SpEL에서 `@beanName.method()` 패턴으로 외부 Bean을 호출할 때, 그 Bean 메서드 내부에서 다른 `@PreAuthorize`가 붙은 메서드를 호출하면 중첩 권한 검사가 발생하는가?

> 💡 **해설**
>
> **Q1.** Interceptor 실행 순서는 `@Order` 값으로 결정됩니다. `AuthorizationManagerBeforeMethodInterceptor`의 `@PreAuthorize` Order는 500, `TransactionInterceptor`의 기본 Order는 `Integer.MAX_VALUE - 3` (= 2147483644)입니다. 낮은 숫자가 먼저 실행되므로 권한 검사(500)가 트랜잭션 시작(2147483644)보다 먼저 실행됩니다. 이는 올바른 설계로, 권한 없는 사용자의 트랜잭션 시작 자체를 막습니다. 만약 `@Transactional`에 `@Order`를 부여해 500보다 낮게 설정하면 트랜잭션이 먼저 시작됩니다.
>
> **Q2.** `@Async` 메서드는 새 스레드에서 실행되고 `SecurityContextHolder.MODE_THREADLOCAL`(기본값)로는 컨텍스트가 전파되지 않습니다. AOP Proxy가 새 스레드에서 `AuthorizationManagerBeforeMethodInterceptor.invoke()`를 호출할 때 `SecurityContextHolder.getContext().getAuthentication()`이 `null`(또는 빈 컨텍스트)을 반환합니다. `PreAuthorizeAuthorizationManager`는 `null` Authentication으로 SpEL을 평가하게 되고, `hasRole()` 등은 `false`를 반환해 `AccessDeniedException`이 발생합니다. 해결 방법은 `DelegatingSecurityContextAsyncTaskExecutor`를 사용해 SecurityContext를 Async 스레드로 전파하는 것입니다.
>
> **Q3.** `@beanName.method()` 패턴으로 호출된 Bean의 메서드가 `@PreAuthorize`로 보호되어 있다면, 해당 Bean도 AOP Proxy로 감싸져 있으므로 중첩 권한 검사가 발생합니다. 즉, 외부 Bean 호출이 Proxy를 통해 이루어지면 그 메서드의 `@PreAuthorize`도 평가됩니다. 이는 의도한 동작이지만 SpEL에서 호출하는 Bean의 메서드에도 `@PreAuthorize`가 있다면 이중 검사가 발생해 불필요한 비용이 들 수 있습니다. 권한 체크용 Bean(`@beanName.canRead()`)에는 `@PreAuthorize`를 붙이지 않고 내부 로직만 작성하는 것이 관례입니다.

---

<div align="center">

**[← 이전: @PreAuthorize vs @Secured vs @RolesAllowed](./01-pre-authorize-vs-secured.md)** | **[홈으로 🏠](../README.md)** | **[다음: FilterSecurityInterceptor 내부 구조 ➡️](./03-filter-security-interceptor.md)**

</div>
