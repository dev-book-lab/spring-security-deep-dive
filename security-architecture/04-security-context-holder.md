# SecurityContext & SecurityContextHolder — ThreadLocal 기반 인증 정보 전파 메커니즘

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `SecurityContextHolder`가 `ThreadLocal`을 사용하는 이유와 그로 인한 제약은 무엇인가?
- `SecurityContextHolderFilter`는 언제 SecurityContext를 로드하고, 언제 정리하는가?
- `@Async` 메서드에서 `SecurityContextHolder.getContext()`를 호출하면 어떤 문제가 생기는가?
- `MODE_INHERITABLETHREADLOCAL`은 무엇을 해결하며 어떤 상황에서도 충분하지 않은가?
- `SecurityContext`를 직접 변경하면 다음 요청에도 변경 사항이 유지되는가?
- Virtual Thread (Java 21) 환경에서 `ThreadLocal` 기반 `SecurityContextHolder`는 어떻게 동작하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 인증 정보를 모든 레이어에 파라미터로 전달할 수 없다

```
인증 정보를 파라미터로 전달하는 방식:

  Filter → Controller → Service → Repository
  doFilter(request, response)
    ↓
  UserController.getUser(Authentication auth, ...)
    ↓
  UserService.findUser(Long id, Authentication auth)
    ↓
  UserRepository.findByIdWithPermissionCheck(Long id, Authentication auth)

  문제:
  → 모든 메서드 시그니처에 Authentication 파라미터 추가
  → Security와 무관한 비즈니스 로직이 Security에 강하게 결합
  → 호출 스택이 깊어질수록 파라미터 전달이 번거로움

해결: ThreadLocal 기반 전역 저장소
  인증 Filter에서 한 번만 저장:
    SecurityContextHolder.getContext().setAuthentication(auth)

  어느 레이어에서든 꺼내서 사용:
    Authentication auth = SecurityContextHolder.getContext().getAuthentication()

  → 메서드 시그니처 불변
  → 동일 스레드 내 어디서든 접근 가능
```

### ThreadLocal이 적합한 이유

```
Servlet 기반 웹 애플리케이션의 전통적 요청 처리 모델:
  요청 1개 = 스레드 1개 (Thread-per-Request)
  
  Thread-A: 사용자 Kim의 요청 처리 (시작 ~ 끝)
  Thread-B: 사용자 Lee의 요청 처리 (시작 ~ 끝)
  
  ThreadLocal은 스레드마다 독립적인 저장소를 제공
  → Thread-A의 SecurityContext ≠ Thread-B의 SecurityContext
  → 요청 간 인증 정보가 절대 섞이지 않음
```

---

## 😱 흔한 보안 실수

### Before: @Async 메서드에서 SecurityContext를 그냥 참조

```java
// ❌ 문제: @Async는 새 스레드에서 실행 → SecurityContext 없음
@Service
public class ReportService {

    @Async
    public void generateReport(Long reportId) {
        // 이 코드는 새 스레드(Async Thread Pool)에서 실행됨
        // → ThreadLocal에 SecurityContext가 없음
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(auth); // null ← SecurityContext가 전파되지 않음!

        // 현재 사용자가 이 report에 접근 권한이 있는지 검사하려 했지만
        // auth가 null이므로 권한 검사 불가 → 잘못된 보안 결정
    }
}
```

```java
// ✅ 해결 1: SecurityContextTaskDecorator로 Executor 래핑
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {

    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(8);
        executor.initialize();
        // SecurityContext를 자식 스레드로 복사하는 Decorator 적용
        return new DelegatingSecurityContextAsyncTaskExecutor(executor);
    }
}

// ✅ 해결 2: SecurityContext를 명시적으로 파라미터로 전달
@Async
public void generateReport(Long reportId, SecurityContext context) {
    SecurityContextHolder.setContext(context); // 명시적 설정
    try {
        Authentication auth = context.getAuthentication();
        // ...
    } finally {
        SecurityContextHolder.clearContext(); // 반드시 정리
    }
}
```

### Before: SecurityContext 변경 후 저장이 자동으로 된다고 착각

```java
// ❌ 잘못된 이해
@PutMapping("/user/role")
public void updateRole(@RequestBody String newRole) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    // 현재 인증 객체에 새 권한 추가
    List<GrantedAuthority> authorities = new ArrayList<>(auth.getAuthorities());
    authorities.add(new SimpleGrantedAuthority(newRole));
    // "이제 다음 요청에도 새 권한이 적용될 것이다" ← 틀림
}

// ✅ 실제:
// SecurityContextHolder는 ThreadLocal → 현재 요청 스레드에만 유효
// 요청이 끝나면 SecurityContextHolderFilter가 clearContext() 호출
// 다음 요청 시 HttpSession에서 SecurityContext를 다시 로드
//   → HttpSession에 저장된 SecurityContext는 변경 전 상태
// 
// 변경 사항을 다음 요청에도 반영하려면:
// SecurityContextRepository에 명시적으로 저장해야 함
@PutMapping("/user/role")
public void updateRole(@RequestBody String newRole,
                       HttpServletRequest request,
                       HttpServletResponse response) {
    // ... 새 Authentication 생성
    UsernamePasswordAuthenticationToken newAuth =
        new UsernamePasswordAuthenticationToken(principal, null, newAuthorities);
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(newAuth);
    SecurityContextHolder.setContext(context);
    // HttpSession에 저장 (다음 요청에 반영)
    new HttpSessionSecurityContextRepository()
        .saveContext(context, request, response);
}
```

---

## ✨ 올바른 보안 구현

### SecurityContextHolder 전략별 사용 시나리오

```java
// 전략 1: MODE_THREADLOCAL (기본값)
// 각 스레드가 독립적인 SecurityContext를 가짐
// Servlet 환경의 Thread-per-Request 모델에 최적

SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);

// 전략 2: MODE_INHERITABLETHREADLOCAL
// 부모 스레드의 SecurityContext를 자식 스레드가 상속
// new Thread(() -> ...) 로 직접 스레드를 생성하는 경우에 유효
// BUT: ThreadPool 환경에서는 풀의 기존 스레드 재사용 → 상속 안 됨

SecurityContextHolder.setStrategyName(
    SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

// 전략 3: MODE_GLOBAL
// JVM 전체에서 하나의 SecurityContext 공유
// 멀티 사용자 환경에서는 절대 사용 금지
// 단독 실행 애플리케이션(비웹)에서만 고려

SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_GLOBAL);
```

---

## 🔬 내부 동작 원리

### 1. SecurityContextHolder 내부 구조

```java
// SecurityContextHolder.java
public class SecurityContextHolder {

    public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";
    public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";
    public static final String MODE_GLOBAL = "MODE_GLOBAL";

    // 실제 저장 전략을 가진 객체 (전략 패턴)
    private static SecurityContextHolderStrategy strategy;

    static {
        initialize(); // 기본값: ThreadLocalSecurityContextHolderStrategy
    }

    public static SecurityContext getContext() {
        return strategy.getContext();
    }

    public static void setContext(SecurityContext context) {
        strategy.setContext(context);
    }

    public static void clearContext() {
        strategy.clearContext();
    }

    public static SecurityContext createEmptyContext() {
        return strategy.createEmptyContext();
    }
}

// ThreadLocalSecurityContextHolderStrategy.java (기본 전략)
final class ThreadLocalSecurityContextHolderStrategy
        implements SecurityContextHolderStrategy {

    // 스레드마다 독립적인 저장소
    private static final ThreadLocal<Supplier<SecurityContext>> contextHolder =
        new ThreadLocal<>();

    @Override
    public SecurityContext getContext() {
        return getDeferredContext().get();
    }

    @Override
    public Supplier<SecurityContext> getDeferredContext() {
        Supplier<SecurityContext> result = contextHolder.get();
        if (result == null) {
            // SecurityContext가 없으면 빈 컨텍스트 생성
            SecurityContext context = createEmptyContext();
            result = () -> context;
            contextHolder.set(result);
        }
        return result;
    }

    @Override
    public void clearContext() {
        contextHolder.remove(); // ThreadLocal에서 완전히 제거
    }
}
```

### 2. SecurityContextHolderFilter — SecurityContext 생명주기 관리

```java
// SecurityContextHolderFilter.java (Spring Security 6.x)
public class SecurityContextHolderFilter extends GenericFilterBean {

    private final SecurityContextRepository securityContextRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws ServletException, IOException {
        // ① 요청 시작: SecurityContextRepository에서 SecurityContext 로드
        //   (기본 구현: HttpSessionSecurityContextRepository)
        //   HttpSession에 "SPRING_SECURITY_CONTEXT" 속성이 있으면 복원
        //   없으면 빈 SecurityContext 생성
        Supplier<SecurityContext> deferredContext =
            securityContextRepository.loadDeferredContext((HttpServletRequest) request);

        try {
            // ② ThreadLocal에 SecurityContext 공급자 저장 (지연 로딩)
            SecurityContextHolder.setDeferredContext(deferredContext);
            chain.doFilter(request, response); // ← 실제 요청 처리
        } finally {
            // ③ 요청 종료: ThreadLocal 정리 (메모리 누수 방지)
            SecurityContextHolder.clearContext();
            request.removeAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_ATTR_NAME);
        }
        // 주의: SecurityContextPersistenceFilter(구버전)와 달리
        //       SecurityContextHolderFilter는 저장을 직접 하지 않음
        //       저장은 각 인증 Filter(UsernamePasswordAuthenticationFilter 등)가 담당
    }
}
```

### 3. 지연 로딩(Deferred Loading)이 도입된 이유

```java
// Spring Security 5.x (SecurityContextPersistenceFilter):
// 요청마다 즉시 HttpSession 조회 → 인증 여부와 관계없이 세션 I/O 발생

// Spring Security 6.x (SecurityContextHolderFilter + Deferred):
// Supplier<SecurityContext>를 저장 → 실제 getContext() 호출 시점에 로드
// → 인증 정보를 실제로 필요로 하는 시점까지 세션 조회 지연

// 예: /public/image.jpg 요청
// → SecurityContextHolder에는 Supplier만 저장
// → AuthorizationFilter: permitAll() → getContext() 호출 안 함
// → HttpSession 조회 발생 안 함 (I/O 절약)

// Supplier 패턴:
private Supplier<SecurityContext> deferredContext;

public SecurityContext getContext() {
    return getDeferredContext().get(); // 이 시점에 실제 로드
}

public void setDeferredContext(Supplier<SecurityContext> supplier) {
    this.deferredContext = supplier; // 저장만 함, 아직 실행 안 함
}
```

### 4. 전체 생명주기 ASCII 다이어그램

```
HTTP 요청: GET /api/orders (인증된 사용자)
│
▼ SecurityContextHolderFilter.doFilter() 시작
│
├─ ① deferredContext = HttpSession에서 Supplier<SecurityContext> 준비
│      (아직 실제 로드 안 함)
│
├─ SecurityContextHolder.setDeferredContext(supplier)
│      ThreadLocal: [Thread-A → Supplier<SecurityContext>]
│
│   ── 다른 Filter들 실행 ──
│
├─ JwtAuthenticationFilter (또는 UsernamePasswordAuthenticationFilter)
│      └─ 인증 성공 시:
│          SecurityContext ctx = SecurityContextHolder.createEmptyContext()
│          ctx.setAuthentication(authentication)
│          SecurityContextHolder.setContext(ctx)
│          securityContextRepository.saveContext(ctx, request, response)
│              └─ HttpSession에 "SPRING_SECURITY_CONTEXT" = ctx 저장
│
├─ AuthorizationFilter
│      └─ SecurityContextHolder.getContext().getAuthentication()
│              ThreadLocal에서 Authentication 조회 → 권한 검사
│
├─ DispatcherServlet → OrderController
│      └─ @PreAuthorize("hasRole('USER')")
│              → SecurityContextHolder.getContext().getAuthentication()
│              → 동일 스레드이므로 동일 SecurityContext 반환
│
▼ SecurityContextHolderFilter.doFilter() 종료
│
└─ finally: SecurityContextHolder.clearContext()
       ThreadLocal에서 SecurityContext 제거
       → 다음 요청 시 깨끗한 상태 보장
       → 스레드 풀 환경에서 스레드 재사용 시 이전 요청 정보 누출 방지
```

### 5. Virtual Thread 환경에서의 동작 (Java 21+)

```java
// Virtual Thread는 ThreadLocal을 지원하지만 주의 필요
// Virtual Thread: OS 스레드에 마운트·언마운트를 반복
// ThreadLocal은 Virtual Thread ID에 바인딩 → 마운트 상태 변경에 무관하게 동작

// 문제: Virtual Thread는 수백만 개가 생성될 수 있음
// ThreadLocal의 메모리 사용량이 급증할 수 있음

// Java 21 ScopedValue (ThreadLocal 대안 검토 중):
// Spring Security 팀은 Virtual Thread 환경에서
// ScopedValue 기반 SecurityContextHolder 전략을 검토 중
// (Spring Security 7.x에서 변경 가능성)

// 현재(Spring Security 6.x) 권장 설정:
// Virtual Thread 환경에서도 기본 MODE_THREADLOCAL 사용 가능
// 단, 스레드 풀을 사용하는 @Async는 여전히 DelegatingSecurityContextExecutor 필요
```

---

## 💻 실험으로 확인하기

### 실험 1: ThreadLocal 격리 확인

```java
@GetMapping("/context-test")
public Map<String, Object> contextTest(Authentication auth) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("thread", Thread.currentThread().getName());
    result.put("principal", auth != null ? auth.getName() : "anonymous");
    result.put("holder-principal",
        SecurityContextHolder.getContext().getAuthentication() != null
            ? SecurityContextHolder.getContext().getAuthentication().getName()
            : "anonymous");
    return result;
}
```

```bash
# 동시에 두 사용자가 요청을 보내면 각각 다른 principal이 응답됨
curl -H "Authorization: Bearer <token-for-kim>" http://localhost:8080/context-test
# → {"thread":"http-nio-8080-exec-1","principal":"kim","holder-principal":"kim"}

curl -H "Authorization: Bearer <token-for-lee>" http://localhost:8080/context-test
# → {"thread":"http-nio-8080-exec-2","principal":"lee","holder-principal":"lee"}
# → 스레드가 다르면 SecurityContext도 완전히 독립
```

### 실험 2: @Async에서 SecurityContext 누락 확인

```java
@RestController
@RequiredArgsConstructor
public class AsyncTestController {

    private final AsyncTestService asyncTestService;

    @GetMapping("/async-test")
    public String asyncTest() {
        String callerName = SecurityContextHolder.getContext()
            .getAuthentication().getName();
        asyncTestService.asyncMethod();
        return "Caller: " + callerName;
    }
}

@Service
public class AsyncTestService {

    @Async
    public void asyncMethod() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // DelegatingSecurityContextAsyncTaskExecutor 없이 실행 시:
        System.out.println("Async thread auth: " + auth); // null 출력
    }
}
```

```yaml
logging:
  level:
    org.springframework.security: DEBUG
```

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/async-test
# 로그: Async thread auth: null
# → @Async 스레드에서 SecurityContext가 비어 있음 확인
```

### 실험 3: clearContext() 미호출 시 메모리 누수 시뮬레이션

```java
// SecurityContextHolderFilter의 finally 블록이 없다면:
// 스레드 풀에서 스레드가 재사용될 때 이전 요청의 SecurityContext가 남아있음

// 직접 Filter를 만들어 clearContext()를 누락시킨 실험:
public class LeakyFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws ServletException, IOException {
        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(new UsernamePasswordAuthenticationToken(
            "hacker", null, List.of()));
        SecurityContextHolder.setContext(ctx);

        chain.doFilter(request, response);
        // clearContext() 없음 → 스레드 풀 반환 후에도 SecurityContext 유지

        // 다음 요청에서 이 스레드를 재사용하면 "hacker"로 인증된 상태로 처리됨!
    }
}
```

---

## 🔒 보안 체크리스트

```
SecurityContext 정리
  ☐ 커스텀 Filter에서 SecurityContext를 설정한 경우 반드시 finally에서 clearContext()
  ☐ 비동기 작업에서 SecurityContext를 복사했다면 작업 완료 후 clearContext()

비동기 처리
  ☐ @Async 사용 시 DelegatingSecurityContextAsyncTaskExecutor 설정
  ☐ CompletableFuture, WebFlux 환경에서는 ReactiveSecurityContextHolder 사용 검토
  ☐ new Thread(() -> ...) 직접 생성 시 DelegatingSecurityContextRunnable 사용

SecurityContext 변경
  ☐ 현재 요청에서 Authentication 변경이 다음 요청에 반영돼야 한다면
     SecurityContextRepository.saveContext() 명시적 호출
  ☐ 권한 변경 후 강제 재인증이 필요한지 검토
```

---

## 🤔 트레이드오프

```
ThreadLocal 기반 SecurityContextHolder:
  장점  호출 스택 전체에서 파라미터 없이 Authentication 접근 가능
        Thread-per-Request 모델에서 완벽한 격리
        Spring MVC, JPA 등 기존 스택과 자연스럽게 연동
  단점  @Async, ThreadPool, CompletableFuture 등 비동기 환경에서 명시적 전파 필요
        Virtual Thread 환경에서 메모리 효율 재검토 필요
        Reactive(WebFlux) 환경에서 사용 불가 → ReactiveSecurityContextHolder 사용

MODE_INHERITABLETHREADLOCAL:
  장점  new Thread()로 직접 생성된 자식 스레드에 자동 전파
  단점  ThreadPool 환경에서는 스레드 재사용으로 인해 전파 불가
        잘못된 컨텍스트가 전파될 위험 (이전 요청의 컨텍스트가 자식 스레드로 전파)
```

---

## 📌 핵심 정리

```
SecurityContextHolder = ThreadLocal 기반 전역 저장소
  동일 스레드 내 어디서든 Authentication 접근 가능
  스레드 간 SecurityContext는 완전히 독립 (격리)

SecurityContextHolderFilter 생명주기
  요청 시작: SecurityContextRepository에서 Supplier<SecurityContext> 로드 (지연)
  요청 처리: ThreadLocal에서 Authentication 조회/저장
  요청 종료: finally { clearContext() } ← 반드시 실행되어야 함

비동기 환경 대응책
  @Async + ThreadPool → DelegatingSecurityContextAsyncTaskExecutor
  직접 스레드 생성  → DelegatingSecurityContextRunnable
  CompletableFuture → DelegatingSecurityContextExecutorService

인증 변경을 다음 요청에 반영하려면
  SecurityContextRepository.saveContext() 명시적 호출 필요
  SecurityContextHolder 변경만으로는 HttpSession에 저장되지 않음
```

---

## 🤔 생각해볼 문제

**Q1.** `SecurityContextHolderFilter`가 `finally` 블록에서 `clearContext()`를 호출하지 않는다면 어떤 보안 위험이 발생하는가? Tomcat의 스레드 풀 크기가 10이고 초당 100개의 요청이 들어올 때 구체적으로 어떤 상황이 생길 수 있는가?

**Q2.** Spring WebFlux (Reactive)에서는 `SecurityContextHolder`(ThreadLocal) 대신 `ReactiveSecurityContextHolder`(Reactor Context)를 사용합니다. 이 차이가 존재하는 이유를 Reactor의 이벤트 루프 모델과 연결해서 설명하라.

**Q3.** `DelegatingSecurityContextRunnable`은 내부적으로 어떻게 SecurityContext를 자식 스레드로 전파하는가? `SecurityContextHolder.getContext()`를 호출하는 시점이 Runnable 생성 시점인지 실행 시점인지에 따라 결과가 달라질 수 있는가?

> 💡 **해설**
>
> **Q1.** `clearContext()`가 누락되면 스레드 풀의 스레드가 요청 처리 후 풀로 반환될 때 ThreadLocal에 이전 요청의 `SecurityContext`가 남아 있습니다. Tomcat 스레드 풀 크기가 10이고 초당 100개 요청이 들어오면 10개의 스레드가 재사용되며, 재사용된 스레드에서 처리되는 다음 요청은 이전 요청의 `Authentication`을 그대로 사용합니다. 예를 들어 관리자(ROLE_ADMIN)의 요청을 처리한 스레드가 일반 사용자 요청에 재사용되면, 일반 사용자가 관리자 권한으로 처리될 수 있습니다. 이는 심각한 권한 상승 취약점입니다.
>
> **Q2.** Reactor의 이벤트 루프 모델에서는 하나의 OS 스레드(이벤트 루프 스레드)가 수많은 요청을 비동기적으로 처리합니다. 따라서 스레드 기반의 ThreadLocal을 사용하면 이벤트 루프 스레드의 ThreadLocal이 모든 요청에서 공유되어 격리가 불가능합니다. Reactor Context는 비동기 파이프라인을 따라 전파되는 불변(immutable) 맵으로, 특정 스레드가 아닌 특정 파이프라인 실행 흐름에 데이터를 바인딩합니다. `ReactiveSecurityContextHolder`는 이 Reactor Context에 `SecurityContext`를 저장하여 비동기 파이프라인 전체에서 올바른 인증 정보가 전파되도록 합니다.
>
> **Q3.** `DelegatingSecurityContextRunnable`은 생성 시점에 `SecurityContextHolder.getContext()`를 호출해 현재 스레드의 `SecurityContext`를 캡처합니다. 실행 시점(`run()`)에는 캡처한 `SecurityContext`를 새 스레드의 `SecurityContextHolder`에 설정하고 원래 `Runnable`을 실행한 뒤 `clearContext()`를 호출합니다. 따라서 생성 시점이 중요합니다. 만약 `SecurityContext`가 설정되기 전에 `DelegatingSecurityContextRunnable`을 생성하면 빈 컨텍스트가 캡처됩니다. 이 때문에 반드시 인증이 완료된 이후 시점(Filter 체인 안)에서 생성해야 합니다.

---

<div align="center">

**[← 이전: Security Filter 15개 완전 정복](./03-security-filters-order.md)** | **[홈으로 🏠](../README.md)** | **[다음: Authentication 객체 구조 ➡️](./05-authentication-object.md)**

</div>
