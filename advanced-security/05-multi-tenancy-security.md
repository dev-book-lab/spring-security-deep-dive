# Multi-tenancy Security 전략 — SecurityFilterChain 분리와 데이터 격리

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- 테넌트별 `SecurityFilterChain` 분리 전략과 요청을 올바른 체인으로 라우팅하는 방법은?
- `TenantContextHolder`와 `SecurityContextHolder`를 연계하는 올바른 순서와 구현은?
- Row-Level Security와 `@PreAuthorize`를 결합한 데이터 격리 패턴은?
- 멀티 테넌트에서 JWT 토큰에 테넌트 정보를 포함하는 방법과 검증은?
- 테넌트 간 데이터 교차 접근(Tenant Data Leakage)을 방지하는 레이어별 전략은?
- Spring Security에서 테넌트별 다른 인증 정책(SAML, OAuth2, Local)을 지원하는 방법은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 멀티 테넌시에서 보안이 중요한 이유

```
SaaS 멀티 테넌트 시스템:
  테넌트 A: 회사 A의 사용자들 (데이터 A)
  테넌트 B: 회사 B의 사용자들 (데이터 B)

  핵심 요구사항: 테넌트 A가 테넌트 B의 데이터에 절대 접근 불가

  보안 위협:
  1. 테넌트 컨텍스트 없이 쿼리 실행 → 모든 테넌트 데이터 반환
  2. tenantId를 클라이언트가 조작 → 다른 테넌트 데이터 접근
  3. SQL Injection으로 테넌트 필터 우회
  4. JWT 토큰의 tenantId 클레임 변조

  방어 레이어:
  레이어 1: Security Filter (인증/테넌트 컨텍스트 설정)
  레이어 2: @PreAuthorize (메서드 수준 테넌트 검증)
  레이어 3: Repository (쿼리 수준 테넌트 필터)
  레이어 4: DB Row-Level Security (DB 수준 최후 방어선)
```

---

## 😱 흔한 보안 실수

### Before: tenantId를 요청 파라미터로 받아 신뢰

```java
// ❌ 클라이언트가 전달한 tenantId를 신뢰
@GetMapping("/api/orders")
public List<Order> getOrders(@RequestParam String tenantId) {
    // tenantId를 파라미터로 받으면 클라이언트가 임의 값 전달 가능
    return orderRepository.findByTenantId(tenantId);
    // → 공격자: tenantId=other-tenant → 다른 테넌트 데이터 노출
}

// ✅ 인증된 사용자의 JWT 또는 세션에서 tenantId 추출
@GetMapping("/api/orders")
public List<Order> getOrders(Authentication authentication) {
    CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();
    String tenantId = user.getTenantId(); // 서버 측에서 결정된 tenantId
    return orderRepository.findByTenantId(tenantId);
}
```

### Before: TenantContextHolder 설정을 SecurityContextHolder 설정 이후에 함

```java
// ❌ 순서 문제: SecurityContext가 설정된 후 TenantContext를 설정하면
// @PreAuthorize 등 Security 평가 시 TenantContext가 아직 설정 안 됐을 수 있음

// 필터 실행 순서:
// JwtAuthFilter → SecurityContext 설정
// TenantFilter → TenantContext 설정 (너무 늦음!)
// AuthorizationFilter → @PreAuthorize에서 TenantContext 접근 → null

// ✅ TenantFilter를 JwtAuthFilter 다음, AuthorizationFilter 이전에 배치
// 또는 JwtAuthFilter에서 JWT의 tenantId를 추출해 동시에 TenantContext 설정
```

---

## ✨ 올바른 보안 구현

### 멀티 테넌트 보안 전체 구현

```java
// ① TenantContextHolder — 요청별 테넌트 컨텍스트
public class TenantContextHolder {

    private static final ThreadLocal<String> CONTEXT =
        new InheritableThreadLocal<>();

    public static void setTenantId(String tenantId) {
        CONTEXT.set(tenantId);
    }

    public static String getTenantId() {
        String tenantId = CONTEXT.get();
        if (tenantId == null) {
            throw new TenantContextMissingException(
                "TenantContext not set for current thread");
        }
        return tenantId;
    }

    public static void clear() {
        CONTEXT.remove();
    }
}

// ② JWT 필터에서 tenantId 추출 + TenantContext 설정
@Component
@RequiredArgsConstructor
public class JwtTenantAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, ...) {
        String token = resolveToken(request);
        if (token != null) {
            try {
                Claims claims = jwtTokenProvider.getClaims(token);
                String username = claims.getSubject();
                String tenantId = claims.get("tenantId", String.class);

                if (tenantId == null) {
                    throw new JwtException("Missing tenantId claim");
                }

                // ★ 순서 중요: TenantContext를 SecurityContext와 동시에 설정
                TenantContextHolder.setTenantId(tenantId);

                UserDetails userDetails =
                    userDetailsService.loadUserByUsername(username);

                // tenantId와 사용자의 tenantId 일치 검증
                if (!tenantId.equals(
                        ((CustomUserDetails) userDetails).getTenantId())) {
                    throw new JwtException("Token tenantId mismatch");
                }

                UsernamePasswordAuthenticationToken auth =
                    UsernamePasswordAuthenticationToken.authenticated(
                        userDetails, null, userDetails.getAuthorities());

                SecurityContext ctx = SecurityContextHolder.createEmptyContext();
                ctx.setAuthentication(auth);
                SecurityContextHolder.setContext(ctx);

            } catch (JwtException e) {
                TenantContextHolder.clear();
                SecurityContextHolder.clearContext();
            }
        }
        try {
            chain.doFilter(request, response);
        } finally {
            TenantContextHolder.clear(); // 반드시 정리
        }
    }
}

// ③ 테넌트별 SecurityFilterChain 분리
@Configuration
@EnableWebSecurity
@Order(1) // 다른 FilterChain보다 먼저
public class AdminTenantSecurityConfig {

    @Bean
    public SecurityFilterChain adminChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/admin/**")
            .authorizeHttpRequests(auth -> auth
                .anyRequest().hasRole("SUPER_ADMIN")
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            );
        return http.build();
    }
}

@Configuration
@EnableWebSecurity
@Order(2)
public class ApiSecurityConfig {

    @Bean
    public SecurityFilterChain apiChain(HttpSecurity http,
                                         JwtTenantAuthenticationFilter jwtFilter) throws Exception {
        http
            .securityMatcher("/api/**")
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}

// ④ Repository 레이어 테넌트 필터
@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {

    // 모든 쿼리에 tenantId 조건 추가
    List<Order> findByTenantId(String tenantId);
    Optional<Order> findByIdAndTenantId(Long id, String tenantId);

    // Spring Data JPA @Query로 테넌트 조건 강제
    @Query("SELECT o FROM Order o WHERE o.id = :id " +
           "AND o.tenantId = :#{T(com.example.TenantContextHolder).getTenantId()}")
    Optional<Order> findSecureById(@Param("id") Long id);
}

// ⑤ @PreAuthorize + TenantContext 결합
@Service
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;

    @PreAuthorize("@tenantSecurity.isSameTenant(#orderId)")
    public Order getOrder(Long orderId) {
        return orderRepository.findByIdAndTenantId(
            orderId, TenantContextHolder.getTenantId()
        ).orElseThrow(() -> new AccessDeniedException("Order not found"));
    }
}

// 테넌트 보안 빈
@Component("tenantSecurity")
public class TenantSecurityService {

    private final OrderRepository orderRepository;

    // 대상 리소스가 현재 테넌트에 속하는지 확인
    public boolean isSameTenant(Long orderId) {
        String currentTenantId = TenantContextHolder.getTenantId();
        return orderRepository
            .findByIdAndTenantId(orderId, currentTenantId)
            .isPresent();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. 테넌트별 SecurityFilterChain 분리 — RequestMatcher 기반

```java
// Spring Security는 여러 SecurityFilterChain을 순서대로 검사
// 첫 번째 매칭되는 FilterChain이 처리

// @Order(1): SAML 로그인 테넌트
@Bean
@Order(1)
public SecurityFilterChain samlChain(HttpSecurity http) throws Exception {
    http.securityMatcher(request -> {
        // X-Tenant-ID 헤더로 SAML 테넌트 구분
        String tenantId = request.getHeader("X-Tenant-ID");
        return samlTenants.contains(tenantId);
    });
    // SAML 설정...
    return http.build();
}

// @Order(2): OAuth2 로그인 테넌트
@Bean
@Order(2)
public SecurityFilterChain oauth2Chain(HttpSecurity http) throws Exception {
    http.securityMatcher(request -> {
        String tenantId = request.getHeader("X-Tenant-ID");
        return oauth2Tenants.contains(tenantId);
    });
    // OAuth2 설정...
    return http.build();
}

// @Order(3): 기본 로컬 인증
@Bean
@Order(3)
public SecurityFilterChain defaultChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/**"); // 나머지 모두
    // 로컬 인증 설정...
    return http.build();
}
```

### 2. TenantContextHolder 생명주기 관리

```java
// 올바른 TenantContext 생명주기:

// 요청 시작:
// JwtTenantAuthenticationFilter.doFilterInternal() {
//   try {
//     TenantContextHolder.setTenantId(tenantId);  ← 설정
//     SecurityContextHolder.setContext(ctx);
//     chain.doFilter(request, response);
//   } finally {
//     TenantContextHolder.clear();                ← 반드시 정리
//     // SecurityContextHolderFilter도 clearContext() 호출
//   }
// }

// 주의: @Async 메서드에서 TenantContextHolder 접근
// → 새 스레드에서 InheritableThreadLocal은 상속됨
// → 하지만 명시적으로 전파하는 것이 안전

@Component
public class TenantAwareAsyncConfig implements AsyncConfigurer {
    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setTaskDecorator(runnable -> {
            String tenantId = TenantContextHolder.getTenantId();
            return () -> {
                TenantContextHolder.setTenantId(tenantId); // 비동기 스레드에 전파
                try {
                    runnable.run();
                } finally {
                    TenantContextHolder.clear();
                }
            };
        });
        return executor;
    }
}
```

### 3. Hibernate Filter로 Row-Level Security 구현

```java
// Hibernate의 @FilterDef + @Filter로 테넌트 조건 자동 추가

// ① Entity 레벨 Filter 정의
@Entity
@FilterDef(name = "tenantFilter",
           parameters = @ParamDef(name = "tenantId", type = String.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class Order {
    @Id
    private Long id;

    @Column(name = "tenant_id")
    private String tenantId;

    // ...
}

// ② Filter 활성화 (Hibernate Session 레벨)
@Component
@RequiredArgsConstructor
public class TenantFilterInterceptor implements HandlerInterceptor {

    private final EntityManager entityManager;

    @Override
    public boolean preHandle(HttpServletRequest request,
                              HttpServletResponse response, Object handler) {
        // 모든 Hibernate 쿼리에 tenantFilter 자동 적용
        Session session = entityManager.unwrap(Session.class);
        session.enableFilter("tenantFilter")
            .setParameter("tenantId", TenantContextHolder.getTenantId());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, ...) {
        Session session = entityManager.unwrap(Session.class);
        session.disableFilter("tenantFilter");
    }
}

// 결과: 모든 Hibernate 쿼리에 "AND tenant_id = ?" 자동 추가
// orderRepository.findAll() → SELECT * FROM orders WHERE tenant_id = 'tenant-a'
```

### 4. JWT에 tenantId 포함 및 검증

```java
// 토큰 발급 시 tenantId 포함
public String createToken(Long userId, String username,
                           String tenantId, List<String> roles) {
    return Jwts.builder()
        .setSubject(username)
        .claim("userId", userId)
        .claim("tenantId", tenantId)  // ← 테넌트 정보 포함
        .claim("roles", roles)
        .setExpiration(new Date(System.currentTimeMillis() + expiry))
        .signWith(secretKey)
        .compact();
}

// 검증 시 tenantId 교차 검증
public void validateTenantClaim(Claims claims, HttpServletRequest request) {
    String tokenTenantId = claims.get("tenantId", String.class);
    // 요청 헤더의 tenantId와 토큰의 tenantId 일치 확인
    String headerTenantId = request.getHeader("X-Tenant-ID");

    if (headerTenantId != null && !headerTenantId.equals(tokenTenantId)) {
        throw new JwtException("Tenant ID mismatch in token and request header");
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 테넌트 간 데이터 격리 확인

```java
@SpringBootTest
class TenantIsolationTest {

    @Test
    @WithCustomOAuth2User(tenantId = "tenant-a")
    void tenantA_cannotAccess_tenantB_orders() {
        // given: tenant-b의 주문
        Order tenantBOrder = orderRepository.save(
            Order.builder().tenantId("tenant-b").build());

        // when: tenant-a가 tenant-b 주문 접근 시도
        // @PreAuthorize에서 tenantId 불일치 → 거부
        assertThatThrownBy(() -> orderService.getOrder(tenantBOrder.getId()))
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithCustomOAuth2User(tenantId = "tenant-a")
    void tenantA_canAccess_ownOrders() {
        Order ownOrder = orderRepository.save(
            Order.builder().tenantId("tenant-a").build());

        assertDoesNotThrow(() -> orderService.getOrder(ownOrder.getId()));
    }
}
```

### 실험 2: TenantContextHolder 스레드 안전성 확인

```java
@Test
void tenantContext_isolatedPerThread() throws InterruptedException {
    CountDownLatch latch = new CountDownLatch(2);
    List<String> capturedTenants = Collections.synchronizedList(new ArrayList<>());

    // 두 스레드가 각각 다른 tenantId 설정
    Thread threadA = new Thread(() -> {
        TenantContextHolder.setTenantId("tenant-a");
        try { Thread.sleep(100); } catch (InterruptedException e) {}
        capturedTenants.add(TenantContextHolder.getTenantId());
        TenantContextHolder.clear();
        latch.countDown();
    });

    Thread threadB = new Thread(() -> {
        TenantContextHolder.setTenantId("tenant-b");
        try { Thread.sleep(50); } catch (InterruptedException e) {}
        capturedTenants.add(TenantContextHolder.getTenantId());
        TenantContextHolder.clear();
        latch.countDown();
    });

    threadA.start();
    threadB.start();
    latch.await();

    // 각 스레드가 자신의 tenantId를 정확히 읽었는지 확인
    assertThat(capturedTenants).containsExactlyInAnyOrder("tenant-a", "tenant-b");
}
```

### 실험 3: Hibernate Filter 적용 확인

```java
@Test
@WithCustomOAuth2User(tenantId = "tenant-a")
void hibernateFilter_automatically_applies_tenantCondition() {
    // given: 두 테넌트의 주문
    Order orderA = testEntityManager.persistAndFlush(Order.of("tenant-a"));
    Order orderB = testEntityManager.persistAndFlush(Order.of("tenant-b"));

    // when: tenant-a의 필터 활성화 상태에서 전체 조회
    List<Order> result = orderRepository.findAll();

    // then: tenant-a 주문만 반환
    assertThat(result).hasSize(1);
    assertThat(result.get(0).getTenantId()).isEqualTo("tenant-a");
    // SQL 로그: SELECT * FROM orders WHERE tenant_id = 'tenant-a'
}
```

---

## 🔒 보안 체크리스트

```
테넌트 컨텍스트 설정
  ☐ tenantId는 서버 측(JWT/세션)에서만 결정 (클라이언트 파라미터 신뢰 금지)
  ☐ TenantContextHolder.clear() 반드시 finally 블록에서 실행
  ☐ @Async, 배치 작업에서 TenantContext 명시적 전파

데이터 격리
  ☐ Repository 쿼리에 tenantId 조건 항상 포함
  ☐ 단독 id 조회 금지 (findById → findByIdAndTenantId)
  ☐ Hibernate Filter 또는 JPA Specification으로 자동 필터링
  ☐ DB Row-Level Security 설정 (최후 방어선)

@PreAuthorize 연계
  ☐ @tenantSecurity.isSameTenant() 등 커스텀 검증 빈 활용
  ☐ 테넌트 간 공유 리소스는 명시적 예외 처리
  ☐ SUPER_ADMIN 역할의 교차 테넌트 접근 별도 구현

멀티 FilterChain
  ☐ @Order로 명확한 우선순위 설정
  ☐ securityMatcher로 명확한 경로/조건 분리
  ☐ 각 테넌트 타입별 인증 정책(SAML, OAuth2, Local) 독립 설정
```

---

## 🤔 트레이드오프

```
Single DB (스키마 분리) vs Shared DB (컬럼 필터):
  Single DB:
    장점  완전한 데이터 격리, 테넌트별 독립 백업/복구
    단점  리소스 비효율 (DB 인스턴스 증가), 운영 복잡도

  Shared DB (Row-Level):
    장점  리소스 효율, 단순한 운영
    단점  tenantId 필터 누락 시 데이터 누출 위험
          쿼리 성능: tenantId 인덱스 필수

Hibernate Filter vs @Query 명시:
  Hibernate Filter:
    장점  자동으로 모든 쿼리에 적용 → 누락 위험 없음
    단점  필터 활성화를 항상 확인해야 함, JPQL 복잡도

  @Query 명시:
    장점  쿼리가 명확, 검토 용이
    단점  테넌트 조건 누락 실수 가능 → 데이터 누출

TenantContextHolder (ThreadLocal) vs Request Attribute:
  ThreadLocal:
    장점  어디서든 직접 접근 가능
    단점  @Async에서 전파 필요, 스레드 풀 오염 위험

  Request Attribute:
    장점  명시적, 요청 범위 자동 관리
    단점  HttpServletRequest 의존 → 서비스 레이어에서 접근 어려움
```

---

## 📌 핵심 정리

```
멀티 테넌트 보안 레이어
  레이어 1: JWT tenantId 클레임 → TenantContextHolder 설정
  레이어 2: @PreAuthorize → @tenantSecurity.isSameTenant() 검증
  레이어 3: Repository → findByIdAndTenantId() 쿼리 필터
  레이어 4: Hibernate Filter → 모든 쿼리 자동 tenantId 조건 추가

TenantContextHolder 원칙
  서버 측 JWT에서만 tenantId 결정 (클라이언트 신뢰 금지)
  JwtAuthFilter에서 설정 → finally 블록에서 반드시 clear()
  @Async: TaskDecorator로 비동기 스레드에 명시적 전파

테넌트별 FilterChain 분리
  @Order + securityMatcher로 테넌트 타입별 인증 정책 분리
  각 체인이 독립적인 인증 메커니즘(SAML, OAuth2, Local) 가능

데이터 격리 핵심
  단독 id 조회 금지: findById(id) → findByIdAndTenantId(id, tenantId)
  Hibernate @Filter로 모든 쿼리에 tenantId 자동 추가
  테넌트 간 공유 데이터는 명시적 설계로 예외 처리
```

---

## 🤔 생각해볼 문제

**Q1.** `TenantContextHolder`에 `InheritableThreadLocal`을 사용했습니다. Spring의 스레드 풀(예: `@Async`에서 사용하는 `ThreadPoolTaskExecutor`)에서 스레드가 재사용될 때, 이전 요청의 테넌트 정보가 다음 요청에서 잘못 사용되는 문제가 발생할 수 있는가? 어떻게 방지하는가?

**Q2.** 멀티 테넌트 환경에서 SUPER_ADMIN이 모든 테넌트의 데이터를 조회해야 하는 관리 기능을 구현할 때, `TenantContextHolder`와 `@PreAuthorize`를 어떻게 설계해야 특정 테넌트 접근 시에만 컨텍스트를 바꾸면서 일반 사용자의 격리를 유지할 수 있는가?

**Q3.** Hibernate `@Filter`를 활성화하지 않은 채로 `findAll()` 쿼리가 실행되면 모든 테넌트 데이터가 노출됩니다. `@Filter` 활성화를 강제하는 방법과, 테스트 환경에서 필터 활성화를 누락했을 때 감지하는 방법은?

> 💡 **해설**
>
> **Q1.** 스레드 풀에서 스레드가 재사용될 때 `InheritableThreadLocal`의 값이 이전 요청의 것으로 남아있을 수 있습니다. 방지 방법: 첫째, `JwtTenantAuthenticationFilter`의 `finally` 블록에서 `TenantContextHolder.clear()`를 반드시 호출합니다. 이렇게 하면 요청이 끝날 때 항상 정리됩니다. 둘째, `TaskDecorator`를 사용해 비동기 스레드에 진입할 때 현재 컨텍스트를 복사하고 종료 시 정리합니다. 셋째, `ThreadLocal` 대신 요청 범위 Bean(`@RequestScope`)을 사용하면 요청이 끝나면 자동으로 소멸합니다. `InheritableThreadLocal`은 자식 스레드에 자동 전파되지만 스레드 풀 재사용 시 오염 위험이 있으므로 `ThreadLocal`을 사용하고 명시적으로 전파하는 것이 더 안전합니다.
>
> **Q2.** SUPER_ADMIN 전용 컨텍스트 전환 패턴: SUPER_ADMIN 요청에서는 대상 테넌트 ID를 안전한 경로(요청 헤더 + SUPER_ADMIN 역할 검증)로 받습니다. SUPER_ADMIN 전용 서비스 메서드는 `@PreAuthorize("hasRole('SUPER_ADMIN')")`으로 보호하고, 내부에서 `TenantContextHolder.setTenantId(targetTenantId)`로 일시적으로 컨텍스트를 변경합니다. 일반 테넌트 사용자는 JWT의 tenantId로만 컨텍스트가 설정되어 `isAuthenticated()`가 아닌 `hasRole('USER')` 체크를 통과하더라도 TenantContext가 자신의 테넌트로 고정됩니다. Repository 레이어에서도 `TenantContextHolder.getTenantId()`를 사용해 항상 현재 컨텍스트의 테넌트로 쿼리합니다.
>
> **Q3.** `@Filter` 활성화를 강제하는 방법: Spring AOP를 사용해 Repository 메서드 호출 전에 필터 활성화 여부를 확인하고, 활성화되지 않았으면 예외를 발생시키거나 자동으로 활성화합니다. `EntityManager`를 래핑한 커스텀 클래스에서 `findAll()` 등의 위험 메서드 호출 시 필터 활성화를 강제합니다. 또는 Hibernate Interceptor에서 쿼리 실행 전 필터 활성화를 체크합니다. 테스트에서 감지하는 방법: 통합 테스트에서 멀티 테넌트 데이터를 입력한 후 각 테넌트 컨텍스트에서 `findAll()` 결과 크기를 검증합니다. `findAll()` 결과에 다른 테넌트 데이터가 포함되면 테스트 실패로 감지합니다. ArchUnit을 사용해 `findAll()` 직접 호출을 금지하고 `findByTenantId()`를 강제하는 아키텍처 테스트를 추가합니다.

---

<div align="center">

**[← 이전: Method Security SpEL 고급 활용](./04-method-security-spel-advanced.md)** | **[홈으로 🏠](../README.md)** | **[🎉 Spring Security Deep Dive 완주!](../README.md)**

</div>
