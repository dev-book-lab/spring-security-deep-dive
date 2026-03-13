# DelegatingFilterProxy와 FilterChainProxy — Servlet Container와 Spring의 책임 분리

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- Servlet Container는 왜 Spring의 Bean을 직접 Servlet Filter로 등록할 수 없는가?
- `DelegatingFilterProxy`는 구체적으로 어떤 문제를 해결하기 위해 존재하는가?
- `springSecurityFilterChain`이라는 이름의 Bean이 생성되는 시점은 언제인가?
- `FilterChainProxy`가 `DelegatingFilterProxy`로부터 요청을 넘겨받는 정확한 코드 경로는?
- `SecurityFilterChain`이 여러 개 등록되어 있을 때 어떤 기준으로 하나를 선택하는가?
- `VirtualFilterChain`은 무엇이며, 왜 실제 `FilterChain`을 감싸는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: Servlet Container와 Spring ApplicationContext는 서로 다른 생명주기를 가진다

```
일반적인 웹 애플리케이션 시작 순서:

  1. Servlet Container (Tomcat) 시작
  2. web.xml 또는 ServletContainerInitializer 읽기
  3. Filter 등록 → Servlet Container가 Filter 인스턴스 직접 생성
  4. Servlet 등록 (DispatcherServlet 등)
  5. Spring ApplicationContext 초기화 (DispatcherServlet.init())
  6. Bean 생성 (Service, Repository, Security 설정 등)

문제:
  3단계에서 Filter를 등록할 때 Spring ApplicationContext(6단계)는 아직 없다
  → Servlet Container는 Spring의 Bean을 Filter로 등록할 방법이 없다
  → 즉, SecurityFilter들을 @Component나 @Bean으로 만들어도
     Servlet Container가 Filter 체인에 직접 끼워 넣지 못한다
```

Spring Security는 수십 개의 Filter를 Spring Bean으로 관리해야 합니다. 왜냐하면 이 Filter들이 `UserDetailsService`, `PasswordEncoder`, `JwtTokenProvider` 같은 Spring Bean에 의존하기 때문입니다. 그러나 Servlet Container는 Spring의 세계를 모릅니다.

이 간극을 메우는 것이 바로 `DelegatingFilterProxy`의 역할입니다.

```
해결책: 브릿지 패턴

  Servlet Container가 아는 세계        Spring이 아는 세계
  ─────────────────────────────         ──────────────────────────
  DelegatingFilterProxy (일반 Filter)  FilterChainProxy (Spring Bean)
       ↕                                       ↕
  Servlet Container에 등록됨           ApplicationContext에서 관리됨
       ↕                                       ↕
  요청을 받으면 Spring Bean에게 위임 →  실제 Security Filter 15개 실행
```

---

## 😱 흔한 보안 실수

### Before: SecurityConfig를 작성했는데 보안이 전혀 적용되지 않는다

```java
// ❌ 문제 상황: FilterChainProxy가 Filter 체인에 끼워지지 않은 경우
//
// Spring Boot 없이 순수 Spring MVC + Spring Security를 사용할 때
// web.xml에 DelegatingFilterProxy를 등록하지 않으면:

// web.xml
<servlet>
    <servlet-name>dispatcher</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>dispatcher</servlet-name>
    <url-pattern>/</url-pattern>
</servlet-mapping>
<!-- DelegatingFilterProxy 누락! → 보안 필터 전혀 동작 안 함 -->

// SecurityConfig에 아무리 정교한 설정을 해도
// 요청이 SecurityFilterChain을 거치지 않으므로 모두 허용됨
// → 인증 없이 /admin 접근 가능, CSRF 방어 없음, 세션 고정 방어 없음
```

```java
// ✅ 올바른 등록: DelegatingFilterProxy를 반드시 등록
// web.xml
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
// filter-name이 "springSecurityFilterChain"인 것이 핵심
// DelegatingFilterProxy가 ApplicationContext에서 이 이름의 Bean을 찾아 위임
```

### Before: 여러 SecurityFilterChain 등록 시 모든 체인이 실행된다고 오해

```java
// ❌ 잘못된 이해:
// "SecurityFilterChain을 2개 등록하면 요청이 두 체인 모두를 통과한다"

@Bean
@Order(1)
public SecurityFilterChain adminChain(HttpSecurity http) throws Exception {
    return http.requestMatcher(new AntPathRequestMatcher("/admin/**"))
               .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ADMIN"))
               .build();
}

@Bean
@Order(2)
public SecurityFilterChain defaultChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
               .build();
}

// ✅ 실제:
// FilterChainProxy는 요청마다 RequestMatcher로 체인을 선택하고
// 매칭된 첫 번째 체인만 실행한다
// /admin/users → adminChain만 실행 (defaultChain은 실행되지 않음)
// /api/users   → adminChain의 RequestMatcher 불일치 → defaultChain 실행
```

---

## ✨ 올바른 보안 구현

### Spring Boot 환경에서의 자동 등록

Spring Boot를 사용하면 `DelegatingFilterProxy` 등록이 자동으로 이루어집니다.

```java
// SecurityAutoConfiguration이 FilterChainProxy를 Bean으로 등록
// SpringBootWebSecurityConfiguration이 기본 SecurityFilterChain 제공
// SecurityFilterAutoConfiguration이 DelegatingFilterProxy를 Servlet Filter로 등록

// 개발자가 해야 할 일은 SecurityFilterChain Bean만 정의하는 것
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );
        return http.build();
    }
}
// 이 Bean이 등록되는 순간:
// 1. HttpSecurity가 SecurityFilterChain 인스턴스를 생성
// 2. FilterChainProxy가 이 체인을 내부 목록에 추가
// 3. DelegatingFilterProxy가 이미 Servlet Container에 등록되어 있음
// → 모든 요청이 자동으로 이 SecurityFilterChain을 통과
```

---

## 🔬 내부 동작 원리

### 1. DelegatingFilterProxy — 지연 초기화 브릿지

```java
// DelegatingFilterProxy.java (spring-web)
public class DelegatingFilterProxy extends GenericFilterBean {

    @Nullable
    private String contextAttribute;    // WebApplicationContext를 찾을 Servlet Context 속성 이름
    @Nullable
    private WebApplicationContext webApplicationContext;
    @Nullable
    private String targetBeanName;      // 위임할 Bean의 이름 ("springSecurityFilterChain")
    @Nullable
    private volatile Filter delegate;  // 실제 위임 대상 (FilterChainProxy)

    // ① Servlet Container가 Filter를 초기화할 때 호출
    @Override
    protected void initFilterBean() throws ServletException {
        synchronized (this.delegateMonitor) {
            if (this.delegate == null) {
                // targetBeanName이 null이면 filter-name을 그대로 사용
                // → "springSecurityFilterChain"
                if (this.targetBeanName == null) {
                    this.targetBeanName = getFilterName();
                }
                // ApplicationContext가 이미 존재하면 지금 바로 delegate 초기화
                WebApplicationContext wac = findWebApplicationContext();
                if (wac != null) {
                    this.delegate = initDelegate(wac);
                }
                // ApplicationContext가 아직 없으면 → doFilter()에서 지연 초기화
            }
        }
    }

    // ② 실제 요청이 들어올 때 호출
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain filterChain)
            throws ServletException, IOException {

        Filter delegateToUse = this.delegate;

        // 지연 초기화: ApplicationContext가 완전히 준비된 후 첫 요청 시점에 초기화
        if (delegateToUse == null) {
            synchronized (this.delegateMonitor) {
                delegateToUse = this.delegate;
                if (delegateToUse == null) {
                    WebApplicationContext wac = findWebApplicationContext();
                    if (wac == null) {
                        throw new IllegalStateException("No WebApplicationContext found...");
                    }
                    delegateToUse = initDelegate(wac); // ③ ApplicationContext에서 Bean 조회
                    this.delegate = delegateToUse;
                }
            }
        }

        // ④ FilterChainProxy에게 요청 위임
        invokeDelegate(delegateToUse, request, response, filterChain);
    }

    // ③ ApplicationContext에서 "springSecurityFilterChain" Bean 조회
    protected Filter initDelegate(WebApplicationContext wac) throws ServletException {
        String targetBeanName = getTargetBeanName();
        // getBean("springSecurityFilterChain", Filter.class)
        Filter delegate = wac.getBean(targetBeanName, Filter.class);
        if (isTargetFilterLifecycle()) {
            delegate.init(getFilterConfig());
        }
        return delegate; // FilterChainProxy 반환
    }

    // ④ 단순 위임 — 직접 처리하지 않고 FilterChainProxy에 넘김
    protected void invokeDelegate(Filter delegate, ServletRequest request,
                                   ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        delegate.doFilter(request, response, filterChain);
    }
}
```

**핵심 포인트**: `DelegatingFilterProxy`는 요청을 아무것도 직접 처리하지 않습니다. 오직 "Servlet Container ↔ Spring Bean" 연결 고리 역할만 합니다.

### 2. FilterChainProxy — 체인 선택과 실행

```java
// FilterChainProxy.java (spring-security-web)
public class FilterChainProxy extends GenericFilterBean {

    // 등록된 모든 SecurityFilterChain 목록
    // @Order 순서로 정렬되어 있음
    private List<SecurityFilterChain> filterChains;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain)
            throws IOException, ServletException {

        // 방화벽 체크: HttpFirewall으로 악의적인 요청 사전 차단
        // (디렉토리 트래버설, 비정상 URL 인코딩 등)
        FirewalledRequest firewallRequest =
            this.firewall.getFirewalledRequest((HttpServletRequest) request);
        HttpServletResponse firewallResponse =
            this.firewall.getFirewalledResponse((HttpServletResponse) response);

        // 실제 필터 실행
        doFilterInternal(firewallRequest, firewallResponse, chain);
    }

    private void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain)
            throws IOException, ServletException {

        // ① 현재 요청에 맞는 SecurityFilterChain 선택
        List<Filter> filters = getFilters(request);

        if (filters == null || filters.isEmpty()) {
            // 매칭되는 체인이 없음 → 그냥 통과 (보안 처리 없음)
            chain.doFilter(request, response);
            return;
        }

        // ② VirtualFilterChain 생성: 선택된 Filter 목록을 순서대로 실행
        VirtualFilterChain virtualFilterChain =
            new VirtualFilterChain(chain, filters);
        virtualFilterChain.doFilter(request, response);
    }

    // ① RequestMatcher로 매칭되는 첫 번째 SecurityFilterChain 반환
    @Nullable
    private List<Filter> getFilters(HttpServletRequest request) {
        int count = 0;
        for (SecurityFilterChain chain : this.filterChains) {
            if (logger.isTraceEnabled()) {
                logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)",
                    chain, ++count, this.filterChains.size()));
            }
            // RequestMatcher.matches()로 현재 요청이 이 체인의 대상인지 확인
            if (chain.matches(request)) {
                return chain.getFilters(); // 매칭된 첫 번째 체인의 Filter 목록만 반환
            }
        }
        return null;
    }
}
```

### 3. VirtualFilterChain — 실제 FilterChain과의 분리

```java
// FilterChainProxy.VirtualFilterChain (내부 클래스)
private static final class VirtualFilterChain implements FilterChain {

    private final FilterChain originalChain; // Servlet Container의 실제 FilterChain
    private final List<Filter> additionalFilters; // Security Filter 목록
    private int currentPosition = 0;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {

        if (this.currentPosition == this.additionalFilters.size()) {
            // ② Security Filter를 모두 통과한 후 → 원래 FilterChain으로 복귀
            // (DispatcherServlet으로 이어지는 Servlet Container의 체인)
            this.originalChain.doFilter(request, response);
            return;
        }

        // ① 다음 Security Filter 실행
        this.currentPosition++;
        Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
        nextFilter.doFilter(request, response, this);
        // this를 넘기므로 각 Filter가 chain.doFilter()를 호출하면
        // 다시 이 VirtualFilterChain.doFilter()가 호출됨
    }
}
```

**VirtualFilterChain이 필요한 이유**: Security Filter들이 서로 `chain.doFilter()`로 연결될 때 실제 Servlet Container의 FilterChain을 건드리지 않아야 합니다. 가상의 체인을 만들어 Security Filter 목록을 모두 실행한 뒤에야 원래 체인(DispatcherServlet 방향)으로 넘어갑니다.

### 4. 전체 흐름 ASCII 다이어그램

```
HTTP 요청
   │
   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Servlet Container (Tomcat)                      │
│                                                                     │
│   Filter Chain (Servlet Container 관리)                              │
│   ┌─────────────────────┐                                           │
│   │ DelegatingFilterProxy│  ← web.xml 또는 자동 등록                    │
│   │ (Servlet Filter)    │                                           │
│   │                     │                                           │
│   │  delegate.doFilter()├──────────────────────────────────────┐    │
│   └─────────────────────┘                                      │    │
│                                                                │    │
└────────────────────────────────────────────────────────────────┼────┘
                                                                 │
                                            위임 (Spring 세계로 진입)
                                                                 │
┌────────────────────────────────────────────────────────────────▼────┐
│                   Spring ApplicationContext                         │
│                                                                     │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │                    FilterChainProxy                          │  │
│   │                 Bean: "springSecurityFilterChain"            │  │
│   │                                                              │  │
│   │  1. HttpFirewall으로 요청 검증                                  │  │
│   │  2. RequestMatcher로 SecurityFilterChain 선택                  │  │
│   │  3. VirtualFilterChain 생성                                   │  │
│   │                                                              │  │
│   │  VirtualFilterChain (선택된 체인의 Filter 목록 순차 실행)           │  │
│   │  ┌───────────────────────────────────────────────────────┐   │  │
│   │  │ SecurityContextHolderFilter       (1번째)              │   │  │
│   │  │ CsrfFilter                        (2번째)              │   │  │
│   │  │ UsernamePasswordAuthenticationFilter (폼 로그인)        │   │  │
│   │  │ JwtAuthenticationFilter           (커스텀)              │   │  │
│   │  │ AnonymousAuthenticationFilter     (익명 사용자)          │   │  │
│   │  │ ExceptionTranslationFilter        (예외 처리)           │   │  │
│   │  │ AuthorizationFilter               (권한 검사, 마지막)     │   │  │
│   │  └───────────────────────────────────────────────────────┘   │  │
│   │                                                              │  │
│   └──────────────────────────────────────────────────────────────┘  │
│                          │ originalChain.doFilter()                 │
└──────────────────────────┼──────────────────────────────────────────┘
                           │
                           ▼
                    DispatcherServlet → Controller
```

### 5. springSecurityFilterChain Bean이 생성되는 과정

```java
// HttpSecurity.build()가 호출될 때 SecurityFilterChain이 생성됨
// WebSecurityConfiguration.java (Spring Security 내부)

@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
// DEFAULT_FILTER_NAME = "springSecurityFilterChain"
public Filter springSecurityFilterChain() throws Exception {
    // ... 등록된 SecurityFilterChain 목록을 수집
    // ... HttpSecurity로 만들어진 체인들을 FilterChainProxy에 전달
    return this.webSecurity.build(); // FilterChainProxy 반환
}

// WebSecurity.performBuild()에서 FilterChainProxy 생성
@Override
protected Filter performBuild() throws Exception {
    // 등록된 모든 SecurityFilterChain 수집
    List<SecurityFilterChain> securityFilterChains = new ArrayList<>();
    for (RequestMatcher ignoredRequest : this.ignoredRequestMatchers) {
        // permitAll() 처리된 경로는 빈 체인으로 등록 (Filter 없이 바로 통과)
        securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest));
    }
    for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder
            : this.securityFilterChainBuilders) {
        securityFilterChains.add(securityFilterChainBuilder.build());
    }

    // FilterChainProxy 생성 — DelegatingFilterProxy가 참조할 Bean
    FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);

    if (this.httpFirewall != null) {
        filterChainProxy.setFirewall(this.httpFirewall);
    }
    filterChainProxy.afterPropertiesSet();
    return filterChainProxy;
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 등록된 SecurityFilterChain과 Filter 목록 출력

```java
@RestController
@RequiredArgsConstructor
public class SecurityDebugController {

    private final ApplicationContext applicationContext;

    @GetMapping("/debug/filter-chains")
    public List<String> filterChains() {
        // "springSecurityFilterChain" Bean은 사실 FilterChainProxy
        FilterChainProxy proxy = (FilterChainProxy)
            applicationContext.getBean("springSecurityFilterChain");

        return proxy.getFilterChains().stream()
            .flatMap(chain -> chain.getFilters().stream())
            .map(f -> f.getClass().getSimpleName())
            .collect(Collectors.toList());
    }
}
```

```bash
curl http://localhost:8080/debug/filter-chains
# 실행 결과 예시:
# [
#   "WebAsyncManagerIntegrationFilter",
#   "SecurityContextHolderFilter",
#   "HeaderWriterFilter",
#   "CsrfFilter",
#   "LogoutFilter",
#   "UsernamePasswordAuthenticationFilter",
#   "DefaultLoginPageGeneratingFilter",
#   "DefaultLogoutPageGeneratingFilter",
#   "BasicAuthenticationFilter",
#   "RequestCacheAwareFilter",
#   "SecurityContextHolderAwareRequestFilter",
#   "AnonymousAuthenticationFilter",
#   "SessionManagementFilter",
#   "ExceptionTranslationFilter",
#   "AuthorizationFilter"
# ]
```

### 실험 2: TRACE 로그로 체인 선택 과정 관찰

```yaml
# application.yml
logging:
  level:
    org.springframework.security.web.FilterChainProxy: TRACE
```

```
# /admin/users 요청 시 로그 (SecurityFilterChain 2개 등록된 경우):
TRACE FilterChainProxy - Trying to match request against
      DefaultSecurityFilterChain [RequestMatcher=Ant [pattern='/admin/**']] (1/2)
TRACE FilterChainProxy - Securing GET /admin/users

# /api/users 요청 시 로그:
TRACE FilterChainProxy - Trying to match request against
      DefaultSecurityFilterChain [RequestMatcher=Ant [pattern='/admin/**']] (1/2)
TRACE FilterChainProxy - Trying to match request against
      DefaultSecurityFilterChain [RequestMatcher=any request] (2/2)
TRACE FilterChainProxy - Securing GET /api/users
```

### 실험 3: 특정 경로를 Security Filter에서 제외

```java
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring()
        .requestMatchers("/h2-console/**", "/actuator/health");
    // 이 경로는 FilterChainProxy에서 완전히 제외됨
    // (빈 SecurityFilterChain으로 등록 → VirtualFilterChain Filter 목록이 비어 있음)
}
```

```bash
# TRACE 로그 확인
curl http://localhost:8080/actuator/health

# 로그:
# TRACE FilterChainProxy - /actuator/health has no matching filters
# → Security Filter를 하나도 거치지 않고 바로 DispatcherServlet으로 이동
```

### 실험 4: DelegatingFilterProxy의 지연 초기화 확인

```java
// 애플리케이션 시작 시 로그에서 확인 가능
// Servlet Container가 Filter를 초기화하는 시점 vs
// Spring ApplicationContext가 준비되는 시점

// 순서:
// 1. [main] o.s.b.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader
//    → Tomcat 시작
// 2. [main] o.s.web.filter.DelegatingFilterProxy
//    → Filter 초기화 (이 시점에 ApplicationContext가 없을 수 있음)
// 3. [main] o.s.s.web.DefaultSecurityFilterChain
//    → Spring Security FilterChain 생성 완료 (Bean 초기화)
// 4. 첫 요청 시 → DelegatingFilterProxy가 "springSecurityFilterChain" Bean을 ApplicationContext에서 조회
//    → delegate 필드에 FilterChainProxy 저장
```

---

## 🔒 보안 체크리스트

```
DelegatingFilterProxy 등록
  ☐ Spring Boot 사용 중이라면 SecurityFilterAutoConfiguration이 자동 등록
  ☐ 순수 Spring (non-Boot)이라면 web.xml 또는 AbstractSecurityWebApplicationInitializer 확인
  ☐ filter-name이 반드시 "springSecurityFilterChain"인지 확인
  ☐ url-pattern이 /* 인지 확인 (일부 경로 누락 시 보안 우회 가능)

SecurityFilterChain 구성
  ☐ requestMatcher()로 범위를 제한한 체인은 @Order로 기본 체인보다 높은 우선순위 설정
  ☐ 여러 SecurityFilterChain이 겹치지 않는지 RequestMatcher 범위 확인
  ☐ webSecurity.ignoring()은 인증 없이 완전히 노출되는 경로이므로 정적 리소스만 사용

HttpFirewall 설정
  ☐ 기본 StrictHttpFirewall 동작 확인 (비정상 URL은 자동 차단)
  ☐ 특수문자가 포함된 URL이 필요한 경우 DefaultHttpFirewall로 교체 시 보안 위험 인지
```

---

## 🤔 트레이드오프

```
DelegatingFilterProxy 지연 초기화 전략:
  장점  ApplicationContext 초기화 전에 Servlet Container가 Filter를 등록할 수 있음
        Servlet Container와 Spring의 생명주기 불일치 문제를 해결
  단점  첫 요청 시점까지 SecurityContext가 초기화되지 않음
        (실제 문제는 거의 없음 — 첫 요청 전에 ApplicationContext가 완전히 준비됨)

여러 SecurityFilterChain 분리:
  장점  API ↔ 웹 폼 로그인 ↔ 관리자 각각 독립된 보안 정책 적용 가능
        각 체인이 서로 영향을 주지 않음
  단점  체인 수가 많아지면 RequestMatcher 순서 관리 복잡
        @Order 값을 잘못 설정하면 예상치 못한 체인이 선택될 수 있음

VirtualFilterChain을 통한 Filter 실행:
  장점  Servlet Container의 원래 FilterChain을 오염시키지 않음
        Security Filter가 모두 끝난 후에만 DispatcherServlet으로 진입
  단점  Filter 체인이 이중 구조 (Servlet FilterChain → VirtualFilterChain)
        → 디버깅 시 스택 트레이스가 복잡해 보일 수 있음
```

---

## 📌 핵심 정리

```
DelegatingFilterProxy의 역할
  Servlet Container (생명주기 A) ↔ Spring ApplicationContext (생명주기 B) 브릿지
  실제 처리는 일절 하지 않음 — FilterChainProxy에게 100% 위임
  "springSecurityFilterChain" 이름의 Bean을 ApplicationContext에서 지연 조회

FilterChainProxy의 역할
  모든 Security Filter를 Spring Bean으로 관리하는 컨테이너
  요청마다 RequestMatcher로 적절한 SecurityFilterChain 하나를 선택
  VirtualFilterChain으로 선택된 Filter 목록을 순서대로 실행

SecurityFilterChain 선택 규칙
  @Order 값 낮을수록 먼저 시도 (높은 우선순위)
  RequestMatcher.matches()가 true인 첫 번째 체인만 실행
  매칭 체인 없음 → 보안 처리 없이 통과 (위험!)

핵심 Bean 이름
  "springSecurityFilterChain" = FilterChainProxy 인스턴스
  DelegatingFilterProxy의 targetBeanName 기본값 = filter-name = "springSecurityFilterChain"
```

---

## 🤔 생각해볼 문제

**Q1.** `DelegatingFilterProxy`가 `initFilterBean()`에서 바로 `initDelegate()`를 호출하지 않고 `doFilter()` 시점까지 지연하는 경우가 있습니다. 어떤 조건에서 지연 초기화가 발생하며, 이것이 문제가 될 수 있는 시나리오는 무엇인가?

**Q2.** `webSecurity.ignoring().requestMatchers("/images/**")`로 설정한 경로는 `FilterChainProxy` 내부에서 어떻게 처리되는가? `permitAll()`로 설정한 경우와 보안 관점에서 어떤 차이가 있는가?

**Q3.** `FilterChainProxy`의 `getFilters()` 메서드는 매칭되는 첫 번째 `SecurityFilterChain`을 반환하고 나머지는 확인하지 않습니다. 만약 두 개의 `SecurityFilterChain`이 동일한 경로를 `RequestMatcher`로 가지고 있다면 어떤 체인이 실행되고, 이것을 의도적으로 활용하는 패턴이 있는가?

> 💡 **해설**
>
> **Q1.** `DelegatingFilterProxy`는 `initFilterBean()`이 호출될 때 `findWebApplicationContext()`가 `null`을 반환하면 지연 초기화를 수행합니다. 이는 Servlet Container가 Filter를 초기화하는 시점에 Spring ApplicationContext가 아직 생성되지 않았을 때 발생합니다. 일반적인 Spring Boot 환경에서는 ApplicationContext가 Servlet Container보다 먼저 완전히 초기화되므로 지연 초기화가 발생하지 않습니다. 문제가 될 수 있는 시나리오는 ApplicationContext 초기화 중에 에러가 발생했음에도 Servlet Container가 구동된 경우로, 이때 첫 요청 시 `IllegalStateException`이 발생합니다.
>
> **Q2.** `webSecurity.ignoring()`으로 설정한 경로는 `FilterChainProxy` 내부에서 `getFilters()` 호출 시 빈 Filter 목록을 가진 `SecurityFilterChain`으로 매칭됩니다. Filter 목록이 비어 있으므로 `VirtualFilterChain`을 거치지 않고 즉시 `originalChain.doFilter()`로 진행합니다. `permitAll()`과의 차이는 `SecurityContext` 초기화 여부입니다. `ignoring()`은 `SecurityContextHolderFilter`조차 실행되지 않으므로 `SecurityContextHolder`에 아무것도 없는 상태로 요청이 도달합니다. 반면 `permitAll()`은 모든 Security Filter를 거치되 최종 `AuthorizationFilter`에서 통과시키므로 `SecurityContext`가 초기화됩니다. 따라서 정적 리소스 외에는 `ignoring()` 사용을 지양해야 합니다.
>
> **Q3.** `@Order` 값이 낮은(우선순위가 높은) 체인이 실행됩니다. `getFilters()`는 `this.filterChains` 목록을 앞에서부터 순회하고, 이 목록은 `@Order` 기준으로 정렬되어 있기 때문입니다. 이를 의도적으로 활용하는 패턴으로는 특정 클라이언트(`/api/v2/**`)에 더 엄격한 보안 정책을 적용하는 체인을 높은 우선순위로 등록하고, 나머지 경로는 기본 체인이 처리하도록 구성하는 것이 있습니다. 이때 범위가 좁은 체인일수록 높은 우선순위(`@Order` 값 낮게)를 부여해야 의도대로 동작합니다.

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: SecurityFilterChain 구성과 우선순위 ➡️](./02-security-filter-chain.md)**

</div>
