# SecurityFilterChain 구성과 우선순위 — @Order와 RequestMatcher로 요청을 체인에 배분하는 방식

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `SecurityFilterChain`이 여러 개 등록될 때 `FilterChainProxy`는 어떤 기준으로 하나를 선택하는가?
- `@Order` 값과 `securityMatcher()`는 각각 어떤 역할을 하며 함께 사용할 때 어떻게 상호작용하는가?
- `HttpSecurity`는 어떻게 `SecurityFilterChain` 인스턴스로 변환되는가?
- API 서버와 웹 폼 로그인을 하나의 애플리케이션에서 분리하려면 어떻게 구성해야 하는가?
- `securityMatcher()` 없이 `SecurityFilterChain`을 여러 개 등록하면 어떤 문제가 생기는가?
- Spring Boot의 기본 `SecurityFilterChain`을 부분적으로만 덮어쓸 수 있는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 하나의 애플리케이션에서 서로 다른 인증 정책이 필요하다

```
실제 서비스에서 자주 등장하는 시나리오:

  /api/**        → JWT Bearer 인증, 세션 없음, JSON 응답
  /admin/**      → 별도 관리자 전용 인증, IP 제한, 엄격한 권한 검사
  /public/**     → 인증 불필요
  그 외 경로      → 폼 로그인, 세션 기반 인증

단일 SecurityFilterChain으로 처리하면:
  formLogin()과 oauth2ResourceServer()를 동시에 설정
  → 모든 요청에 불필요한 Filter가 실행됨
  → 경로별로 예외 처리를 분기해야 해서 코드가 복잡해짐
  → 인증 실패 시 JSON vs HTML 응답을 하나의 체인에서 구분해야 함

해결: SecurityFilterChain 분리
  각 체인이 자신이 담당할 URL 패턴을 선언 (securityMatcher)
  각 체인이 독립적인 Filter 구성을 가짐
  → 관심사 분리, 각 체인은 자신의 영역에만 집중
```

---

## 😱 흔한 보안 실수

### Before: securityMatcher() 없이 여러 SecurityFilterChain을 등록

```java
// ❌ 문제: 두 번째 체인은 절대 실행되지 않는다
@Bean
@Order(1)
public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    // securityMatcher()가 없으면 모든 요청에 매칭됨
    http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .httpBasic(Customizer.withDefaults());
    return http.build();
}

@Bean
@Order(2)
public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
    // @Order(1) 체인이 모든 요청을 가로채므로 이 체인은 도달 불가
    http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .formLogin(Customizer.withDefaults());
    return http.build();
}

// ✅ 해결: 범위를 좁게 선언하는 체인에 securityMatcher() 추가
@Bean
@Order(1)
public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/**")  // /api/**에만 이 체인 적용
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .httpBasic(Customizer.withDefaults());
    return http.build();
}

@Bean
@Order(2)
public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
    // securityMatcher() 없음 → /api/** 외 나머지 모든 요청 처리
    http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .formLogin(Customizer.withDefaults());
    return http.build();
}
```

### Before: @Order를 생략하면 순서가 보장된다고 착각

```java
// ❌ 잘못된 이해
// "Bean 정의 순서대로 SecurityFilterChain이 실행된다"

@Bean
public SecurityFilterChain adminChain(HttpSecurity http) { ... }  // 먼저 정의

@Bean
public SecurityFilterChain defaultChain(HttpSecurity http) { ... } // 나중 정의

// ✅ 실제:
// @Order 없으면 스프링의 기본 정렬 기준 사용
// → Bean 이름, 정의 순서 등에 따라 비결정적 동작
// → 환경에 따라 체인 순서가 바뀔 수 있음
// 반드시 @Order를 명시적으로 지정할 것
```

---

## ✨ 올바른 보안 구현

### After: API ↔ Web 이중 SecurityFilterChain 구성

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // ── Chain 1: REST API (JWT, Stateless) ──────────────────────────
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtFilter) throws Exception {

        http
            .securityMatcher("/api/**")           // /api/**만 담당
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable())         // Stateless → CSRF 불필요
            .addFilterBefore(jwtFilter,
                UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                // 인증 실패 → 401 JSON 응답 (redirect 없음)
            );

        return http.build();
    }

    // ── Chain 2: 웹 (세션 기반 폼 로그인) ──────────────────────────
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {

        http
            // securityMatcher() 없음 → /api/** 외 나머지 전담
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/css/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout")
            );

        return http.build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. HttpSecurity → SecurityFilterChain 변환 과정

```java
// HttpSecurity.java
// HttpSecurity는 SecurityFilterChain의 빌더(Builder)
// 각 configurers (formLogin, sessionManagement 등)가
// 자신의 Filter를 HttpSecurity의 내부 Filter 목록에 추가

public final class HttpSecurity
        extends AbstractRequestMatcherRegistry<HttpSecurity>
        implements SecurityBuilder<DefaultSecurityFilterChain> {

    // 내부에 쌓이는 Filter 목록
    private List<OrderedFilter> filters = new ArrayList<>();
    // 이 체인이 담당할 URL 범위
    private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

    // securityMatcher("/api/**") 호출 시
    @Override
    public HttpSecurity requestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    // http.build() 호출 시 최종적으로 DefaultSecurityFilterChain 생성
    @Override
    protected DefaultSecurityFilterChain performBuild() {
        this.filters.sort(InsertionSortFilters.COMPARATOR);
        // 순서대로 정렬된 Filter 목록과 RequestMatcher로 체인 생성
        return new DefaultSecurityFilterChain(this.requestMatcher,
                                              this.filters.stream()
                                                          .map(f -> f.filter)
                                                          .collect(Collectors.toList()));
    }
}
```

### 2. DefaultSecurityFilterChain — SecurityFilterChain의 기본 구현

```java
// DefaultSecurityFilterChain.java
public final class DefaultSecurityFilterChain implements SecurityFilterChain {

    private final RequestMatcher requestMatcher;
    private final List<Filter> filters;

    public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
        if (filters.isEmpty()) {
            logger.info("...");
        } else {
            logger.info("Will secure {} with {}", requestMatcher, filters);
        }
        this.requestMatcher = requestMatcher;
        this.filters = new ArrayList<>(filters);
    }

    // FilterChainProxy.getFilters()에서 호출
    // → 이 체인이 현재 요청을 담당해야 하는가?
    @Override
    public boolean matches(HttpServletRequest request) {
        return this.requestMatcher.matches(request);
    }

    @Override
    public List<Filter> getFilters() {
        return this.filters;
    }
}
```

### 3. 체인 선택 흐름 상세 추적

```java
// FilterChainProxy.doFilterInternal()에서 체인 선택
private List<Filter> getFilters(HttpServletRequest request) {
    for (SecurityFilterChain chain : this.filterChains) {
        // matches() → RequestMatcher가 현재 URL·메서드·헤더 등을 검사
        if (chain.matches(request)) {
            return chain.getFilters(); // 첫 번째 매칭 체인의 Filter 목록만 반환
        }
    }
    return null; // 매칭 체인 없음 → 보안 처리 없이 통과
}

// filterChains 목록의 정렬 기준:
// WebSecurity.performBuild()에서 OrderComparator.sort(securityFilterChainBuilders)
// → @Order 값 기준 오름차순 (낮을수록 먼저)
// → @Order(1) 체인이 @Order(2) 체인보다 먼저 시도됨
```

### 4. RequestMatcher 종류와 선택 기준

```java
// securityMatcher()에 전달할 수 있는 RequestMatcher 구현체들

// 1. AntPathRequestMatcher — Ant 패턴 기반
http.securityMatcher("/api/**");
// 내부: new AntPathRequestMatcher("/api/**")
// /api/users ✓   /api/users/1 ✓   /other ✗

// 2. 여러 패턴 동시 지정
http.securityMatcher("/api/**", "/v2/**");
// 내부: new OrRequestMatcher(List.of(new AntPathRequestMatcher("/api/**"), ...))

// 3. MvcRequestMatcher — Spring MVC의 PathPattern 사용 (더 정교)
http.securityMatcher(new MvcRequestMatcher.Builder(introspector)
    .pattern("/api/**"));

// 4. RequestHeaderRequestMatcher — 헤더 조건
http.securityMatcher(new RequestHeaderRequestMatcher("X-API-KEY", "secret"));
// X-API-KEY: secret 헤더가 있는 요청만 이 체인 담당

// 5. 람다 기반 커스텀 매처
http.securityMatcher(request ->
    "application/json".equals(request.getHeader("Accept")));
// Accept: application/json 요청만 담당
```

### 5. 체인 구성 전체 ASCII 흐름

```
HTTP 요청: GET /api/users
                │
                ▼
        FilterChainProxy
        filterChains 목록 (Order 순서):
        ┌──────────────────────────────────────────────┐
        │  Chain 1 (@Order=1)                          │
        │  RequestMatcher: AntPath("/api/**")          │
        │  matches("/api/users") → true ✓              │
        │  ┌──────────────────────────────────────┐    │
        │  │ SecurityContextHolderFilter          │    │
        │  │ CsrfFilter (disabled)                │    │
        │  │ JwtAuthenticationFilter              │    │
        │  │ ExceptionTranslationFilter           │    │
        │  │ AuthorizationFilter                  │    │
        │  └──────────────────────────────────────┘    │
        │  → 이 체인 실행, Chain 2는 시도하지 않음            │
        └──────────────────────────────────────────────┘
        ┌──────────────────────────────────────────────┐
        │  Chain 2 (@Order=2)                          │
        │  RequestMatcher: AnyRequest                  │
        │  ← /api/**에 해당하므로 여기까지 오지 않음           │
        └──────────────────────────────────────────────┘

HTTP 요청: GET /dashboard
                │
                ▼
        FilterChainProxy
        ┌──────────────────────────────────────────────┐
        │  Chain 1 (@Order=1)                          │
        │  matches("/dashboard") → false ✗             │
        └──────────────────────────────────────────────┘
        ┌──────────────────────────────────────────────┐
        │  Chain 2 (@Order=2)                          │
        │  matches("/dashboard") → true ✓              │
        │  ┌──────────────────────────────────────┐    │
        │  │ SecurityContextHolderFilter          │    │
        │  │ CsrfFilter                           │    │
        │  │ UsernamePasswordAuthenticationFilter │    │
        │  │ SessionManagementFilter              │    │
        │  │ ExceptionTranslationFilter           │    │
        │  │ AuthorizationFilter                  │    │
        │  └──────────────────────────────────────┘    │
        │  → 이 체인 실행                                 │
        └──────────────────────────────────────────────┘
```

### 6. Spring Boot 기본 SecurityFilterChain의 @Order

```java
// SpringBootWebSecurityConfiguration.java
// Spring Boot가 SecurityFilterChain Bean이 없을 때 제공하는 기본 체인
@ConditionalOnDefaultWebSecurity
@Bean
@Order(SecurityProperties.BASIC_AUTH_ORDER) // = Integer.MAX_VALUE - 5
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
    http.formLogin(withDefaults());
    http.httpBasic(withDefaults());
    return http.build();
}

// 개발자가 직접 SecurityFilterChain을 등록하면:
// @ConditionalOnDefaultWebSecurity → @ConditionalOnMissingBean(SecurityFilterChain.class)
// → 기본 체인이 등록되지 않음
// → 개발자의 체인만 동작

// Integer.MAX_VALUE - 5 = 2147483642
// 개발자가 @Order(1)이나 @Order(100)을 사용하면 항상 기본 체인보다 우선순위가 높음
```

---

## 💻 실험으로 확인하기

### 실험 1: 체인 매칭 과정 TRACE 로그로 확인

```yaml
logging:
  level:
    org.springframework.security.web.FilterChainProxy: TRACE
    org.springframework.security: DEBUG
```

```bash
# API 요청
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/users

# 예상 로그:
# TRACE FilterChainProxy - Trying to match request against
#       DefaultSecurityFilterChain [RequestMatcher=Ant [pattern='/api/**']] (1/2)
# TRACE FilterChainProxy - Securing GET /api/users

# 웹 요청
curl http://localhost:8080/dashboard

# 예상 로그:
# TRACE FilterChainProxy - Trying to match request against
#       DefaultSecurityFilterChain [RequestMatcher=Ant [pattern='/api/**']] (1/2)
# TRACE FilterChainProxy - Trying to match request against
#       DefaultSecurityFilterChain [RequestMatcher=any request] (2/2)
# TRACE FilterChainProxy - Securing GET /dashboard
```

### 실험 2: 각 체인의 Filter 목록 비교

```java
@RestController
@RequiredArgsConstructor
public class SecurityDebugController {

    private final ApplicationContext ctx;

    @GetMapping("/debug/chains")
    public Map<String, List<String>> chains() {
        FilterChainProxy proxy = (FilterChainProxy)
            ctx.getBean("springSecurityFilterChain");

        Map<String, List<String>> result = new LinkedHashMap<>();
        int i = 1;
        for (SecurityFilterChain chain : proxy.getFilterChains()) {
            List<String> filterNames = chain.getFilters().stream()
                .map(f -> f.getClass().getSimpleName())
                .collect(Collectors.toList());
            result.put("Chain-" + i++, filterNames);
        }
        return result;
    }
}
```

```bash
curl http://localhost:8080/debug/chains | jq
# {
#   "Chain-1": [
#     "SecurityContextHolderFilter",
#     "JwtAuthenticationFilter",
#     "ExceptionTranslationFilter",
#     "AuthorizationFilter"
#   ],
#   "Chain-2": [
#     "SecurityContextHolderFilter",
#     "CsrfFilter",
#     "UsernamePasswordAuthenticationFilter",
#     "SessionManagementFilter",
#     "ExceptionTranslationFilter",
#     "AuthorizationFilter"
#   ]
# }
# → API 체인은 JWT 관련 Filter만, 웹 체인은 폼 로그인 관련 Filter 포함
```

### 실험 3: 잘못된 @Order로 인한 체인 우선순위 역전

```java
// @Order를 바꿔서 어떤 체인이 요청을 가로채는지 확인
@Bean
@Order(2) // API 체인 우선순위 낮춤
public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/**") ...
}

@Bean
@Order(1) // 웹 체인 우선순위 높임 + securityMatcher 없음
public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
    // securityMatcher 없음 → 모든 요청에 매칭
    ...
}
```

```bash
curl http://localhost:8080/api/users
# → webChain(@Order=1)이 모든 요청을 가로채므로
#   apiChain은 절대 실행되지 않음
# → formLogin 리다이렉트 발생 (예상치 못한 동작)
```

---

## 🔒 보안 체크리스트

```
SecurityFilterChain 구성
  ☐ 범위를 제한하는 모든 체인에 securityMatcher() 명시
  ☐ @Order를 모든 체인에 명시적으로 지정
  ☐ 범위가 좁은 체인일수록 낮은 @Order 값 (높은 우선순위)
  ☐ "catch-all" 체인(securityMatcher 없는)은 가장 높은 @Order 값

중복 범위 방지
  ☐ 두 체인의 securityMatcher가 겹치지 않는지 확인
  ☐ 겹치는 경우 의도한 체인이 낮은 @Order(높은 우선순위)인지 확인

인증 방식별 분리
  ☐ Stateless(JWT) 체인: SessionCreationPolicy.STATELESS, CSRF 비활성화
  ☐ Stateful(세션) 체인: CSRF 활성화, 세션 고정 방어 설정
  ☐ 각 체인의 exceptionHandling: API는 JSON 응답, 웹은 redirect 응답
```

---

## 🤔 트레이드오프

```
SecurityFilterChain 분리:
  장점  인증 방식별 완전한 독립 구성 (Filter 목록, 세션 정책, 예외 처리 모두 다름)
        각 체인이 작고 명확해서 이해하기 쉬움
        특정 체인만 수정해도 다른 체인에 영향 없음
  단점  공통 설정(CORS, 헤더 등)을 각 체인에 중복 작성해야 함
        체인 수가 많아지면 @Order 관리 복잡
        → SecurityFilterChain 공통 베이스 추출로 해결 가능

단일 SecurityFilterChain:
  장점  설정이 한 곳에 집중 → 전체 보안 정책 파악 쉬움
        공통 설정 중복 없음
  단점  경로별 인증 방식 분기가 설정 내 조건문으로 처리됨
        Filter가 모든 요청에 실행되어 불필요한 처리 발생
        → 소규모 서비스나 단일 인증 방식에는 단일 체인이 충분히 적합
```

---

## 📌 핵심 정리

```
SecurityFilterChain 선택 규칙
  FilterChainProxy → @Order 오름차순으로 정렬된 체인 목록을 순서대로 시도
  → securityMatcher().matches()가 true인 첫 번째 체인만 실행
  → 나머지 체인은 해당 요청에 대해 실행되지 않음

securityMatcher() 없는 체인 = AnyRequestMatcher
  모든 요청에 매칭 → 반드시 가장 높은 @Order 값(낮은 우선순위)으로 설정
  → 범위 좁은 체인들이 먼저 선택된 후 남은 요청만 처리

@Order 권장 패턴
  1  → API 체인 (가장 좁은 범위)
  2  → 관리자 체인
  ..
  N  → 기본 웹 체인 (securityMatcher 없음, 가장 넓은 범위)

HttpSecurity.build() → DefaultSecurityFilterChain(requestMatcher, sortedFilters)
```

---

## 🤔 생각해볼 문제

**Q1.** `http.securityMatcher("/api/**")` 설정 후 `/api/`로 끝나는 요청(트레일링 슬래시)은 이 체인에 매칭되는가? Spring Boot 3.x에서 트레일링 슬래시 처리 방식이 변경된 것이 `securityMatcher`에도 영향을 주는가?

**Q2.** `FilterChainProxy`의 `filterChains` 목록이 `@Order` 기준으로 정렬된다고 했는데, 두 체인이 동일한 `@Order` 값을 가지면 어떻게 되는가? 이 상황에서 체인 순서는 결정론적인가?

**Q3.** `securityMatcher()`로 `/api/**`를 지정한 체인에 CORS 설정을 추가했는데, Preflight 요청(`OPTIONS /api/users`)이 이 체인의 인증 Filter를 통과하면서 `401`이 반환된다. 어떻게 해결해야 하며, CORS Preflight와 Security Filter 처리 순서의 관계는?

> 💡 **해설**
>
> **Q1.** `AntPathRequestMatcher("/api/**")`는 `/api/`(트레일링 슬래시)도 매칭합니다. `/**` 패턴은 하위 모든 경로를 포함하기 때문입니다. Spring Boot 3.x에서 MVC 컨트롤러의 트레일링 슬래시 매칭은 기본적으로 비활성화됐지만, `securityMatcher`의 `AntPathRequestMatcher`는 별개로 동작하므로 영향을 받지 않습니다. 단, `MvcRequestMatcher`를 `securityMatcher`에 사용하는 경우에는 MVC 설정의 영향을 받을 수 있습니다.
>
> **Q2.** 동일한 `@Order` 값은 `OrderComparator`가 0을 반환하므로 정렬 결과가 비결정적입니다. JVM 버전, Bean 등록 순서, 클래스로딩 순서에 따라 달라질 수 있습니다. 이는 보안상 위험한 상황으로, 환경에 따라 의도치 않은 체인이 먼저 실행될 수 있습니다. 반드시 모든 `SecurityFilterChain`에 고유한 `@Order` 값을 명시해야 합니다.
>
> **Q3.** Preflight `OPTIONS` 요청이 `401`을 받는 원인은 `CorsFilter`가 `JwtAuthenticationFilter`보다 뒤에 실행되거나, `CorsFilter`가 아예 Security Filter Chain에 포함되지 않기 때문입니다. 해결 방법은 `http.cors(Customizer.withDefaults())`를 Security 설정에 추가해 `CorsFilter`를 Security 체인 안에서 가장 먼저 실행되도록 하는 것입니다. `CorsFilter`는 Preflight 요청을 감지하면 인증 Filter에 도달하기 전에 CORS 응답 헤더를 추가하고 `chain.doFilter()`를 호출하지 않고 응답을 종료합니다.

---

<div align="center">

**[← 이전: DelegatingFilterProxy와 FilterChainProxy 관계](./01-delegating-filter-proxy.md)** | **[홈으로 🏠](../README.md)** | **[다음: Security Filter 15개 완전 정복 ➡️](./03-security-filters-order.md)**

</div>
