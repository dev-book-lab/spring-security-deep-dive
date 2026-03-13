# AuthenticationManager vs ProviderManager — 인증 위임 계층 구조

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `AuthenticationManager`가 인터페이스인 이유는 무엇이며, `ProviderManager`와의 관계는?
- `ProviderManager`가 부모 `AuthenticationManager`에게 위임하는 조건은 무엇인가?
- 전역(Global) `AuthenticationManager`와 로컬(Local) `AuthenticationManager`를 분리하는 이유는?
- `HttpSecurity`마다 별도의 `AuthenticationManager`를 가질 수 있는가?
- `authenticationManager()` Bean을 직접 정의할 때와 `AuthenticationManagerBuilder`를 사용할 때의 차이는?
- `ProviderNotFoundException`은 언제 발생하며 어떻게 방지하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 인증 방식이 여러 개일 때 각 Filter가 직접 검증 로직을 갖는 것은 위험하다

```
나쁜 설계: 각 Filter가 직접 인증 처리
  UsernamePasswordAuthenticationFilter
    → DB 조회, 비밀번호 검증, 권한 로드 — 모두 Filter 내부에 구현
  JwtAuthenticationFilter
    → 토큰 파싱, 서명 검증, 사용자 조회 — 모두 Filter 내부에 구현
  BasicAuthenticationFilter
    → Base64 디코딩, DB 조회, 검증 — 모두 Filter 내부에 구현

  문제:
  → 인증 로직이 Filter마다 중복
  → 새 인증 방식 추가 = 새 Filter 전체 작성
  → 인증 로직만 단위 테스트하기 어려움

좋은 설계: Filter는 AuthenticationManager에게 위임
  UsernamePasswordAuthenticationFilter
    → new UsernamePasswordAuthenticationToken(username, password) 생성
    → authenticationManager.authenticate(token) 위임
  JwtAuthenticationFilter
    → new JwtAuthenticationToken(jwtString) 생성
    → authenticationManager.authenticate(token) 위임

  AuthenticationManager (ProviderManager)
    → 등록된 Provider 중 이 토큰을 처리할 수 있는 것 선택
    → 실제 검증 수행 → 인증된 Authentication 반환

  → Filter: 요청에서 자격증명 추출만 담당
  → AuthenticationProvider: 실제 검증 담당
  → 관심사 명확히 분리
```

---

## 😱 흔한 보안 실수

### Before: AuthenticationManager를 여러 곳에서 중복 정의

```java
// ❌ 문제: @Bean으로 AuthenticationManager를 정의하면서
//   HttpSecurity의 기본 AuthenticationManager와 충돌

@Bean
public AuthenticationManager authenticationManager() throws Exception {
    // 이렇게 정의하면 HttpSecurity가 내부적으로 생성하는
    // AuthenticationManager와 별개의 인스턴스가 됨
    // → JwtFilter에서 이 Bean을 주입받아 사용하면
    //   HttpSecurity의 UserDetailsService 설정이 적용되지 않을 수 있음
    return new ProviderManager(new DaoAuthenticationProvider());
}

// ✅ 올바른 방법: HttpSecurity의 AuthenticationManager를 재사용
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .userDetailsService(customUserDetailsService)
        .authenticationProvider(customProvider);

    AuthenticationManager authManager = http.getSharedObject(AuthenticationManager.class);
    // 또는:
    // AuthenticationManager authManager =
    //   http.getSharedObject(AuthenticationManagerBuilder.class).build();

    JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(authManager);
    http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
}
```

### Before: ProviderNotFoundException이 발생해도 원인을 모름

```java
// ❌ 증상: "No AuthenticationProvider found for class X" 예외

// 원인: authenticate() 메서드에 전달한 Authentication 타입을
//       supports()로 처리할 수 있는 Provider가 없음

// 흔한 시나리오:
// 커스텀 SmsAuthenticationToken을 만들었지만
// SmsAuthenticationProvider를 AuthenticationManager에 등록하지 않은 경우

// ✅ 디버깅 방법:
// 1. 어떤 Provider가 등록되어 있는지 확인
@Autowired
AuthenticationManager authenticationManager;

public void debugProviders() {
    if (authenticationManager instanceof ProviderManager pm) {
        pm.getProviders().forEach(p ->
            System.out.println("Provider: " + p.getClass().getSimpleName()));
    }
}

// 2. supports() 메서드가 올바르게 구현됐는지 확인
// SmsAuthenticationProvider.supports()가 SmsAuthenticationToken.class를
// 반환하는지 검증
```

---

## ✨ 올바른 보안 구현

### 전역 AuthenticationManager와 로컬 AuthenticationManager 분리

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // ── 전역 AuthenticationManager ────────────────────────────────────
    // AuthenticationConfiguration에서 자동 생성되는 전역 AM
    // UserDetailsService Bean과 PasswordEncoder Bean이 있으면 자동 연결
    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public AuthenticationManager globalAuthenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // ── 로컬 AuthenticationManager (SecurityFilterChain별) ──────────
    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {

        // HttpSecurity 내부 AuthenticationManagerBuilder를 이용한 로컬 AM 구성
        AuthenticationManagerBuilder localBuilder =
            http.getSharedObject(AuthenticationManagerBuilder.class);

        localBuilder
            .authenticationProvider(jwtAuthenticationProvider())
            .authenticationProvider(apiKeyAuthenticationProvider());

        // 로컬 AuthenticationManager: JWT + API Key 전용
        // 전역 AM을 부모로 자동 연결 (fallback)
        AuthenticationManager localManager = localBuilder.build();

        JwtAuthenticationFilter jwtFilter =
            new JwtAuthenticationFilter(localManager);

        http
            .securityMatcher("/api/**")
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

        return http.build();
    }

    @Bean
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        // 웹 체인은 전역 AM 사용 (DaoAuthenticationProvider 기본 포함)
        http
            .formLogin(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. AuthenticationManager 인터페이스

```java
// AuthenticationManager.java
// 단 하나의 메서드만 정의 — 인증 책임의 단일 진입점
public interface AuthenticationManager {

    /**
     * @param authentication 인증 요청 (isAuthenticated=false)
     * @return 인증 완료된 Authentication (isAuthenticated=true)
     * @throws AuthenticationException 인증 실패 시
     *   - BadCredentialsException: 자격증명 불일치
     *   - DisabledException: 계정 비활성화
     *   - LockedException: 계정 잠금
     *   - AccountExpiredException: 계정 만료
     *   - CredentialsExpiredException: 비밀번호 만료
     */
    Authentication authenticate(Authentication authentication)
            throws AuthenticationException;
}
```

### 2. ProviderManager — AuthenticationManager의 핵심 구현체

```java
// ProviderManager.java
public class ProviderManager implements AuthenticationManager,
        MessageSourceAware, InitializingBean {

    // 등록된 AuthenticationProvider 목록
    private List<AuthenticationProvider> providers = Collections.emptyList();

    // 부모 AuthenticationManager (모든 Provider가 실패했을 때 fallback)
    @Nullable
    private AuthenticationManager parent;

    // 인증 성공 후 credentials 자동 제거 여부 (기본: true)
    private boolean eraseCredentialsAfterAuthentication = true;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        Class<? extends Authentication> toTest = authentication.getClass();
        AuthenticationException lastException = null;
        Authentication result = null;

        // ① 등록된 Provider를 순서대로 순회
        for (AuthenticationProvider provider : getProviders()) {

            // ② 이 Provider가 해당 Authentication 타입을 처리할 수 있는가?
            if (!provider.supports(toTest)) {
                continue; // supports()=false → 다음 Provider로
            }

            try {
                // ③ 처리 가능한 Provider에게 인증 위임
                result = provider.authenticate(authentication);

                if (result != null) {
                    // ④ 인증 성공 → 요청 details를 결과에 복사
                    copyDetails(authentication, result);
                    break;
                }
            } catch (AccountStatusException | InternalAuthenticationServiceException ex) {
                // 계정 상태 예외는 부모 위임 없이 즉시 전파
                throw ex;
            } catch (AuthenticationException ex) {
                lastException = ex;
            }
        }

        // ⑤ 모든 Provider가 실패했을 때 부모 AuthenticationManager에 위임
        if (result == null && this.parent != null) {
            try {
                parentResult = this.parent.authenticate(authentication);
                result = parentResult;
            } catch (AuthenticationException ex) {
                lastException = ex;
            }
        }

        if (result == null) {
            // 처리 가능한 Provider가 없으면 ProviderNotFoundException
            if (lastException == null) {
                lastException = new ProviderNotFoundException(
                    "No AuthenticationProvider found for " + toTest.getName());
            }
            throw lastException;
        }

        // ⑥ 인증 성공 후 credentials 제거 (보안)
        if (eraseCredentialsAfterAuthentication && result instanceof CredentialsContainer) {
            ((CredentialsContainer) result).eraseCredentials();
        }

        // ⑦ 인증 성공 이벤트 발행
        if (parentResult == null) {
            this.eventPublisher.publishAuthenticationSuccess(result);
        }

        return result;
    }
}
```

### 3. 부모 ProviderManager 위임 — 계층 구조 전체 흐름

```
요청: POST /api/users (JWT Bearer Token)

로컬 ProviderManager (API 체인 전용)
  providers: [JwtAuthenticationProvider, ApiKeyAuthenticationProvider]
  │
  ├─ JwtAuthenticationProvider.supports(UsernamePasswordAuthenticationToken)?
  │    → false (JWT 토큰 타입 아님)
  ├─ ApiKeyAuthenticationProvider.supports(UsernamePasswordAuthenticationToken)?
  │    → false
  │
  └─ 모든 로컬 Provider 실패 → 부모에게 위임
       │
       ▼
전역 ProviderManager (부모)
  providers: [DaoAuthenticationProvider, AnonymousAuthenticationProvider]
  │
  ├─ DaoAuthenticationProvider.supports(UsernamePasswordAuthenticationToken)?
  │    → true!
  │    → loadUserByUsername() → DB 조회 → 검증
  │    → 인증 성공 반환
  └─ 결과: 로컬 → 부모 위임으로 인증 완료


요청: POST /login (폼 로그인)

로컬 ProviderManager 없음 → 전역 ProviderManager 직접 호출
  providers: [DaoAuthenticationProvider]
  → DaoAuthenticationProvider.supports(UPAT) → true
  → 인증 성공
```

### 4. AuthenticationManagerBuilder — 선언적 AM 구성

```java
// AuthenticationManagerBuilder.java
// AuthenticationManager를 DSL 방식으로 구성하는 빌더
public class AuthenticationManagerBuilder
        extends AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder>
        implements ProviderManagerBuilder<AuthenticationManagerBuilder> {

    // 직접 Provider 추가
    public AuthenticationManagerBuilder authenticationProvider(
            AuthenticationProvider authenticationProvider) {
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    // UserDetailsService + PasswordEncoder로 DaoAuthenticationProvider 자동 생성
    public DaoAuthenticationConfigurer<AuthenticationManagerBuilder, UserDetailsService>
            userDetailsService(UserDetailsService userDetailsService) throws Exception {
        // 내부적으로 DaoAuthenticationProvider 생성 + 등록
        this.defaultUserDetailsService = userDetailsService;
        return apply(new DaoAuthenticationConfigurer<>(userDetailsService));
    }

    // build() 시 ProviderManager 인스턴스 생성
    @Override
    protected ProviderManager performBuild() throws Exception {
        ProviderManager providerManager =
            new ProviderManager(this.authenticationProviders, this.parentAuthenticationManager);
        providerManager.setEraseCredentialsAfterAuthentication(
            this.eraseCredentials);
        return providerManager;
    }
}
```

### 5. 전역 AuthenticationManager 자동 구성 과정

```java
// AuthenticationConfiguration.java (Spring Security 자동 구성)
@Configuration(proxyBeanMethods = false)
public class AuthenticationConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManagerBuilder authenticationManagerBuilder(
            ObjectPostProcessor<Object> objectPostProcessor,
            ApplicationContext context) {
        // ...
    }

    // 전역 AuthenticationManager — 개발자가 직접 @Bean으로 정의하지 않은 경우 자동 생성
    public AuthenticationManager getAuthenticationManager() throws Exception {
        if (this.authenticationManagerInitialized) {
            return this.authenticationManager;
        }
        AuthenticationManagerBuilder authBuilder = this.applicationContext
            .getBean(AuthenticationManagerBuilder.class);

        if (this.buildingAuthenticationManager.getAndSet(true)) {
            return new AuthenticationManagerDelegator(authBuilder);
        }

        // ApplicationContext에서 UserDetailsService Bean을 찾아 자동 연결
        for (GlobalAuthenticationConfigurerAdapter config : globalAuthConfigurers) {
            authBuilder.apply(config);
        }

        this.authenticationManager = authBuilder.build();
        this.authenticationManagerInitialized = true;
        return this.authenticationManager;
    }
}

// UserDetailsServiceAutoConfiguration (Spring Boot)
// → UserDetailsService Bean이 있으면 자동으로 전역 AM에 DaoAuthenticationProvider 등록
// → PasswordEncoder Bean이 있으면 DaoAuthenticationProvider에 자동 주입
```

### 6. 전체 구조 ASCII 다이어그램

```
Spring Boot 자동 구성:

  [전역 ProviderManager] (부모)
    providers:
    └── DaoAuthenticationProvider
          userDetailsService: CustomUserDetailsService (Bean)
          passwordEncoder:    BCryptPasswordEncoder (Bean)

  [로컬 ProviderManager] (자식, API 체인)
    providers:
    ├── JwtAuthenticationProvider
    └── ApiKeyAuthenticationProvider
    parent → [전역 ProviderManager]

  [로컬 ProviderManager] (자식, 웹 체인)
    providers:
    └── DaoAuthenticationProvider (별도 구성 없으면 전역 위임)
    parent → [전역 ProviderManager]

인증 요청 흐름:
  Filter → 로컬 PM → [Provider 순회] → 실패 시 → 전역 PM
                                        성공 시 → 인증 완료
```

---

## 💻 실험으로 확인하기

### 실험 1: 등록된 Provider 목록 확인

```java
@RestController
@RequiredArgsConstructor
public class AuthDebugController {

    private final AuthenticationManager authenticationManager;

    @GetMapping("/debug/providers")
    public List<String> providers() {
        if (authenticationManager instanceof ProviderManager pm) {
            List<String> result = new ArrayList<>();
            result.add("=== Local Providers ===");
            pm.getProviders().forEach(p ->
                result.add(p.getClass().getSimpleName()));

            AuthenticationManager parent = pm.getParent();
            if (parent instanceof ProviderManager parentPm) {
                result.add("=== Parent Providers ===");
                parentPm.getProviders().forEach(p ->
                    result.add(p.getClass().getSimpleName()));
            }
            return result;
        }
        return List.of("Not a ProviderManager: " +
            authenticationManager.getClass().getSimpleName());
    }
}
```

```bash
curl http://localhost:8080/debug/providers
# [
#   "=== Local Providers ===",
#   "JwtAuthenticationProvider",
#   "=== Parent Providers ===",
#   "DaoAuthenticationProvider"
# ]
```

### 실험 2: ProviderNotFoundException 재현

```java
// SmsAuthenticationToken을 지원하는 Provider를 등록하지 않은 상태에서 인증 시도
@PostMapping("/sms-login-test")
public String smsLoginTest(@RequestParam String phone) {
    try {
        Authentication result = authenticationManager.authenticate(
            new SmsAuthenticationToken(phone, "123456") // OTP
        );
        return "Success: " + result.getName();
    } catch (ProviderNotFoundException e) {
        return "ProviderNotFoundException: " + e.getMessage();
        // "No AuthenticationProvider found for SmsAuthenticationToken"
    }
}
```

### 실험 3: DEBUG 로그로 Provider 선택 과정 확인

```yaml
logging:
  level:
    org.springframework.security.authentication.ProviderManager: DEBUG
```

```
# POST /login 요청 시 로그:
DEBUG ProviderManager - Authentication attempt using DaoAuthenticationProvider
DEBUG ProviderManager - Authentication attempt was successful

# 지원하는 Provider 없을 때 로그:
DEBUG ProviderManager - No AuthenticationProvider found for ...
DEBUG ProviderManager - Delegating to parent AuthenticationManager
```

---

## 🔒 보안 체크리스트

```
AuthenticationManager 구성
  ☐ SecurityFilterChain마다 별도 로컬 AM이 필요한지 검토
  ☐ 전역 AM의 Provider 목록이 의도한 대로 구성됐는지 확인
  ☐ eraseCredentialsAfterAuthentication=true (기본값) 유지

Provider 등록 누락 방지
  ☐ 커스텀 Authentication 타입마다 대응하는 Provider 등록 확인
  ☐ Provider의 supports() 메서드가 올바른 타입을 반환하는지 테스트

부모-자식 AM 설계
  ☐ 로컬 AM이 전역 AM에 부모로 연결되는지 확인
  ☐ 로컬 AM에서 처리 못 한 요청이 전역 AM으로 올바르게 위임되는지 확인
```

---

## 🤔 트레이드오프

```
단일 전역 AuthenticationManager:
  장점  구성 단순, Provider 중복 없음
  단점  모든 인증 방식의 Provider가 한 곳에 집중 → 관리 복잡
        체인별로 다른 인증 전략 적용 어려움

SecurityFilterChain별 로컬 AuthenticationManager:
  장점  체인마다 독립된 인증 전략 (API: JWT, Web: FormLogin)
        Provider 수가 최소화 → supports() 순회 비용 감소
  단점  공통 Provider가 여러 AM에 중복 등록 가능
        → 부모 AM 공유로 해결

AuthenticationManagerBuilder vs 직접 ProviderManager 생성:
  AuthenticationManagerBuilder 사용:
    장점  DaoAuthenticationProvider 자동 구성, 이벤트 발행 자동 설정
  직접 생성:
    장점  완전한 제어권
    단점  이벤트 발행, credentials erase 등 수동 설정 필요
```

---

## 📌 핵심 정리

```
AuthenticationManager = 인증의 단일 진입점 인터페이스
  authenticate(Authentication) 한 메서드만 정의
  Filter는 이 인터페이스만 알면 됨 → 구현체 교체 가능

ProviderManager = AuthenticationManager의 표준 구현체
  등록된 Provider를 순서대로 순회 → supports() 확인 → 처리 위임
  모든 Provider 실패 시 → 부모 AM에 위임
  모든 Provider + 부모 실패 시 → ProviderNotFoundException

부모-자식 계층 구조
  로컬 PM (SecurityFilterChain별) → 전역 PM (부모, fallback)
  → 로컬에서 처리 못한 인증 타입을 전역에서 처리

eraseCredentialsAfterAuthentication=true
  인증 성공 후 자동으로 credentials(비밀번호) null 처리
  기본값 유지 필수
```

---

## 🤔 생각해볼 문제

**Q1.** `ProviderManager`가 `AccountStatusException`과 `InternalAuthenticationServiceException`은 부모에게 위임하지 않고 즉시 throw하도록 설계된 이유는 무엇인가?

**Q2.** 같은 `Authentication` 타입을 처리할 수 있는 `AuthenticationProvider`가 두 개 등록되어 있을 때, 두 번째 Provider는 언제 실행되는가?

**Q3.** `AuthenticationManagerDelegator`는 무엇이며, `getAuthenticationManager()`에서 순환 참조를 방지하기 위해 어떻게 사용되는가?

> 💡 **해설**
>
> **Q1.** `AccountStatusException`(계정 비활성화, 잠금, 만료 등)은 자격증명 자체가 아닌 계정 상태의 문제입니다. 부모 AM에 위임해도 동일한 계정을 다른 방식으로 인증할 수 없으므로 즉시 예외를 전파합니다. `InternalAuthenticationServiceException`은 DB 연결 실패 등 서버 내부 오류로, 부모 위임으로 해결될 수 없습니다. 두 예외 모두 "다른 Provider가 처리할 수 있을 가능성"이 없으므로 빠른 실패(fail-fast)가 올바른 전략입니다.
>
> **Q2.** 첫 번째 Provider가 `null`을 반환하는 경우에만 두 번째 Provider가 시도됩니다. 첫 번째 Provider가 `AuthenticationException`을 throw하면 `lastException`에 저장하고 다음 Provider를 시도합니다. 단, 첫 번째 Provider가 `AccountStatusException`을 throw하면 즉시 중단됩니다. 동일 타입을 처리하는 두 Provider 중 하나만 사용하려면 등록 순서를 조정하거나 `supports()` 조건을 더 세밀하게 구분해야 합니다.
>
> **Q3.** `AuthenticationManagerDelegator`는 `AuthenticationConfiguration.getAuthenticationManager()`에서 순환 참조를 방지하는 프록시입니다. `getAuthenticationManager()`가 `AuthenticationManagerBuilder`를 통해 AM을 빌드하는 과정에서, 빌드 중인 AM을 참조하는 Bean이 있으면 무한 루프가 발생할 수 있습니다. `buildingAuthenticationManager` 플래그가 `true`일 때 `AuthenticationManagerDelegator`를 반환하면, 실제 AM이 완전히 초기화된 후에 `authenticate()`가 호출되는 시점에 진짜 AM으로 위임합니다.

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: AuthenticationProvider 체인 동작 ➡️](./02-authentication-provider-chain.md)**

</div>
