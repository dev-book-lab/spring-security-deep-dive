# Custom Authentication Provider 작성 — SMS OTP·API Key 인증 구현

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `AuthenticationProvider`를 직접 구현할 때 `supports()`를 어떻게 설계해야 하는가?
- 커스텀 `Authentication` 토큰을 만들 때 `AbstractAuthenticationToken`을 상속해야 하는 이유는?
- SMS OTP 인증 Provider를 구현할 때 보안상 주의할 점은 무엇인가?
- API Key 인증 Provider를 `ProviderManager`에 등록하는 방법은?
- 커스텀 Provider를 `AuthenticationManagerBuilder`에 등록하는 것과 `http.authenticationProvider()`에 등록하는 것의 차이는?
- 커스텀 Provider가 던지는 예외 타입이 클라이언트 응답에 어떻게 영향을 미치는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 기본 제공 Provider로는 충분하지 않은 인증 요구사항이 있다

```
기본 Provider로 처리할 수 없는 인증 방식:

  SMS OTP 인증:
    → 전화번호 + 6자리 일회용 비밀번호
    → UsernamePasswordAuthenticationToken으로 억지로 처리 가능하지만
      OTP의 만료, 단일 사용, 전화번호 검증 등 특수 로직 필요

  API Key 인증:
    → X-API-KEY: abc123 헤더
    → username/password 개념 자체가 없음
    → 키에 연결된 서비스 계정(Service Account) 처리 필요

  인증서 기반 인증 (커스텀):
    → 특정 포맷의 인증서 파싱 및 검증
    → 내부 CA에서 발급한 인증서만 허용

  멀티팩터 인증 (MFA):
    → 1단계: username/password
    → 2단계: TOTP 또는 SMS OTP
    → 각 단계를 별도 Provider로 분리

해결: AuthenticationProvider 직접 구현
  → 커스텀 Authentication 토큰 타입 정의
  → supports()로 이 토큰만 처리
  → ProviderManager에 등록
```

---

## 😱 흔한 보안 실수

### Before: OTP를 검증하면서 타이밍 공격 방어를 누락

```java
// ❌ 취약: 단순 문자열 비교 → 타이밍 공격 가능
@Override
public Authentication authenticate(Authentication authentication) {
    SmsOtpAuthenticationToken token = (SmsOtpAuthenticationToken) authentication;
    String storedOtp = otpStore.get(token.getPhone());

    if (token.getOtp().equals(storedOtp)) { // 타이밍 공격 취약!
        // 빠른 실패 vs 느린 실패로 OTP 유추 가능
        return createAuthenticatedToken(token);
    }
    throw new BadCredentialsException("Invalid OTP");
}

// ✅ 안전: 일정 시간 비교 (MessageDigest.isEqual 활용)
import java.security.MessageDigest;

@Override
public Authentication authenticate(Authentication authentication) {
    SmsOtpAuthenticationToken token = (SmsOtpAuthenticationToken) authentication;
    String storedOtp = otpStore.get(token.getPhone());

    if (storedOtp == null) {
        throw new BadCredentialsException("OTP not found or expired");
    }

    // 상수 시간 비교 → 타이밍으로 OTP 추측 불가
    boolean matches = MessageDigest.isEqual(
        token.getOtp().getBytes(StandardCharsets.UTF_8),
        storedOtp.getBytes(StandardCharsets.UTF_8)
    );

    if (!matches) {
        otpStore.incrementFailureCount(token.getPhone()); // 실패 횟수 추적
        throw new BadCredentialsException("Invalid OTP");
    }

    otpStore.invalidate(token.getPhone()); // 사용 후 즉시 삭제 (단일 사용)
    return createAuthenticatedToken(token);
}
```

### Before: supports()가 너무 넓어 의도치 않은 토큰을 처리

```java
// ❌ 위험: 모든 Authentication 처리
@Override
public boolean supports(Class<?> authentication) {
    return Authentication.class.isAssignableFrom(authentication);
    // → 모든 토큰 타입이 이 Provider로 들어옴
}

// ✅ 정확한 타입만 처리
@Override
public boolean supports(Class<?> authentication) {
    return SmsOtpAuthenticationToken.class.isAssignableFrom(authentication);
    // SmsOtpAuthenticationToken과 그 하위 타입만
}
```

---

## ✨ 올바른 보안 구현

### 패턴 1: SMS OTP 인증 전체 구현

```java
// ── Step 1: 커스텀 Authentication 토큰 ─────────────────────────────
public class SmsOtpAuthenticationToken extends AbstractAuthenticationToken {

    private final String phone;  // principal 역할
    private String otp;          // credentials 역할

    // 인증 전 (OTP 검증 요청용)
    public SmsOtpAuthenticationToken(String phone, String otp) {
        super(null);
        this.phone = phone;
        this.otp = otp;
        setAuthenticated(false);
    }

    // 인증 후 (검증 완료된 토큰)
    public SmsOtpAuthenticationToken(String phone,
                                      Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.phone = phone;
        this.otp = null; // 인증 후 OTP 제거
        super.setAuthenticated(true);
    }

    @Override public Object getPrincipal() { return this.phone; }
    @Override public Object getCredentials() { return this.otp; }

    @Override
    public void setAuthenticated(boolean authenticated) {
        Assert.isTrue(!authenticated,
            "Cannot set this token to trusted; use constructor with authorities");
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.otp = null; // OTP 메모리에서 제거
    }
}

// ── Step 2: AuthenticationProvider 구현 ────────────────────────────
@Component
@RequiredArgsConstructor
public class SmsOtpAuthenticationProvider implements AuthenticationProvider {

    private final OtpStore otpStore;
    private final UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        SmsOtpAuthenticationToken token =
            (SmsOtpAuthenticationToken) authentication;
        String phone = (String) token.getPrincipal();
        String presentedOtp = (String) token.getCredentials();

        // OTP 조회
        OtpRecord record = otpStore.findByPhone(phone)
            .orElseThrow(() ->
                new BadCredentialsException("No OTP found for: " + phone));

        // 만료 확인
        if (record.isExpired()) {
            otpStore.delete(phone);
            throw new CredentialsExpiredException("OTP has expired");
        }

        // 상수 시간 비교
        boolean matches = MessageDigest.isEqual(
            presentedOtp.getBytes(StandardCharsets.UTF_8),
            record.getOtp().getBytes(StandardCharsets.UTF_8)
        );

        if (!matches) {
            throw new BadCredentialsException("Invalid OTP");
        }

        // 단일 사용 → 즉시 삭제
        otpStore.delete(phone);

        // 사용자 조회 및 상태 확인
        User user = userRepository.findByPhone(phone)
            .orElseThrow(() ->
                new UsernameNotFoundException("User not found: " + phone));

        if (!user.isEnabled()) {
            throw new DisabledException("User account is disabled");
        }

        // 인증 완료 토큰 반환
        List<GrantedAuthority> authorities =
            user.getRoles().stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .collect(Collectors.toList());

        return new SmsOtpAuthenticationToken(phone, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SmsOtpAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

// ── Step 3: Filter에서 Provider 호출 ────────────────────────────────
@RequiredArgsConstructor
public class SmsOtpAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public SmsOtpAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher("/auth/sms-login", "POST"),
              authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) {
        String phone = request.getParameter("phone");
        String otp = request.getParameter("otp");

        if (phone == null || otp == null) {
            throw new AuthenticationServiceException("phone and otp are required");
        }

        SmsOtpAuthenticationToken token = new SmsOtpAuthenticationToken(phone, otp);
        setDetails(request, token);
        return getAuthenticationManager().authenticate(token);
    }
}
```

### 패턴 2: API Key 인증

```java
// ── API Key Authentication Token ───────────────────────────────────
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private final String apiKey;
    private final Object principal; // 인증 전: null, 인증 후: ServiceAccount

    // 인증 전
    public ApiKeyAuthenticationToken(String apiKey) {
        super(null);
        this.apiKey = apiKey;
        this.principal = null;
        setAuthenticated(false);
    }

    // 인증 후
    public ApiKeyAuthenticationToken(String apiKey, Object principal,
                                      Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.apiKey = apiKey;
        this.principal = principal;
        super.setAuthenticated(true);
    }

    @Override public Object getPrincipal() { return this.principal; }
    @Override public Object getCredentials() { return this.apiKey; }
}

// ── API Key Provider ────────────────────────────────────────────────
@Component
@RequiredArgsConstructor
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private final ApiKeyRepository apiKeyRepository;

    @Override
    public Authentication authenticate(Authentication authentication) {
        ApiKeyAuthenticationToken token = (ApiKeyAuthenticationToken) authentication;
        String presentedKey = (String) token.getCredentials();

        // DB에서 API Key 조회 (해시로 저장하고 해시 비교 권장)
        ApiKeyRecord record = apiKeyRepository.findByKeyHash(hashKey(presentedKey))
            .orElseThrow(() -> new BadCredentialsException("Invalid API key"));

        // 만료 확인
        if (record.isExpired()) {
            throw new CredentialsExpiredException("API key has expired");
        }

        // 비활성화 확인
        if (!record.isActive()) {
            throw new DisabledException("API key is disabled");
        }

        // 사용 이력 업데이트
        apiKeyRepository.updateLastUsed(record.getId(), LocalDateTime.now());

        // 인증 완료 토큰 생성
        List<GrantedAuthority> authorities = record.getScopes().stream()
            .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
            .collect(Collectors.toList());

        return new ApiKeyAuthenticationToken(
            presentedKey,
            record.getServiceAccount(), // principal
            authorities
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private String hashKey(String key) {
        // SHA-256으로 해시 (DB에는 해시만 저장 — 원문 복원 불가)
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(key.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

// ── API Key Filter ──────────────────────────────────────────────────
@RequiredArgsConstructor
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private static final String API_KEY_HEADER = "X-API-KEY";
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain)
            throws ServletException, IOException {

        String apiKey = request.getHeader(API_KEY_HEADER);

        if (apiKey == null || apiKey.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication auth = authenticationManager.authenticate(
                new ApiKeyAuthenticationToken(apiKey));

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(auth);
            SecurityContextHolder.setContext(context);

        } catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Invalid API key\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
```

### 커스텀 Provider 등록 방법

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SmsOtpAuthenticationProvider smsOtpProvider;
    private final ApiKeyAuthenticationProvider apiKeyProvider;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    // ── 방법 1: http.authenticationProvider() ──────────────────────
    // 해당 SecurityFilterChain에만 적용
    @Bean
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {

        // AuthenticationManager 빌드
        AuthenticationManagerBuilder builder =
            http.getSharedObject(AuthenticationManagerBuilder.class);
        builder
            .authenticationProvider(apiKeyProvider)
            .authenticationProvider(smsOtpProvider)
            .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);

        AuthenticationManager authManager = builder.build();

        // Filter에 authManager 주입
        ApiKeyAuthenticationFilter apiKeyFilter =
            new ApiKeyAuthenticationFilter(authManager);

        http
            .securityMatcher("/api/**")
            .authenticationProvider(apiKeyProvider)
            .authenticationProvider(smsOtpProvider)
            .addFilterBefore(apiKeyFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

        return http.build();
    }

    // ── 방법 2: AuthenticationManagerBuilder (전역 AM에 등록) ───────
    // 모든 SecurityFilterChain에서 사용 가능
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        // AuthenticationConfiguration의 전역 AM에 접근해서 커스텀 Provider 추가 불가
        // → http.getSharedObject() 방식 사용 권장
        return config.getAuthenticationManager();
    }
}
```

---

## 🔬 내부 동작 원리

### 커스텀 Provider 선택 흐름

```
POST /auth/sms-login (phone=01012345678&otp=123456)
│
▼ SmsOtpAuthenticationFilter.attemptAuthentication()
│    new SmsOtpAuthenticationToken("01012345678", "123456")
│    → authManager.authenticate(token)
│
▼ ProviderManager.authenticate()
│    providers: [ApiKeyAuthenticationProvider,
│                SmsOtpAuthenticationProvider,
│                DaoAuthenticationProvider]
│
├─ ApiKeyAuthenticationProvider.supports(SmsOtpAuthenticationToken)?
│    SmsOtpAuthenticationToken.isAssignableFrom(ApiKeyAuthenticationToken)? → false
│    → 스킵
│
├─ SmsOtpAuthenticationProvider.supports(SmsOtpAuthenticationToken)?
│    SmsOtpAuthenticationToken.isAssignableFrom(SmsOtpAuthenticationToken)? → true!
│    → authenticate() 호출
│         otpStore.findByPhone("01012345678") → OtpRecord
│         만료 확인 → 유효
│         MessageDigest.isEqual("123456", storedOtp) → true
│         otpStore.delete("01012345678") → 단일 사용 보장
│         return SmsOtpAuthenticationToken("01012345678", [ROLE_USER])
│
└─ 인증 성공 → successfulAuthentication() 호출
     SecurityContext.setAuthentication(authenticatedToken)
```

### AbstractAuthenticationToken 상속의 이유

```java
// AbstractAuthenticationToken 주요 기능
public abstract class AbstractAuthenticationToken
        implements Authentication, CredentialsContainer {

    private final Collection<GrantedAuthority> authorities;
    private Object details;
    private boolean authenticated = false;

    // eraseCredentials() 기본 구현
    // getPrincipal()과 getCredentials()가 CredentialsContainer이면 재귀적으로 호출
    @Override
    public void eraseCredentials() {
        eraseSecret(getCredentials());
        eraseSecret(getPrincipal());
        eraseSecret(this.details);
    }

    // getName() 기본 구현 — getPrincipal().toString()
    @Override
    public String getName() {
        if (this.getPrincipal() instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        // ...
        return (this.getPrincipal() == null) ? "" : this.getPrincipal().toString();
    }

    // setAuthenticated() 보호
    @Override
    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }
}

// 직접 구현 시 놓치기 쉬운 것:
// - eraseCredentials() 미구현 → 인증 후 OTP/API Key가 메모리에 남음
// - getName() 미구현 → 로그/감사 기록에 "null" 표시
// - isAuthenticated()를 잘못 구현 → 인증 우회 가능
// → AbstractAuthenticationToken 상속으로 안전하게 기반 기능 확보
```

---

## 💻 실험으로 확인하기

### 실험 1: 커스텀 Provider supports() 단위 테스트

```java
@ExtendWith(MockitoExtension.class)
class SmsOtpAuthenticationProviderTest {

    @InjectMocks
    SmsOtpAuthenticationProvider provider;

    @Test
    void supports_smsOtpToken_returnsTrue() {
        assertTrue(provider.supports(SmsOtpAuthenticationToken.class));
    }

    @Test
    void supports_usernamePasswordToken_returnsFalse() {
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void supports_anonymousToken_returnsFalse() {
        assertFalse(provider.supports(AnonymousAuthenticationToken.class));
    }
}
```

### 실험 2: OTP 단일 사용 보장 확인

```bash
# OTP 요청 (서버에서 123456 발급됨)
curl -X POST http://localhost:8080/auth/request-otp \
  -d "phone=01012345678"
# → 200 OK (SMS 발송 됨)

# 첫 번째 OTP 사용
curl -X POST http://localhost:8080/auth/sms-login \
  -d "phone=01012345678&otp=123456"
# → 200 OK (인증 성공)

# 두 번째 OTP 사용 시도 (같은 OTP)
curl -X POST http://localhost:8080/auth/sms-login \
  -d "phone=01012345678&otp=123456"
# → 401 Unauthorized (OTP already consumed)
# → otpStore.delete() 이후 재사용 불가 확인
```

### 실험 3: API Key 해시 비교 확인

```bash
# API Key 등록 (SHA-256 해시로 저장)
curl -X POST http://localhost:8080/admin/api-keys \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"name":"test-service","scopes":["READ","WRITE"]}'
# → {"apiKey":"raw-key-value", "id":1}
# DB에는 SHA-256(raw-key-value)만 저장

# API Key 사용
curl -H "X-API-KEY: raw-key-value" http://localhost:8080/api/data
# → 200 OK (Provider에서 해시 비교 후 인증)

# 잘못된 키
curl -H "X-API-KEY: wrong-key" http://localhost:8080/api/data
# → 401 Unauthorized
```

---

## 🔒 보안 체크리스트

```
커스텀 Token 구현
  ☐ AbstractAuthenticationToken 상속 (eraseCredentials, getName 등 기반 기능 활용)
  ☐ 인증 전 생성자: authorities=null, setAuthenticated(false)
  ☐ 인증 후 생성자: super.setAuthenticated(true) (직접 setAuthenticated 불가하게 Override)
  ☐ eraseCredentials(): OTP, API Key 등 민감 정보 null 처리

커스텀 Provider 구현
  ☐ supports(): 정확한 토큰 타입만 선언 (너무 넓은 범위 금지)
  ☐ OTP 비교: MessageDigest.isEqual() 사용 (타이밍 공격 방어)
  ☐ OTP 단일 사용: 검증 성공 즉시 삭제
  ☐ OTP 만료: 5~10분 이내 설정
  ☐ API Key: DB에 해시로 저장 (원문 저장 금지)

등록 및 테스트
  ☐ supports() 단위 테스트 (처리할 타입, 처리 안 할 타입 모두)
  ☐ authenticate() 성공/실패 경로 단위 테스트
  ☐ ProviderManager에 올바른 순서로 등록됐는지 확인
```

---

## 🤔 트레이드오프

```
커스텀 토큰 타입 vs UsernamePasswordAuthenticationToken 재사용:
  커스텀 토큰 타입:
    장점  타입 안전, 커스텀 필드 명확히 분리 (phone, otp 등)
          supports()로 정확한 Provider 선택
    단점  추가 클래스 작성 필요

  UPAT 재사용:
    장점  기존 코드와 연동 용이
    단점  username/password 필드에 phone/otp를 억지로 맞춰야 함
          다른 Provider(DaoAuthenticationProvider)가 supports()=true를 반환해 간섭 가능

API Key DB 저장 방식:
  원문 저장:
    단점  DB 탈취 시 모든 API Key 노출 (즉시 사용 가능)

  해시 저장 (SHA-256):
    장점  DB 탈취 시 원문 복원 불가
    단점  단방향이므로 사용자에게 Key를 한 번만 보여줘야 함

  prefix + 해시 (GitHub 방식):
    예: "svc_abc123" → prefix="svc_", 나머지를 해시
    장점  prefix로 Key의 목적 파악 가능
          해시 비교로 안전한 검증
```

---

## 📌 핵심 정리

```
커스텀 AuthenticationProvider 구현 패턴
  1. 커스텀 Authentication 토큰 클래스 (AbstractAuthenticationToken 상속)
     인증 전 생성자: credentials만, authenticated=false
     인증 후 생성자: authorities 포함, authenticated=true
  2. AuthenticationProvider 구현
     supports(): 정확한 토큰 타입만
     authenticate(): 검증 → 성공 시 인증 완료 토큰 반환
  3. 커스텀 Filter 또는 기존 Filter에서 토큰 생성 → AM 위임
  4. SecurityConfig에서 Provider 등록

OTP 보안 원칙
  상수 시간 비교 (타이밍 공격 방어)
  단일 사용 (검증 즉시 삭제)
  짧은 만료 시간 (5~10분)
  실패 횟수 제한 + 잠금

API Key 보안 원칙
  DB에 SHA-256 해시로 저장
  X-API-KEY 헤더로 전달 (쿼리 파라미터 금지 — 서버 로그에 노출)
  만료 일시 + 활성화 상태 관리
  사용 이력 기록 (감사 로그)
```

---

## 🤔 생각해볼 문제

**Q1.** `SmsOtpAuthenticationProvider`가 `authenticate()` 내에서 `UsernameNotFoundException`을 throw했을 때 `ProviderManager`는 이 예외를 어떻게 처리하는가? 부모 `ProviderManager`에 위임하는가, 즉시 전파하는가?

**Q2.** API Key 인증에서 `OncePerRequestFilter`를 사용하는 이유는 무엇인가? `AbstractAuthenticationProcessingFilter`를 사용하면 어떤 문제가 생기는가?

**Q3.** 커스텀 OTP Provider를 구현할 때 `AbstractUserDetailsAuthenticationProvider`를 상속하는 것이 적절한가? 상속이 적합한 경우와 직접 `AuthenticationProvider`를 구현하는 것이 적합한 경우를 비교하라.

> 💡 **해설**
>
> **Q1.** `UsernameNotFoundException`은 `AuthenticationException`의 하위 타입이지만 `AccountStatusException`이나 `InternalAuthenticationServiceException`은 아닙니다. 따라서 `ProviderManager`는 `UsernameNotFoundException`을 `lastException`에 저장하고 다음 Provider를 시도합니다. 모든 Provider가 실패한 후 부모 `ProviderManager`에 위임합니다. 부모도 처리하지 못하면 마지막 예외(`UsernameNotFoundException`)를 전파합니다. 단, `hideUserNotFoundExceptions=true`(기본값)인 경우 `UsernameNotFoundException`은 `BadCredentialsException`으로 변환되어 전파됩니다. 이는 사용자 존재 여부를 클라이언트에게 노출하지 않기 위한 보안 설계입니다.
>
> **Q2.** `AbstractAuthenticationProcessingFilter`는 특정 URL 패턴에서만 `attemptAuthentication()`을 실행하고, 성공 시 `successHandler`(리다이렉트 등)를 호출합니다. API Key 인증은 모든 요청의 헤더를 검사해야 하므로 URL 패턴 제한이 맞지 않습니다. 또한 성공 시 리다이렉트가 아닌 `chain.doFilter()`로 요청을 계속 처리해야 합니다. `OncePerRequestFilter`는 모든 요청에서 한 번만 실행되고 인증 성공/실패 모두 `filterChain.doFilter()`를 제어할 수 있어 API Key 인증에 적합합니다.
>
> **Q3.** `AbstractUserDetailsAuthenticationProvider`는 `UsernamePasswordAuthenticationToken`에 특화된 템플릿입니다. OTP는 `username+password` 패러다임과 다르므로(phone+otp) 억지로 `AbstractUserDetailsAuthenticationProvider`를 상속하면 `UsernamePasswordAuthenticationToken`에 종속됩니다. OTP Provider는 전화번호로 사용자를 조회하고, OTP를 별도 저장소에서 검증하며, 단일 사용을 보장해야 하는 고유한 흐름을 가집니다. 이런 경우 `AuthenticationProvider`를 직접 구현하는 것이 적합합니다. 반면 `AbstractUserDetailsAuthenticationProvider` 상속이 적합한 경우는 `UserDetailsService`로 사용자를 조회하고 자격증명을 검증하는 기본 패턴을 따르는 경우입니다. 예를 들어 LDAP 기반 비밀번호 검증처럼 조회 방식만 다르고 검증 구조는 동일한 경우에 상속이 유리합니다.

---

<div align="center">

**[← 이전: Remember-Me 인증 메커니즘](./06-remember-me-authentication.md)** | **[홈으로 🏠](../README.md)** | **[Chapter 3으로 이동: @PreAuthorize vs @Secured ➡️](../authorization-method-security/01-pre-authorize-vs-secured.md)**

</div>
