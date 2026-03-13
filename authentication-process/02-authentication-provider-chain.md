# AuthenticationProvider 체인 동작 — supports()로 책임을 분배하는 전략 패턴

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `AuthenticationProvider.supports()`가 `true`를 반환하는 기준은 어떻게 설계해야 하는가?
- `DaoAuthenticationProvider`가 `AbstractUserDetailsAuthenticationProvider`를 상속하는 이유는?
- `AnonymousAuthenticationProvider`는 어떤 상황에서 필요한가?
- `Provider`가 `null`을 반환하는 것과 `AuthenticationException`을 throw하는 것은 어떻게 다른가?
- `RememberMeAuthenticationProvider`는 `RememberMeAuthenticationToken`의 키를 왜 검증하는가?
- Spring Security의 기본 Provider 목록은 어떤 순서로 등록되는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 인증 방식마다 검증 로직이 완전히 다르다

```
인증 방식별 필요한 검증 로직:

  폼 로그인 (UsernamePasswordAuthenticationToken):
    → DB에서 사용자 조회
    → 비밀번호 BCrypt 비교
    → 계정 상태 검사 (활성화, 잠금, 만료 등)

  Remember-Me (RememberMeAuthenticationToken):
    → 쿠키 토큰 파싱
    → 서버 저장 토큰과 비교
    → 사용자 재로드

  OAuth2 (OAuth2AuthenticationToken):
    → OAuth2 서버에서 사용자 정보 조회
    → 로컬 사용자와 매핑

  JWT (JwtAuthenticationToken):
    → 서명 검증 (HMAC 또는 RSA)
    → 만료 시간 확인
    → Claims에서 사용자 정보 추출

이 모든 로직을 하나의 클래스에 넣으면 OCP 위반
→ 각 인증 방식을 독립된 AuthenticationProvider로 구현
→ 새 인증 방식 = 새 Provider 추가 (기존 코드 수정 없음)
```

---

## 😱 흔한 보안 실수

### Before: supports()를 너무 넓게 구현해 의도치 않은 Provider가 실행됨

```java
// ❌ 위험: supports()에서 부모 타입으로 체크
@Component
public class DangerousProvider implements AuthenticationProvider {

    @Override
    public boolean supports(Class<?> authentication) {
        // AbstractAuthenticationToken의 모든 하위 타입을 처리하겠다고 선언
        return AbstractAuthenticationToken.class.isAssignableFrom(authentication);
        // → UsernamePasswordAuthenticationToken, JwtAuthenticationToken,
        //   AnonymousAuthenticationToken, RememberMeAuthenticationToken 등
        //   모든 토큰을 이 Provider가 가로챔
        // → 다른 Provider가 실행될 기회를 빼앗음
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        // 처리 못하는 타입이 들어와도 null이나 예외를 던지면 문제
        // 특히 AnonymousAuthenticationToken을 받아서 잘못 처리하면
        // 인증되지 않은 사용자에게 권한이 부여될 수 있음
        return null;
    }
}

// ✅ 올바른 방법: 정확한 타입으로 한정
@Override
public boolean supports(Class<?> authentication) {
    // isAssignableFrom 사용 시: 정확히 처리할 타입만 선언
    return UsernamePasswordAuthenticationToken.class
        .isAssignableFrom(authentication);
    // 또는 equals 사용 (하위 타입 제외)
    // return UsernamePasswordAuthenticationToken.class.equals(authentication);
}
```

### Before: Provider에서 null 반환과 예외 throw를 혼용

```java
// ❌ 혼란: null과 예외의 의미가 다름
@Override
public Authentication authenticate(Authentication authentication) {
    String username = authentication.getName();
    UserDetails user = userDetailsService.loadUserByUsername(username);

    if (user == null) {
        return null; // 의도: "처리할 수 없다" → 다른 Provider에게 위임
        // 문제: null은 ProviderManager가 "이 Provider가 처리했지만 결과 없음"으로 해석
        //       실제로는 UsernameNotFoundException을 throw해야 함
    }

    if (!passwordEncoder.matches(auth.getCredentials().toString(), user.getPassword())) {
        throw new BadCredentialsException("Bad credentials");
        // 올바름: 검증 실패 → 명확한 예외
    }
    return ...; // 성공
}

// ✅ 올바른 semantics:
// null 반환: "나는 이 인증 타입을 처리할 수 없다 — 다른 Provider에게 넘겨라"
//            (supports()=true이지만 런타임에 처리 불가한 예외적 상황)
// 예외 throw: "처리는 했지만 인증 실패" (자격증명 오류, 계정 잠금 등)
```

---

## ✨ 올바른 보안 구현

### Provider 등록과 우선순위 설정

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 1순위: 커스텀 Provider (addAuthenticationProvider 순서)
            .authenticationProvider(smsOtpAuthenticationProvider())
            // 2순위: JWT Provider
            .authenticationProvider(jwtAuthenticationProvider())
            // DaoAuthenticationProvider는 UserDetailsService Bean 설정 시 자동 추가됨
            // (authenticationProvider()로 명시 등록 시 자동 추가는 비활성화됨)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public SmsOtpAuthenticationProvider smsOtpAuthenticationProvider() {
        return new SmsOtpAuthenticationProvider(smsService, userDetailsService());
    }
}
```

---

## 🔬 내부 동작 원리

### 1. AuthenticationProvider 인터페이스

```java
// AuthenticationProvider.java
public interface AuthenticationProvider {

    /**
     * 실제 인증 수행
     * @return 인증된 Authentication (null이면 다음 Provider에게 위임)
     * @throws AuthenticationException 인증 실패
     */
    Authentication authenticate(Authentication authentication)
            throws AuthenticationException;

    /**
     * 이 Provider가 처리할 수 있는 Authentication 타입 선언
     * ProviderManager가 Provider 선택에 사용
     */
    boolean supports(Class<?> authentication);
}
```

### 2. AbstractUserDetailsAuthenticationProvider — 공통 인증 흐름 템플릿

```java
// AbstractUserDetailsAuthenticationProvider.java
// DaoAuthenticationProvider의 부모 — 템플릿 메서드 패턴
public abstract class AbstractUserDetailsAuthenticationProvider
        implements AuthenticationProvider, InitializingBean, MessageSourceAware {

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        String username = determineUsername(authentication);

        // ① 캐시에서 UserDetails 조회
        UserDetails user = this.userCache.getUserFromCache(username);

        if (user == null) {
            // ② 캐시 미스 → 실제 로드 (DaoAuthenticationProvider에서 구현)
            try {
                user = retrieveUser(username,
                    (UsernamePasswordAuthenticationToken) authentication);
            } catch (UsernameNotFoundException ex) {
                // 타이밍 공격 방지: 사용자 없어도 비밀번호 검증 수행
                this.passwordEncoder.matches("dummy", this.userNotFoundEncodedPassword);
                throw ex;
            }
        }

        // ③ 계정 상태 사전 검사
        preAuthenticationChecks.check(user);
        //   isAccountNonLocked() → false → LockedException
        //   isEnabled()          → false → DisabledException
        //   isAccountNonExpired()→ false → AccountExpiredException

        // ④ 실제 자격증명 검증 (비밀번호 비교 — DaoAuthenticationProvider 구현)
        additionalAuthenticationChecks(user,
            (UsernamePasswordAuthenticationToken) authentication);

        // ⑤ 계정 상태 사후 검사
        postAuthenticationChecks.check(user);
        //   isCredentialsNonExpired() → false → CredentialsExpiredException

        // ⑥ 캐시 저장
        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }

        // ⑦ 인증 성공 토큰 생성
        return createSuccessAuthentication(user, authentication, user);
    }

    // 하위 클래스가 구현해야 하는 추상 메서드
    protected abstract UserDetails retrieveUser(String username,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException;

    protected abstract void additionalAuthenticationChecks(UserDetails userDetails,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException;
}
```

### 3. DaoAuthenticationProvider — DB 기반 인증

```java
// DaoAuthenticationProvider.java
public class DaoAuthenticationProvider
        extends AbstractUserDetailsAuthenticationProvider {

    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    // ① 사용자 로드 (DB 조회)
    @Override
    protected UserDetails retrieveUser(String username,
            UsernamePasswordAuthenticationToken authentication) {
        try {
            UserDetails loadedUser =
                this.getUserDetailsService().loadUserByUsername(username);
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                    "UserDetailsService returned null...");
            }
            return loadedUser;
        } catch (UsernameNotFoundException ex) {
            throw ex; // 재throw → AbstractParent가 타이밍 공격 방지 처리
        } catch (InternalAuthenticationServiceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    // ② 비밀번호 검증
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) {
        if (authentication.getCredentials() == null) {
            throw new BadCredentialsException("Bad credentials");
        }
        String presentedPassword = authentication.getCredentials().toString();
        // PasswordEncoder.matches(raw, encoded) — BCrypt 해시 비교
        if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // UsernamePasswordAuthenticationToken 및 하위 타입 지원
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

### 4. 기본 Provider 목록과 등록 시점

```java
// HttpSecurityConfiguration.java + 각 Configurer들이 Provider를 추가

// formLogin() 설정 시:
//   → UsernamePasswordAuthenticationFilter 추가
//   → DaoAuthenticationProvider가 자동 연결 (UserDetailsService Bean 있으면)

// rememberMe() 설정 시:
//   → RememberMeAuthenticationFilter 추가
//   → RememberMeAuthenticationProvider 등록

// anonymous() 설정 시 (기본 활성화):
//   → AnonymousAuthenticationFilter 추가
//   → AnonymousAuthenticationProvider 등록
//   (AnonymousAuthenticationFilter가 생성한 토큰을 AM이 처리할 수 있도록)

// 기본 Provider 실행 순서 (등록 순서):
// 1. 개발자가 authenticationProvider()로 추가한 것들
// 2. DaoAuthenticationProvider (UserDetailsService 연결)
// 3. AnonymousAuthenticationProvider (anonymous() 활성화 시)
// 4. RememberMeAuthenticationProvider (rememberMe() 활성화 시)
```

### 5. 기본 Provider 상세

```
Provider                        처리하는 Authentication 타입
─────────────────────────────  ─────────────────────────────────────
DaoAuthenticationProvider      UsernamePasswordAuthenticationToken
                                → supports(): UPAT.isAssignableFrom()
                                → retrieveUser(): UserDetailsService.loadByUsername()
                                → additionalChecks(): PasswordEncoder.matches()

AnonymousAuthenticationProvider AnonymousAuthenticationToken
                                → supports(): AAT.isAssignableFrom()
                                → authenticate(): key 검증만 수행
                                  (AnonymousAuthenticationFilter가 생성한 토큰의
                                   key가 일치하는지 확인)

RememberMeAuthenticationProvider RememberMeAuthenticationToken
                                → supports(): RMAT.isAssignableFrom()
                                → authenticate(): token.getKeyHash() 검증
                                  (RememberMeServices 설정 key와 일치해야 함)

PreAuthenticatedAuthenticationProvider PreAuthenticatedAuthenticationToken
                                → X.509, 요청 헤더 사전 인증 처리
                                → supports(): PAAT.isAssignableFrom()
```

### 6. Provider가 null을 반환하는 시나리오

```java
// ProviderManager.authenticate() 내부:
for (AuthenticationProvider provider : getProviders()) {
    if (!provider.supports(toTest)) continue;

    result = provider.authenticate(authentication);

    if (result != null) {
        break; // 성공 → 루프 종료
    }
    // result == null → 다음 Provider 시도
    // (supports()=true인데 null 반환 = 처리하겠다고 했지만 못함)
}

// null을 반환해야 하는 적절한 시나리오:
// ① 멀티 테넌트: Provider가 특정 테넌트의 요청만 처리
@Override
public Authentication authenticate(Authentication authentication) {
    String tenantId = extractTenantId(authentication);
    if (!"tenant-A".equals(tenantId)) {
        return null; // "나는 tenant-A만 처리한다 — 다음 Provider에게"
    }
    // tenant-A 처리 ...
}
```

---

## 💻 실험으로 확인하기

### 실험 1: supports() 분기 TRACE 로그

```yaml
logging:
  level:
    org.springframework.security.authentication: TRACE
```

```
# POST /login 요청 시:
TRACE ProviderManager - Authenticating request with DaoAuthenticationProvider
DEBUG DaoAuthenticationProvider - Authenticated user

# 지원 안 되는 타입:
TRACE ProviderManager - DaoAuthenticationProvider does not support SmsAuthenticationToken
TRACE ProviderManager - AnonymousAuthenticationProvider does not support SmsAuthenticationToken
DEBUG ProviderManager - No AuthenticationProvider found for SmsAuthenticationToken
```

### 실험 2: UserDetails 상태별 예외 확인

```java
// 각 UserDetails 상태에 따라 다른 예외 발생 확인
@Test
void testAccountStatusExceptions() {
    // isEnabled=false
    when(userDetailsService.loadUserByUsername("disabled"))
        .thenReturn(new User("disabled", "pass",
            false, true, true, true,   // enabled=false
            List.of()));

    assertThatThrownBy(() ->
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken("disabled", "pass")))
        .isInstanceOf(DisabledException.class);

    // isAccountNonLocked=false
    when(userDetailsService.loadUserByUsername("locked"))
        .thenReturn(new User("locked", "pass",
            true, true, true, false,   // nonLocked=false
            List.of()));

    assertThatThrownBy(() ->
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken("locked", "pass")))
        .isInstanceOf(LockedException.class);
}
```

### 실험 3: 타이밍 공격 방지 확인

```java
// 존재하지 않는 사용자와 잘못된 비밀번호 응답 시간 비교
@Test
void timingAttackPrevention() {
    long start1 = System.currentTimeMillis();
    try {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken("nonexistent", "pass"));
    } catch (AuthenticationException ignored) {}
    long time1 = System.currentTimeMillis() - start1;

    long start2 = System.currentTimeMillis();
    try {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken("existing", "wrongpass"));
    } catch (AuthenticationException ignored) {}
    long time2 = System.currentTimeMillis() - start2;

    // time1 ≈ time2 (타이밍 차이로 존재 여부 추론 불가)
    // AbstractUserDetailsAuthenticationProvider가
    // 사용자 없어도 dummy 비밀번호 검증을 수행하기 때문
    System.out.println("NonExistent: " + time1 + "ms, WrongPass: " + time2 + "ms");
}
```

---

## 🔒 보안 체크리스트

```
AuthenticationProvider 구현
  ☐ supports()에서 처리할 정확한 Authentication 타입만 선언
  ☐ retrieveUser()에서 사용자 미존재 시 UsernameNotFoundException throw
     (null 반환 금지 — InternalAuthenticationServiceException 발생)
  ☐ additionalAuthenticationChecks()에서 자격증명 검증 후 명확한 예외 throw

타이밍 공격 방지
  ☐ 사용자가 없어도 비밀번호 검증 시간을 동일하게 유지
     (AbstractUserDetailsAuthenticationProvider의 기본 구현 활용)
  ☐ 예외 메시지에 "사용자 없음" vs "비밀번호 틀림"을 구분해서 노출하지 않음

계정 상태 검사
  ☐ preAuthenticationChecks: locked, disabled, expired 검사
  ☐ postAuthenticationChecks: credentialsExpired 검사
  ☐ 커스텀 상태 검사가 필요하면 UserDetailsChecker 구현 후 주입
```

---

## 🤔 트레이드오프

```
AbstractUserDetailsAuthenticationProvider 상속 vs AuthenticationProvider 직접 구현:
  상속:
    장점  캐싱, 타이밍 공격 방지, 계정 상태 검사 자동 처리
          인증 이벤트 발행 자동
    단점  UsernamePasswordAuthenticationToken에 종속
          다른 토큰 타입 처리 시 부적합

  직접 구현:
    장점  완전한 자유 (JWT, API Key, OTP 등 모든 타입 처리)
    단점  타이밍 공격 방지, 이벤트 발행 등을 직접 구현해야 함

UserDetails 캐싱:
  장점  동일 사용자의 반복 요청 시 DB 조회 감소
  단점  캐시된 UserDetails가 최신 상태와 다를 수 있음
        권한 변경이 즉시 반영되지 않음
        → TTL 설정이나 캐시 무효화 전략 필요
```

---

## 📌 핵심 정리

```
AuthenticationProvider 책임
  supports()   → "이 Authentication 타입을 내가 처리할 수 있는가?"
  authenticate() → 실제 검증 수행
                   성공: 인증된 Authentication 반환
                   실패: AuthenticationException throw
                   위임: null 반환 (다음 Provider 시도)

AbstractUserDetailsAuthenticationProvider 템플릿
  retrieveUser()         → 사용자 로드 (DB 조회)
  preAuthenticationChecks → 계정 상태 사전 검사
  additionalAuthenticationChecks → 자격증명 검증 (비밀번호 비교)
  postAuthenticationChecks → 비밀번호 만료 검사
  타이밍 공격 방지 내장    → 사용자 없어도 dummy 비밀번호 검증

기본 Provider 목록
  DaoAuthenticationProvider    → 폼 로그인 / Basic Auth
  AnonymousAuthenticationProvider → 익명 사용자 토큰 검증
  RememberMeAuthenticationProvider → Remember-Me 쿠키 인증
```

---

## 🤔 생각해볼 문제

**Q1.** `AbstractUserDetailsAuthenticationProvider`가 사용자 미존재 시 `UsernameNotFoundException`을 catch하고 dummy 비밀번호 검증을 수행하는 이유는 무엇인가? 이를 비활성화하면 어떤 공격이 가능해지는가?

**Q2.** `UserCache`를 활성화했을 때 사용자의 비밀번호가 변경되거나 계정이 잠금 처리됐을 경우 어떤 문제가 발생하는가? 실시간으로 반영하려면 어떻게 해야 하는가?

**Q3.** `DaoAuthenticationProvider`에 `UserDetailsPasswordService`를 주입하면 어떤 추가 기능이 활성화되는가?

> 💡 **해설**
>
> **Q1.** 사용자 미존재 시 즉시 예외를 반환하면 응답 시간이 매우 짧아집니다(DB 조회 후 즉시 반환). 반면 존재하는 사용자의 비밀번호 틀림은 BCrypt 비교 시간(약 100~300ms)이 추가됩니다. 공격자는 이 시간 차이를 이용해 어떤 사용자명이 시스템에 존재하는지 열거(User Enumeration)할 수 있습니다. Dummy 비밀번호 검증으로 두 경우의 응답 시간을 유사하게 만들어 이를 방지합니다. 비활성화하면 응답 시간 측정만으로 유효한 사용자명을 수집할 수 있어 크리덴셜 스터핑 공격의 효율이 높아집니다.
>
> **Q2.** `UserCache`에 저장된 `UserDetails`는 `isEnabled=true`, `isAccountNonLocked=true` 등의 상태를 캐시 생성 시점으로 고정합니다. 관리자가 계정을 잠금 처리해도 캐시가 유효한 동안은 잠금이 반영되지 않아 보안 위험이 됩니다. 해결 방법으로는 캐시 TTL을 짧게 설정하거나, 계정 상태 변경 시 `UserCache.removeUserFromCache(username)`를 명시적으로 호출하거나, JWT Stateless 환경에서는 캐시 자체를 사용하지 않는 방법이 있습니다.
>
> **Q3.** `UserDetailsPasswordService`를 주입하면 `DaoAuthenticationProvider`가 인증 성공 시 현재 `PasswordEncoder`가 업그레이드를 권장하는지 확인합니다(`passwordEncoder.upgradeEncoding()`). 예를 들어 MD5로 저장된 비밀번호를 BCrypt로 자동 업그레이드하거나, BCrypt의 work factor를 높인 새 설정으로 재해싱할 때 사용합니다. 인증 성공 시 새 해시로 DB를 자동 업데이트하므로 `DelegatingPasswordEncoder`와 결합하면 무중단 비밀번호 알고리즘 마이그레이션이 가능합니다.

---

<div align="center">

**[← 이전: AuthenticationManager vs ProviderManager](./01-authentication-manager-provider-manager.md)** | **[홈으로 🏠](../README.md)** | **[다음: UserDetailsService 구현과 커스터마이징 ➡️](./03-user-details-service.md)**

</div>
