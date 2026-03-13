# UserDetailsService 구현과 커스터마이징 — loadUserByUsername()의 계약과 UserDetails 설계

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `UserDetailsService.loadUserByUsername()`이 `null`을 반환하면 안 되는 이유는?
- `UserDetails`의 `isAccountNonExpired`, `isEnabled`, `isAccountNonLocked`, `isCredentialsNonExpired` 4개 플래그가 인증 흐름에서 언제, 어떤 순서로 검사되는가?
- `UserDetailsManager`는 `UserDetailsService`와 어떻게 다른가?
- 이메일·전화번호로도 로그인할 수 있도록 `loadUserByUsername()`을 어떻게 확장하는가?
- `UserDetails`를 캐싱할 때 고려해야 할 일관성 문제는 무엇인가?
- `UserDetails`와 도메인 `User` 엔티티를 어떻게 설계해야 결합도를 낮출 수 있는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 사용자 저장소(DB, LDAP, OAuth 서버)가 다양하다

```
사용자 정보 저장 방식:
  관계형 DB (JPA, JDBC)
  LDAP 디렉터리
  인메모리 (테스트용)
  OAuth2 서버 (소셜 로그인)
  외부 API

DaoAuthenticationProvider는 사용자 로드 방법을 알고 싶지 않음
→ "나에게 username을 주면 UserDetails를 돌려줘" 라는 계약만 정의
→ UserDetailsService 인터페이스 — 저장소 추상화

개발자는 저장소에 맞는 UserDetailsService만 구현하면
DaoAuthenticationProvider, 비밀번호 검증, 계정 상태 검사를
모두 공짜로 얻음
```

---

## 😱 흔한 보안 실수

### Before: loadUserByUsername()에서 null 반환

```java
// ❌ 위험: null 반환 시 InternalAuthenticationServiceException 발생
@Override
public UserDetails loadUserByUsername(String username) {
    User user = userRepository.findByUsername(username);
    if (user == null) {
        return null; // 하면 안 됨!
        // DaoAuthenticationProvider:
        //   if (loadedUser == null)
        //     throw new InternalAuthenticationServiceException("returned null")
        // → 500 에러로 처리됨 (클라이언트에게 혼란스러운 응답)
    }
    return mapToUserDetails(user);
}

// ✅ 올바른 계약: 사용자 없으면 UsernameNotFoundException throw
@Override
public UserDetails loadUserByUsername(String username)
        throws UsernameNotFoundException {
    return userRepository.findByUsername(username)
        .map(this::mapToUserDetails)
        .orElseThrow(() ->
            new UsernameNotFoundException("User not found: " + username));
    // → DaoAuthenticationProvider가 타이밍 공격 방지 처리를 올바르게 수행
}
```

### Before: UserDetails에 민감한 정보를 너무 많이 포함

```java
// ❌ 과도한 정보 포함 — SecurityContext에 직렬화되어 세션에 저장됨
public class OverloadedUserDetails implements UserDetails {
    private Long userId;
    private String username;
    private String password;
    private String email;
    private String phone;
    private String homeAddress;       // 불필요 — 보안 컨텍스트에 저장 불필요
    private LocalDate birthDate;      // 불필요
    private String socialSecurityNumber; // 매우 위험!
    private List<Order> orderHistory; // 불필요 — 거대한 객체 직렬화
    // ... 20개 필드
}
// → HttpSession 직렬화 크기 폭발
// → 세션 탈취 시 개인정보 대규모 노출

// ✅ 최소 필요 정보만 포함
public class MinimalUserDetails implements UserDetails {
    private Long userId;       // PK (DB 재조회용)
    private String username;   // 사용자명
    private String password;   // 비밀번호 해시 (인증 후 erase됨)
    private boolean enabled;
    private boolean accountNonLocked;
    private List<String> roles; // 권한 문자열만
}
```

---

## ✨ 올바른 보안 구현

### 실전 UserDetailsService 구현

```java
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        // 이메일·전화번호·사용자명 모두 허용하는 유연한 조회
        User user = userRepository
            .findByUsernameOrEmailOrPhone(username, username, username)
            .orElseThrow(() ->
                new UsernameNotFoundException(
                    "No user found with identifier: " + username));

        return CustomUserDetails.builder()
            .userId(user.getId())
            .username(user.getUsername())
            .password(user.getPasswordHash())
            .authorities(mapToAuthorities(user.getRoles()))
            .enabled(user.isEnabled())
            .accountNonExpired(!user.isAccountExpired())
            .accountNonLocked(!user.isLocked())
            .credentialsNonExpired(!user.isPasswordExpired())
            .build();
    }

    private Collection<GrantedAuthority> mapToAuthorities(Set<Role> roles) {
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
            .collect(Collectors.toList());
    }
}
```

### UserDetails 커스텀 구현 — 필요한 필드만 담기

```java
@Getter
@Builder
public class CustomUserDetails implements UserDetails {

    private final Long userId;     // 도메인 식별자 — @AuthenticationPrincipal로 주입
    private final String username;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean enabled;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;

    // UserDetails 인터페이스 구현 (Lombok @Getter로 자동 생성)

    // eraseCredentials() — 인증 완료 후 비밀번호 null 처리
    // CredentialsContainer 구현 시 ProviderManager가 자동 호출
    // (UserDetails는 기본적으로 CredentialsContainer를 구현하지 않으므로
    //  필요시 직접 구현)
    public CustomUserDetails erased() {
        return CustomUserDetails.builder()
            .userId(this.userId)
            .username(this.username)
            .password(null)  // 비밀번호 제거
            .authorities(this.authorities)
            .enabled(this.enabled)
            .accountNonExpired(this.accountNonExpired)
            .accountNonLocked(this.accountNonLocked)
            .credentialsNonExpired(this.credentialsNonExpired)
            .build();
    }
}
```

---

## 🔬 내부 동작 원리

### 1. UserDetailsService 인터페이스

```java
// UserDetailsService.java
@FunctionalInterface
public interface UserDetailsService {

    /**
     * 사용자명으로 UserDetails 로드
     *
     * 계약:
     * - 사용자 없으면 반드시 UsernameNotFoundException throw (null 반환 금지)
     * - 반환값은 non-null
     * - 비밀번호는 반드시 인코딩된 형태 (평문 비밀번호 금지)
     */
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

### 2. UserDetails 인터페이스 — 4개 상태 플래그의 의미

```java
// UserDetails.java
public interface UserDetails extends Serializable {

    // 부여된 권한 목록
    Collection<? extends GrantedAuthority> getAuthorities();

    // 인코딩된 비밀번호
    // → 인증 완료 후 ProviderManager.eraseCredentials()로 null 처리됨
    String getPassword();

    // 사용자명 (loadUserByUsername()의 입력값과 반드시 동일할 필요는 없음)
    // → @AuthenticationPrincipal에서 접근하는 값
    String getUsername();

    // ── 4개 계정 상태 플래그 ─────────────────────────────────────────

    // 계정 만료 여부 (false → AccountExpiredException)
    // 사용 예: 유료 구독 만료, 일정 기간 미활동 계정 비활성화
    boolean isAccountNonExpired();

    // 계정 잠금 여부 (false → LockedException)
    // 사용 예: 로그인 5회 실패 시 잠금
    boolean isAccountNonLocked();

    // 자격증명(비밀번호) 만료 여부 (false → CredentialsExpiredException)
    // 사용 예: 90일마다 비밀번호 변경 강제
    boolean isCredentialsNonExpired();

    // 계정 활성화 여부 (false → DisabledException)
    // 사용 예: 이메일 인증 미완료, 관리자에 의한 정지
    boolean isEnabled();
}
```

### 3. 4개 플래그 검사 순서와 위치

```java
// AbstractUserDetailsAuthenticationProvider.java
// 검사 순서가 중요 — 어떤 예외가 먼저 발생하는지 결정

// ① preAuthenticationChecks (비밀번호 검증 전)
private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
    @Override
    public void check(UserDetails user) {
        // 1. 계정 잠금 (가장 먼저)
        if (!user.isAccountNonLocked()) {
            throw new LockedException("User account is locked");
        }
        // 2. 계정 활성화
        if (!user.isEnabled()) {
            throw new DisabledException("User is disabled");
        }
        // 3. 계정 만료
        if (!user.isAccountNonExpired()) {
            throw new AccountExpiredException("User account has expired");
        }
    }
}

// ② additionalAuthenticationChecks — 비밀번호 검증

// ③ postAuthenticationChecks (비밀번호 검증 후)
private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
    @Override
    public void check(UserDetails user) {
        // 4. 비밀번호 만료 (비밀번호 검증 성공 후에만 검사)
        if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException("User credentials have expired");
        }
    }
}

// 설계 이유:
// isCredentialsNonExpired()를 마지막에 검사하는 이유:
// 비밀번호가 맞다는 것을 확인한 후에야 "비밀번호 만료" 안내를 제공
// (자격증명 오류인지 만료인지 구분 가능)
```

### 4. UserDetailsManager — 확장 인터페이스

```java
// UserDetailsManager.java (UserDetailsService 확장)
public interface UserDetailsManager extends UserDetailsService {
    void createUser(UserDetails user);
    void updateUser(UserDetails user);
    void deleteUser(String username);
    void changePassword(String oldPassword, String newPassword);
    boolean userExists(String username);
}

// 구현체 종류:
// InMemoryUserDetailsManager  — 메모리 기반 (테스트, 데모)
// JdbcUserDetailsManager      — JDBC 기반 (Spring Security 기본 테이블 스키마)
// 커스텀 구현                 — JPA 기반 실무 구현

// JPA 기반 UserDetailsManager 예시
@Service
@RequiredArgsConstructor
@Transactional
public class JpaUserDetailsManager implements UserDetailsManager {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    @Override
    public void createUser(UserDetails user) {
        // UserDetails → 도메인 User 엔티티 변환 후 저장
        User entity = new User();
        entity.setUsername(user.getUsername());
        entity.setPasswordHash(passwordEncoder.encode(user.getPassword()));
        entity.setEnabled(user.isEnabled());
        userRepository.save(entity);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentAuth = SecurityContextHolder.getContext()
            .getAuthentication();
        String username = currentAuth.getName();

        // 현재 비밀번호 검증
        UserDetails user = loadUserByUsername(username);
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new BadCredentialsException("Current password is incorrect");
        }

        // 새 비밀번호로 업데이트
        userRepository.updatePassword(username, passwordEncoder.encode(newPassword));
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        return userDetailsService.loadUserByUsername(username);
    }
    // ...
}
```

### 5. 캐싱 전략 — SpringCacheBasedUserCache

```java
// UserCache 활성화 설정
@Configuration
public class CacheConfig {

    @Bean
    public UserCache userCache() {
        return new SpringCacheBasedUserCache(userDetailsCache());
    }

    @Bean
    public Cache userDetailsCache() {
        // CaffeineCache: TTL 5분, 최대 1000개
        return new CaffeineCache("userDetails",
            Caffeine.newBuilder()
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .maximumSize(1000)
                .build());
    }
}

// DaoAuthenticationProvider에 캐시 주입
@Bean
public DaoAuthenticationProvider authenticationProvider(
        UserDetailsService userDetailsService,
        PasswordEncoder passwordEncoder,
        UserCache userCache) {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(userDetailsService);
    provider.setPasswordEncoder(passwordEncoder);
    provider.setUserCache(userCache); // 캐시 활성화
    return provider;
}

// 캐시 무효화 — 비밀번호 변경, 권한 변경 시 반드시 호출
@Service
@RequiredArgsConstructor
public class UserManagementService {

    private final UserRepository userRepository;
    private final UserCache userCache;

    public void updateUserRole(String username, String newRole) {
        userRepository.updateRole(username, newRole);
        userCache.removeUserFromCache(username); // 캐시 즉시 제거
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 각 플래그별 예외 발생 확인

```java
@ParameterizedTest
@MethodSource("userDetailsStatusProvider")
void testAccountStatusExceptions(UserDetails userDetails,
                                  Class<? extends Exception> expectedException) {
    when(userDetailsService.loadUserByUsername(any()))
        .thenReturn(userDetails);

    assertThatThrownBy(() ->
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken("user", "pass")))
        .isInstanceOf(expectedException);
}

static Stream<Arguments> userDetailsStatusProvider() {
    return Stream.of(
        Arguments.of(
            buildUser(false, true, true, true),   // enabled=false
            DisabledException.class),
        Arguments.of(
            buildUser(true, false, true, true),   // accountNonLocked=false
            LockedException.class),
        Arguments.of(
            buildUser(true, true, false, true),   // accountNonExpired=false
            AccountExpiredException.class),
        Arguments.of(
            buildUser(true, true, true, false),   // credentialsNonExpired=false
            CredentialsExpiredException.class)
    );
}
```

### 실험 2: 다중 식별자(이메일·전화번호) 로그인 테스트

```bash
# 사용자명으로 로그인
curl -X POST http://localhost:8080/login \
  -d "username=kim&password=1234"

# 이메일로 로그인 (동일한 loadUserByUsername 활용)
curl -X POST http://localhost:8080/login \
  -d "username=kim@example.com&password=1234"

# 전화번호로 로그인
curl -X POST http://localhost:8080/login \
  -d "username=01012345678&password=1234"

# 모두 같은 UserDetailsService.loadUserByUsername()을 통해 처리됨
```

### 실험 3: UserDetails 캐시 동작 확인

```java
@GetMapping("/debug/cache-test")
public Map<String, Object> cacheTest() {
    // 첫 번째 인증: DB 조회 발생
    long start = System.currentTimeMillis();
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken("kim", "1234"));
    long first = System.currentTimeMillis() - start;

    // 두 번째 인증: 캐시 히트 (DB 조회 없음)
    start = System.currentTimeMillis();
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken("kim", "1234"));
    long second = System.currentTimeMillis() - start;

    return Map.of(
        "first_ms", first,
        "second_ms", second,
        "cache_hit", second < first / 2
    );
}
```

---

## 🔒 보안 체크리스트

```
UserDetailsService 구현
  ☐ 사용자 없으면 UsernameNotFoundException throw (null 반환 절대 금지)
  ☐ 반환 UserDetails의 password가 인코딩된 해시인지 확인 (평문 금지)
  ☐ loadUserByUsername()에 @Transactional(readOnly=true) 적용 (JPA lazy loading 방지)

UserDetails 설계
  ☐ Serializable 구현 (HttpSession 직렬화를 위해 필수)
  ☐ serialVersionUID 명시적 선언 (클래스 변경 시 세션 호환성)
  ☐ 민감 정보(주민번호, 카드번호 등) 포함 금지
  ☐ 무거운 연관 객체(주문 목록 등) 포함 금지

4개 플래그 활용
  ☐ 로그인 실패 N회 시 isAccountNonLocked=false 처리 구현
  ☐ 이메일 미인증 시 isEnabled=false 처리
  ☐ 비밀번호 N일 경과 시 isCredentialsNonExpired=false 처리

캐싱
  ☐ 권한 변경 시 캐시 즉시 무효화
  ☐ 계정 잠금/비활성화 시 캐시 즉시 제거
  ☐ TTL을 짧게 설정 (기본 5분 이하 권장)
```

---

## 🤔 트레이드오프

```
UserDetails와 도메인 엔티티 분리 vs 통합:
  분리 (CustomUserDetails + User 엔티티):
    장점  Security 의존성이 도메인 계층에 침투하지 않음
          UserDetails 변경이 도메인 모델에 영향 없음
    단점  변환 코드(mapToUserDetails) 추가 필요
          두 객체 간 동기화 관리 필요

  통합 (User 엔티티가 UserDetails 구현):
    장점  변환 코드 불필요, 단순함
    단점  도메인 엔티티가 Spring Security에 강하게 결합
          테스트 시 Security 컨텍스트 필요
          UserDetails 인터페이스 변경 시 도메인 영향

loadUserByUsername() 성능:
  매 요청마다 DB 조회:
    장점  항상 최신 상태 (권한 변경 즉시 반영)
    단점  DB 부하 (특히 JWT Stateless 환경에서 매 요청 조회)
  캐싱:
    장점  DB 부하 감소
    단점  권한 변경 지연, 캐시 무효화 복잡성
```

---

## 📌 핵심 정리

```
UserDetailsService 계약
  loadUserByUsername(username): UserDetails
  → 사용자 없으면 UsernameNotFoundException (null 금지)
  → 반환값의 password는 인코딩된 해시

UserDetails 4개 플래그 검사 순서
  1. isAccountNonLocked   → false: LockedException (비밀번호 검증 전)
  2. isEnabled            → false: DisabledException
  3. isAccountNonExpired  → false: AccountExpiredException
  4. (비밀번호 검증)
  5. isCredentialsNonExpired → false: CredentialsExpiredException

UserDetailsManager = UserDetailsService + CRUD
  createUser, updateUser, deleteUser, changePassword, userExists
  실무에서는 JPA 기반 커스텀 구현이 일반적

캐싱 주의사항
  권한/계정상태 변경 시 userCache.removeUserFromCache() 필수
  TTL을 짧게 유지하여 불일치 시간 최소화
```

---

## 🤔 생각해볼 문제

**Q1.** `loadUserByUsername()`에 `@Transactional`을 붙이지 않으면 JPA 환경에서 어떤 문제가 발생할 수 있는가? `User` 엔티티의 `roles` 컬렉션이 `FetchType.LAZY`인 경우를 예로 들어 설명하라.

**Q2.** `isEnabled=false`인 사용자가 Remember-Me 쿠키로 자동 로그인을 시도하면 어떻게 되는가? `RememberMeAuthenticationFilter`와 `DaoAuthenticationProvider`의 상호작용을 설명하라.

**Q3.** 이메일 인증이 완료되지 않은 사용자를 로그인은 허용하되 특정 기능만 제한하고 싶다. `isEnabled=false`를 사용하면 로그인 자체가 막히므로 다른 접근 방법을 설계하라.

> 💡 **해설**
>
> **Q1.** `loadUserByUsername()`에 `@Transactional`이 없으면 메서드가 실행되는 시점에 영속성 컨텍스트가 없거나 이미 닫혀 있을 수 있습니다. `user.getRoles()`가 `LAZY`로 설정된 경우, 영속성 컨텍스트가 없는 상태에서 컬렉션에 접근하면 `LazyInitializationException`이 발생합니다. 해결 방법은 `@Transactional(readOnly=true)`를 추가하거나, JPQL로 `JOIN FETCH`를 사용해 즉시 로딩하거나, 권한을 별도 쿼리로 로드하는 방법이 있습니다. `readOnly=true`는 불필요한 dirty checking을 건너뛰어 성능 최적화에도 도움됩니다.
>
> **Q2.** Remember-Me 쿠키로 로그인 시 `RememberMeAuthenticationFilter`가 쿠키를 파싱하고 `RememberMeServices.autoLogin()`을 호출합니다. 이 과정에서 `UserDetailsService.loadUserByUsername()`이 호출되어 최신 `UserDetails`를 로드합니다. 반환된 `UserDetails`의 `isEnabled=false`이면 `AbstractUserDetailsAuthenticationProvider.preAuthenticationChecks()`에서 `DisabledException`이 발생합니다. `RememberMeAuthenticationFilter`는 이 예외를 catch하고 쿠키를 삭제한 뒤 `SecurityContext`를 초기화합니다. 즉, 계정 비활성화 시 Remember-Me 자동 로그인도 차단됩니다.
>
> **Q3.** 이메일 인증 미완료 사용자에게 로그인은 허용하되 기능을 제한하는 방법으로는 세 가지 접근이 있습니다. 첫째, `isEnabled=true`로 로그인은 허용하되 권한에 `ROLE_UNVERIFIED`만 부여하고, 이메일 인증 후 `ROLE_USER`로 업그레이드합니다. `ROLE_UNVERIFIED` 사용자는 `/verify-email` 페이지만 접근 가능하도록 `authorizeHttpRequests`에서 제한합니다. 둘째, `AuthenticationSuccessHandler`에서 인증 직후 이메일 인증 여부를 확인하고 미완료 시 인증 페이지로 리다이렉트합니다. 셋째, `@PreAuthorize`에 커스텀 SpEL 표현식을 만들어 `isEmailVerified()` 조건을 추가합니다. 첫 번째 방법이 가장 Spring Security 관용적입니다.

---

<div align="center">

**[← 이전: AuthenticationProvider 체인 동작](./02-authentication-provider-chain.md)** | **[홈으로 🏠](../README.md)** | **[다음: PasswordEncoder 종류와 선택 ➡️](./04-password-encoder.md)**

</div>
