# Authentication 객체 구조 — Principal·Credentials·Authorities와 인증 전·후 상태 변화

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `Authentication` 인터페이스의 `getPrincipal()`, `getCredentials()`, `getAuthorities()`는 각각 무엇을 반환하는가?
- `UsernamePasswordAuthenticationToken`이 인증 전과 인증 후에 다른 내부 상태를 갖는 이유는?
- `isAuthenticated()` 플래그는 누가 언제 `true`로 변경하는가?
- `Authentication`을 직접 `new`로 만들어 `SecurityContext`에 저장해도 되는가?
- `@AuthenticationPrincipal`이 `getPrincipal()`과 어떻게 연결되는가?
- 커스텀 `Authentication` 구현체를 만들어야 하는 경우는 언제인가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 다양한 인증 방식을 하나의 인터페이스로 추상화해야 한다

```
Spring Security가 지원하는 인증 방식:
  - 폼 로그인 (username + password)
  - HTTP Basic Auth
  - JWT Bearer Token
  - OAuth2 (소셜 로그인)
  - API Key
  - X.509 인증서
  - SAML2
  - OTP (일회용 비밀번호)

각 방식의 인증 결과를 서로 다른 타입으로 관리하면:
  FormLoginResult formResult = ...
  JwtResult jwtResult = ...
  OAuth2Result oauthResult = ...
  // AuthorizationFilter에서 모든 타입을 알아야 함
  if (result instanceof FormLoginResult) { ... }
  else if (result instanceof JwtResult) { ... }
  ...

해결: Authentication 인터페이스로 통일
  모든 인증 방식의 결과 = Authentication 구현체
  AuthorizationFilter는 Authentication만 알면 됨
  → 새 인증 방식 = 새 Authentication 구현체만 추가
```

---

## 😱 흔한 보안 실수

### Before: Credentials를 인증 후에도 보관

```java
// ❌ 보안 위험: 인증 완료 후 비밀번호를 Authentication에 유지
// 일부 커스텀 구현에서 Credentials를 지우지 않는 경우

// ProviderManager.authenticate() 기본 동작:
// eraseCredentialsAfterAuthentication = true (기본값)
// → 인증 성공 후 authentication.eraseCredentials() 호출
// → UsernamePasswordAuthenticationToken: credentials = null로 설정

// ❌ eraseCredentials를 false로 설정하면:
@Bean
public ProviderManager authenticationManager(
        AuthenticationProvider provider) {
    ProviderManager manager = new ProviderManager(provider);
    manager.setEraseCredentialsAfterAuthentication(false); // 위험!
    return manager;
}
// → authentication.getCredentials()에 평문 비밀번호가 유지됨
// → SecurityContext가 직렬화되어 HttpSession에 저장될 경우
//   세션 탈취 시 비밀번호 노출

// ✅ 기본값(eraseCredentialsAfterAuthentication=true) 유지 권장
```

### Before: isAuthenticated()를 직접 true로 설정해 인증 우회

```java
// ❌ 위험: 인증 절차 없이 isAuthenticated()만 강제로 true 설정
Authentication fakeAuth = new UsernamePasswordAuthenticationToken(
    "admin", null,
    List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
);
// 이 생성자는 이미 isAuthenticated()=true인 상태
// 아무 검증 없이 ADMIN 권한을 부여

SecurityContextHolder.getContext().setAuthentication(fakeAuth);
// → AuthorizationFilter에서 ADMIN으로 처리됨

// ✅ 올바른 방법: 반드시 AuthenticationManager를 통해 인증
Authentication auth = authenticationManager.authenticate(
    new UsernamePasswordAuthenticationToken(username, password)
    // 이 생성자: isAuthenticated() = false
    // AuthenticationManager가 검증 후 새 토큰 반환
    // 반환된 토큰: isAuthenticated() = true
);
SecurityContextHolder.getContext().setAuthentication(auth);
```

---

## ✨ 올바른 보안 구현

### Authentication 타입별 활용 패턴

```java
// Controller에서 Authentication 접근 방법

// 방법 1: 파라미터로 직접 주입 (Spring Security가 자동 주입)
@GetMapping("/profile")
public UserProfile getProfile(Authentication authentication) {
    String username = authentication.getName(); // getPrincipal().toString()
    return userService.findByUsername(username);
}

// 방법 2: @AuthenticationPrincipal — getPrincipal()의 타입 안전 버전
@GetMapping("/profile")
public UserProfile getProfile(
        @AuthenticationPrincipal CustomUserDetails userDetails) {
    // getPrincipal()이 CustomUserDetails 타입임을 보장
    Long userId = userDetails.getUserId();
    return userService.findById(userId);
}

// 방법 3: @AuthenticationPrincipal + SpEL — 필드 직접 추출
@GetMapping("/orders")
public List<Order> getOrders(
        @AuthenticationPrincipal(expression = "#this.userId") Long userId) {
    // CustomUserDetails.getUserId()를 직접 주입
    return orderService.findByUserId(userId);
}

// 방법 4: SecurityContextHolder에서 직접 (서비스 레이어에서 사용)
@Service
public class OrderService {
    public List<Order> getMyOrders() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails details = (CustomUserDetails) auth.getPrincipal();
        return orderRepository.findByUserId(details.getUserId());
    }
}
```

---

## 🔬 내부 동작 원리

### 1. Authentication 인터페이스 구조

```java
// Authentication.java
public interface Authentication extends Principal, Serializable {

    // 부여된 권한 목록 (ROLE_USER, ROLE_ADMIN 등)
    // 인증 전: null 또는 빈 컬렉션
    // 인증 후: UserDetails.getAuthorities()에서 가져온 권한 목록
    Collection<? extends GrantedAuthority> getAuthorities();

    // 인증에 사용된 자격증명
    // 폼 로그인: 비밀번호 (인증 완료 후 erase → null)
    // JWT: 토큰 문자열
    // 인증 완료 후 보안을 위해 null로 지워짐
    Object getCredentials();

    // 요청 관련 추가 정보 (요청 IP, 세션 ID 등)
    // 주로 WebAuthenticationDetails 인스턴스
    Object getDetails();

    // 인증 주체 — 가장 중요한 필드
    // 폼 로그인 후: UserDetails 객체 (또는 CustomUserDetails)
    // JWT: username 문자열 또는 커스텀 Principal 객체
    // @AuthenticationPrincipal이 이 값을 주입
    Object getPrincipal();

    // 이 Authentication이 인증 완료 상태인가?
    // false: AuthenticationManager에 전달하기 전 (인증 요청)
    // true:  AuthenticationManager가 검증 완료 후 반환 (인증 완료)
    boolean isAuthenticated();

    void setAuthenticated(boolean isAuthenticated)
            throws IllegalArgumentException;
}
```

### 2. UsernamePasswordAuthenticationToken — 인증 전/후 상태 변화

```java
// UsernamePasswordAuthenticationToken.java
public class UsernamePasswordAuthenticationToken
        extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    // ── 생성자 1: 인증 전 (인증 요청용) ──────────────────────────────
    // UsernamePasswordAuthenticationFilter에서 사용
    public UsernamePasswordAuthenticationToken(Object principal,
                                                Object credentials) {
        super(null); // authorities = null
        this.principal = principal;   // 입력된 username 문자열
        this.credentials = credentials; // 입력된 password 문자열
        setAuthenticated(false);      // ← 반드시 false (아직 검증 안 됨)
    }

    // ── 생성자 2: 인증 후 (인증 완료 결과용) ─────────────────────────
    // DaoAuthenticationProvider에서 검증 성공 후 생성
    public UsernamePasswordAuthenticationToken(Object principal,
                                                Object credentials,
                                                Collection<? extends GrantedAuthority> authorities) {
        super(authorities);           // authorities 설정
        this.principal = principal;   // UserDetails 객체 (전체 사용자 정보)
        this.credentials = credentials; // 비밀번호 (곧 erase됨)
        super.setAuthenticated(true); // ← true (검증 완료)
    }

    // isAuthenticated()를 외부에서 true로 변경 시도 시 예외 발생
    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        Assert.isTrue(!isAuthenticated,
            "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }
    // → 생성자 2를 통해서만 authenticated=true 가능
    // → setAuthenticated(true)를 직접 호출하면 IllegalArgumentException
}
```

### 3. DaoAuthenticationProvider — 인증 전 → 후 변환 과정

```java
// DaoAuthenticationProvider.java (핵심 흐름)
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Override
    protected Authentication createSuccessAuthentication(Object principal,
            Authentication authentication,
            UserDetails user) {
        // ① 비밀번호 업그레이드가 필요한지 확인 (DelegatingPasswordEncoder)
        boolean upgradeEncoding = this.userDetailsPasswordService != null
            && this.passwordEncoder.upgradeEncoding(user.getPassword());
        if (upgradeEncoding) {
            String newPassword = this.passwordEncoder.encode(
                (String) authentication.getCredentials());
            user = this.userDetailsPasswordService.updatePassword(user, newPassword);
        }

        // ② 인증 완료 토큰 생성 (생성자 2 사용 — isAuthenticated=true)
        UsernamePasswordAuthenticationToken result =
            UsernamePasswordAuthenticationToken.authenticated(
                principal,                   // UserDetails 객체
                authentication.getCredentials(), // 비밀번호 (곧 지워짐)
                this.authoritiesMapper.mapAuthorities(user.getAuthorities())
            );
        result.setDetails(authentication.getDetails()); // WebAuthenticationDetails 복사
        return result;
        // ③ ProviderManager로 반환 → eraseCredentials() 호출 → credentials = null
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) {
        // 비밀번호 검증
        if (!this.passwordEncoder.matches(
                (String) authentication.getCredentials(),
                userDetails.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }
    }
}
```

### 4. Authentication 구현체 계층 구조

```
Authentication (interface)
├── AbstractAuthenticationToken (abstract)
│   ├── UsernamePasswordAuthenticationToken  ← 폼 로그인, Basic Auth
│   ├── AnonymousAuthenticationToken         ← 미인증 사용자
│   ├── RememberMeAuthenticationToken        ← Remember-Me 쿠키
│   ├── JwtAuthenticationToken               ← JWT (Spring OAuth2 Resource Server)
│   ├── OAuth2AuthenticationToken            ← OAuth2 로그인
│   ├── BearerTokenAuthenticationToken       ← Bearer Token (인증 전)
│   └── PreAuthenticatedAuthenticationToken ← X.509, 사전인증
└── (커스텀 구현 가능)
    └── ApiKeyAuthenticationToken            ← API Key 인증 (커스텀 예시)
```

### 5. WebAuthenticationDetails — getDetails()의 실제 내용

```java
// WebAuthenticationDetails.java
public class WebAuthenticationDetails implements Serializable {

    private final String remoteAddress; // 클라이언트 IP 주소
    private final String sessionId;     // HTTP 세션 ID

    public WebAuthenticationDetails(HttpServletRequest request) {
        this.remoteAddress = request.getRemoteAddr();
        HttpSession session = request.getSession(false);
        this.sessionId = (session != null) ? session.getId() : null;
    }
}

// UsernamePasswordAuthenticationFilter에서 details 설정:
// authRequest.setDetails(authenticationDetailsSource.buildDetails(request))
// → WebAuthenticationDetails(request) 생성

// 활용 예: IP 기반 접근 제한
@Component
public class IpRestrictionAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) {
        WebAuthenticationDetails details =
            (WebAuthenticationDetails) authentication.getDetails();
        if (!isAllowedIp(details.getRemoteAddress())) {
            throw new AuthenticationServiceException("Access from this IP is not allowed");
        }
        // ... 나머지 인증 로직
    }
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 인증 전·후 Authentication 상태 비교

```java
@PostMapping("/debug/auth-state")
public Map<String, Object> debugAuthState(@RequestBody LoginRequest request,
                                           HttpServletRequest httpRequest) {
    Map<String, Object> result = new LinkedHashMap<>();

    // 인증 전 토큰
    UsernamePasswordAuthenticationToken before =
        new UsernamePasswordAuthenticationToken(
            request.getUsername(), request.getPassword());

    result.put("before_isAuthenticated", before.isAuthenticated()); // false
    result.put("before_principal_type", before.getPrincipal().getClass().getSimpleName()); // String
    result.put("before_authorities", before.getAuthorities()); // []

    // 인증 수행
    Authentication after = authenticationManager.authenticate(before);

    result.put("after_isAuthenticated", after.isAuthenticated()); // true
    result.put("after_principal_type", after.getPrincipal().getClass().getSimpleName()); // CustomUserDetails
    result.put("after_credentials", after.getCredentials()); // null (erased)
    result.put("after_authorities", after.getAuthorities()); // [ROLE_USER]

    return result;
}
```

### 실험 2: @AuthenticationPrincipal 타입 확인

```java
// CustomUserDetails 구현
@Getter
public class CustomUserDetails implements UserDetails {
    private final Long userId;
    private final String username;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;

    // ...
}

// Controller에서 타입 안전하게 사용
@GetMapping("/me")
public Map<String, Object> me(
        @AuthenticationPrincipal CustomUserDetails userDetails) {

    return Map.of(
        "userId", userDetails.getUserId(),
        "username", userDetails.getUsername(),
        "authorities", userDetails.getAuthorities()
    );
}
```

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/me
# → {"userId":42,"username":"kim","authorities":["ROLE_USER"]}
```

### 실험 3: AnonymousAuthenticationToken 확인

```java
@GetMapping("/who-am-i")
public Map<String, Object> whoAmI(Authentication auth) {
    return Map.of(
        "type", auth.getClass().getSimpleName(),
        "name", auth.getName(),
        "isAuthenticated", auth.isAuthenticated(),
        "authorities", auth.getAuthorities()
    );
}
```

```bash
# 인증 없이 접근 (AnonymousAuthenticationFilter가 삽입한 Authentication)
curl http://localhost:8080/who-am-i
# → {"type":"AnonymousAuthenticationToken","name":"anonymousUser",
#    "isAuthenticated":true,"authorities":["ROLE_ANONYMOUS"]}
# 주의: isAuthenticated=true이지만 principal="anonymousUser" 문자열

# 인증 후 접근
curl -H "Authorization: Bearer <token>" http://localhost:8080/who-am-i
# → {"type":"UsernamePasswordAuthenticationToken","name":"kim",
#    "isAuthenticated":true,"authorities":["ROLE_USER"]}
```

---

## 🔒 보안 체크리스트

```
Authentication 생성
  ☐ 인증 요청용 토큰은 반드시 credentials-only 생성자 사용 (isAuthenticated=false)
  ☐ 인증 완료 토큰은 반드시 AuthenticationManager를 통해 생성
  ☐ setAuthenticated(true)를 직접 호출하지 않음

Credentials 관리
  ☐ ProviderManager.eraseCredentialsAfterAuthentication=true (기본값) 유지
  ☐ 커스텀 Authentication 구현 시 eraseCredentials() 메서드에서 민감 정보 null 처리

Principal 설계
  ☐ getPrincipal()이 UserDetails 구현체를 반환하도록 설계
  ☐ userId, email 등 자주 사용하는 필드를 커스텀 UserDetails에 포함
  ☐ getPrincipal()에서 민감한 정보(비밀번호, 개인정보) 반환 금지
```

---

## 🤔 트레이드오프

```
getPrincipal()에 UserDetails 전체 반환 vs userId만 반환:
  UserDetails 전체 반환:
    장점  @AuthenticationPrincipal로 모든 사용자 정보 즉시 접근 가능
          DB 추가 조회 없이 Controller 처리 가능
    단점  SecurityContext 직렬화 시 UserDetails 전체가 HttpSession에 저장
          사용자 정보 변경 시 세션의 UserDetails와 DB 불일치 가능

  userId만 반환:
    장점  SecurityContext 경량화 (세션 크기 감소)
          최신 사용자 정보를 항상 DB에서 조회
    단점  매 요청마다 DB 조회 필요 → 캐시 전략 필요

커스텀 Authentication 구현:
  필요한 경우  표준 Authentication 타입이 담을 수 없는 인증 컨텍스트가 필요할 때
               (API Key + 테넌트 ID 조합, OTP 상태 등)
  위험성       isAuthenticated() 구현을 잘못하면 인증 우회 가능
               반드시 AbstractAuthenticationToken을 상속해서 구현할 것
```

---

## 📌 핵심 정리

```
Authentication 인터페이스 핵심 메서드
  getPrincipal()    → 인증된 사용자 (UserDetails 또는 username)
  getCredentials()  → 인증 수단 (비밀번호 등 — 인증 후 null)
  getAuthorities()  → 권한 목록 (ROLE_USER, ROLE_ADMIN 등)
  isAuthenticated() → 인증 완료 여부

UsernamePasswordAuthenticationToken 두 가지 상태
  인증 전: new UPAT(username, password)          → isAuthenticated=false, principal=String
  인증 후: new UPAT(userDetails, null, roles)    → isAuthenticated=true, principal=UserDetails
  → 생성자 선택으로 상태 강제 (setAuthenticated(true) 호출 불가)

@AuthenticationPrincipal
  getPrincipal()을 타입 안전하게 Controller 파라미터로 주입
  expression으로 특정 필드만 추출 가능

eraseCredentials
  인증 완료 후 credentials(비밀번호)를 null로 자동 제거
  기본값 true — 변경 금지
```

---

## 🤔 생각해볼 문제

**Q1.** `AnonymousAuthenticationToken`의 `isAuthenticated()`는 `true`를 반환합니다. 이것이 `UsernamePasswordAuthenticationToken(isAuthenticated=true)`와 어떻게 구별되는가? `ExceptionTranslationFilter`는 이 두 가지를 어떻게 다르게 처리하는가?

**Q2.** `CustomUserDetails`를 `getPrincipal()`에 저장하고 이 객체가 `HttpSession`에 직렬화되는 경우, 배포 중 `CustomUserDetails` 클래스가 변경되면 어떤 문제가 발생하는가? 이를 방지하는 전략은 무엇인가?

**Q3.** JWT 인증 환경에서 `UsernamePasswordAuthenticationToken` 대신 커스텀 `JwtAuthenticationToken`을 만드는 경우와 만들지 않는 경우의 트레이드오프는 무엇인가?

> 💡 **해설**
>
> **Q1.** `AnonymousAuthenticationToken`은 `AuthenticationTrustResolver.isAnonymous()` 메서드로 구별됩니다. 이 메서드는 `Authentication` 타입이 `AnonymousAuthenticationToken` 인지를 확인합니다. `ExceptionTranslationFilter`에서 `AccessDeniedException`이 발생했을 때, `isAnonymous(auth)` 또는 `isRememberMe(auth)`가 `true`이면 인증 필요 상태로 판단해 로그인 페이지로 리다이렉트하거나 `AuthenticationEntryPoint`를 호출합니다. 반면 `UsernamePasswordAuthenticationToken(isAuthenticated=true)`이면 이미 인증된 사용자의 권한 부족으로 판단해 `AccessDeniedHandler`를 호출합니다(403 응답).
>
> **Q2.** `CustomUserDetails`에 `serialVersionUID`가 선언되지 않은 상태에서 필드가 추가·삭제·변경되면 JVM이 자동 계산하는 `serialVersionUID`가 달라집니다. 기존 세션에 직렬화된 객체를 역직렬화할 때 `InvalidClassException`이 발생하고 세션이 무효화됩니다. 이를 방지하는 전략은 세 가지입니다. 첫째, `serialVersionUID`를 명시적으로 고정합니다. 둘째, `UserDetails`에 최소한의 불변 필드만 포함하고 자주 변경되는 데이터는 DB에서 조회합니다. 셋째, Spring Session Redis 등을 사용해 세션 저장 형식을 JSON으로 변경하면 직렬화 문제를 회피할 수 있습니다.
>
> **Q3.** `UsernamePasswordAuthenticationToken`을 재사용하는 경우: 구현이 간단하고 기존 `@PreAuthorize`, `@AuthenticationPrincipal` 등과 바로 호환됩니다. 단, JWT의 `Claims` 정보(커스텀 클레임, 발급자 등)를 저장할 공간이 없어 별도 조회가 필요합니다. 커스텀 `JwtAuthenticationToken`을 만드는 경우: `Claims` 전체를 `Authentication`에 포함시켜 매 요청마다 DB 조회 없이 정보를 사용할 수 있습니다. 단, `AbstractAuthenticationToken`을 올바르게 상속해야 하며 `isAuthenticated()` 구현에 주의가 필요합니다. Spring Security OAuth2 Resource Server의 `JwtAuthenticationToken`을 활용하면 커스텀 구현 없이 Claims를 `Authentication`에 담을 수 있습니다.

---

<div align="center">

**[← 이전: SecurityContext & SecurityContextHolder](./04-security-context-holder.md)** | **[홈으로 🏠](../README.md)** | **[다음: GrantedAuthority vs Role 차이 ➡️](./06-granted-authority-vs-role.md)**

</div>
