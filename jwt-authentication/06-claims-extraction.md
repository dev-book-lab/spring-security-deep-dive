# Claims 추출과 사용 — @AuthenticationPrincipal과 JwtAuthenticationToken 패턴

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- Filter 이후 Controller에서 `@AuthenticationPrincipal`로 커스텀 `UserDetails`를 주입받는 내부 동작은?
- `JwtAuthenticationToken`을 커스텀 구현해 Claims를 직접 principal로 사용하는 패턴은?
- `UsernamePasswordAuthenticationToken` vs 커스텀 `JwtAuthenticationToken` 중 언제 무엇을 선택하는가?
- `@AuthenticationPrincipal(expression = "...")` SpEL로 중첩 필드를 추출하는 방법은?
- DB 조회 없이 JWT 클레임만으로 SecurityContext를 구성하는 경우 principal의 구조는?
- 다양한 API에서 일관성 있게 현재 사용자 정보를 사용하는 패턴은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### Controller에서 인증 정보에 접근하는 방법이 왜 중요한가

```
나쁜 패턴: 모든 메서드에서 SecurityContextHolder 직접 접근
  @GetMapping("/api/orders")
  public List<Order> getOrders() {
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails user = (CustomUserDetails) auth.getPrincipal();
      return orderService.getByUserId(user.getUserId());
  }
  문제:
  → 보일러플레이트 반복
  → 캐스팅 실패 가능 (principal 타입 불일치)
  → 테스트에서 SecurityContext 설정 필요

좋은 패턴: @AuthenticationPrincipal로 선언적 주입
  @GetMapping("/api/orders")
  public List<Order> getOrders(
          @AuthenticationPrincipal CustomUserDetails user) {
      return orderService.getByUserId(user.getUserId());
  }
  장점:
  → 메서드 시그니처에서 의존성 명확
  → Spring이 타입 안전하게 주입
  → 테스트에서 @WithMockUser, @WithUserDetails 활용
```

---

## 😱 흔한 보안 실수

### Before: principal 캐스팅 시 ClassCastException

```java
// ❌ principal 타입 검증 없이 캐스팅
@GetMapping("/api/profile")
public Profile getProfile(Authentication authentication) {
    CustomUserDetails user =
        (CustomUserDetails) authentication.getPrincipal(); // 타입 불일치 시 예외
    // JWT 클레임에서 직접 생성한 경우 UserDetails 타입이 아닐 수 있음
    return profileService.get(user.getUserId());
}

// ✅ @AuthenticationPrincipal로 타입 안전하게 주입
@GetMapping("/api/profile")
public Profile getProfile(
        @AuthenticationPrincipal CustomUserDetails user) {
    // null 체크: 미인증 요청에서 null일 수 있음
    if (user == null) throw new UnauthorizedException("인증이 필요합니다.");
    return profileService.get(user.getUserId());
}
```

### Before: Claims를 매번 파싱해서 사용

```java
// ❌ Controller에서 직접 토큰 파싱
@GetMapping("/api/orders")
public List<Order> getOrders(HttpServletRequest request) {
    String token = request.getHeader("Authorization").substring(7);
    Claims claims = jwtTokenProvider.getClaims(token); // 이미 필터에서 파싱함
    Long userId = claims.get("userId", Long.class);    // 중복 파싱
    return orderService.getByUserId(userId);
}

// ✅ SecurityContext의 principal에서 추출 (필터에서 이미 파싱 완료)
@GetMapping("/api/orders")
public List<Order> getOrders(
        @AuthenticationPrincipal CustomUserDetails user) {
    return orderService.getByUserId(user.getUserId()); // 추가 파싱 없음
}
```

---

## ✨ 올바른 보안 구현

### 패턴 1: CustomUserDetails를 principal로 사용 (DB 조회 방식)

```java
// UserDetails 구현
@Getter
public class CustomUserDetails implements UserDetails {

    private final Long userId;
    private final String username;
    private final String email;
    private final Collection<GrantedAuthority> authorities;

    // UserDetails 필수 구현
    @Override public Collection<? extends GrantedAuthority> getAuthorities() { return authorities; }
    @Override public String getPassword() { return null; } // JWT에서 불필요
    @Override public String getUsername() { return username; }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}

// JwtAuthenticationFilter에서:
UserDetails userDetails = userDetailsService.loadUserByUsername(username);
// UserDetailsService가 CustomUserDetails를 반환
UsernamePasswordAuthenticationToken auth =
    UsernamePasswordAuthenticationToken.authenticated(
        userDetails, null, userDetails.getAuthorities());
// → authentication.getPrincipal() = CustomUserDetails

// Controller:
@RestController
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;

    @GetMapping("/api/orders")
    public List<Order> getOrders(
            @AuthenticationPrincipal CustomUserDetails user) {
        return orderService.getByUserId(user.getUserId());
    }

    // SpEL로 특정 필드만 추출
    @GetMapping("/api/orders/count")
    public long countOrders(
            @AuthenticationPrincipal(expression = "userId") Long userId) {
        return orderService.countByUserId(userId);
    }

    // Authentication 전체 주입 (여러 필드 필요 시)
    @GetMapping("/api/me")
    public UserInfo me(Authentication authentication) {
        CustomUserDetails user =
            (CustomUserDetails) authentication.getPrincipal();
        WebAuthenticationDetails details =
            (WebAuthenticationDetails) authentication.getDetails();
        return UserInfo.of(user, details.getRemoteAddress());
    }
}
```

### 패턴 2: Claims를 직접 principal로 사용 (DB 조회 없는 방식)

```java
// 커스텀 JwtAuthenticationToken
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Claims claims; // JWT Claims를 principal로 직접 사용

    public JwtAuthenticationToken(Claims claims,
                                   Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.claims = claims;
        setAuthenticated(true); // 검증 완료
    }

    @Override
    public Object getCredentials() { return null; }

    @Override
    public Claims getPrincipal() { return claims; } // Claims 반환

    // 편의 메서드
    public Long getUserId() {
        return claims.get("userId", Long.class);
    }

    public String getUsername() {
        return claims.getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles() {
        return claims.get("roles", List.class);
    }
}

// JwtAuthenticationFilter에서:
Claims claims = jwtTokenProvider.getClaims(token);
List<SimpleGrantedAuthority> authorities = getRoles(claims).stream()
    .map(SimpleGrantedAuthority::new)
    .collect(Collectors.toList());

JwtAuthenticationToken auth = new JwtAuthenticationToken(claims, authorities);
SecurityContextHolder.getContext().setAuthentication(auth);

// Controller:
@GetMapping("/api/orders")
public List<Order> getOrders(
        @AuthenticationPrincipal Claims claims) { // Claims 직접 주입
    Long userId = claims.get("userId", Long.class);
    return orderService.getByUserId(userId);
}

// 또는 JwtAuthenticationToken 전체 주입
@GetMapping("/api/me")
public UserInfo me(JwtAuthenticationToken authentication) {
    return UserInfo.of(
        authentication.getUserId(),
        authentication.getUsername(),
        authentication.getAuthorities()
    );
}
```

### 패턴 3: @CurrentUser 커스텀 어노테이션

```java
// 커스텀 어노테이션 정의
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@AuthenticationPrincipal
public @interface CurrentUser {
}

// Controller에서 사용:
@GetMapping("/api/orders")
public List<Order> getOrders(@CurrentUser CustomUserDetails user) {
    return orderService.getByUserId(user.getUserId());
}
// @AuthenticationPrincipal과 동일한 동작, 더 명확한 의미

// @CurrentUser(expression = "userId") 변형:
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@AuthenticationPrincipal(expression = "userId")
public @interface CurrentUserId {
}

@GetMapping("/api/my-profile")
public Profile getProfile(@CurrentUserId Long userId) {
    return profileService.get(userId);
}
```

---

## 🔬 내부 동작 원리

### 1. AuthenticationPrincipalArgumentResolver 내부 동작

```java
// AuthenticationPrincipalArgumentResolver.resolveArgument() 내부:

public Object resolveArgument(MethodParameter parameter, ...) {
    // ① SecurityContextHolder에서 Authentication 조회
    Authentication authentication =
        SecurityContextHolder.getContext().getAuthentication();

    if (authentication == null) return null; // 미인증 → null 반환

    // ② principal 추출
    Object principal = authentication.getPrincipal();

    // ③ @AuthenticationPrincipal(expression = "...")이 있으면 SpEL 평가
    AuthenticationPrincipal annotation =
        findMethodAnnotation(AuthenticationPrincipal.class, parameter);

    if (StringUtils.hasLength(annotation.expression())) {
        // SpEL 평가: expression = "userId"
        // → principal.getUserId() 호출
        StandardEvaluationContext context = new StandardEvaluationContext(principal);
        principal = expressionParser
            .parseExpression(annotation.expression())
            .getValue(context);
    }

    // ④ 파라미터 타입과 주입 값의 타입 검증
    if (principal == null) {
        return null; // errorOnInvalidType=false (기본): null 허용
    }

    if (!parameter.getParameterType().isInstance(principal)) {
        // errorOnInvalidType=true일 때만 예외
        if (annotation.errorOnInvalidType()) {
            throw new ClassCastException("...");
        }
        return null; // 타입 불일치 → null
    }

    return principal;
}
```

### 2. CustomUserDetails 등록 — UserDetailsService

```java
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(
                "User not found: " + username));

        return CustomUserDetails.builder()
            .userId(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .authorities(user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList()))
            .enabled(user.isActive())
            .accountNonLocked(!user.isLocked())
            .build();
    }
}
// → authentication.getPrincipal() = CustomUserDetails
// → @AuthenticationPrincipal CustomUserDetails 주입 성공
```

### 3. 전역 사용자 정보 접근 — AOP + SecurityContextHolder

```java
// 서비스 레이어에서 현재 사용자 접근 (Controller가 아닌 경우)
@Component
public class SecurityUtils {

    public static CustomUserDetails getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new UnauthorizedException("인증이 필요합니다.");
        }
        return (CustomUserDetails) auth.getPrincipal();
    }

    public static Long getCurrentUserId() {
        return getCurrentUser().getUserId();
    }

    public static boolean hasRole(String role) {
        return SecurityContextHolder.getContext().getAuthentication()
            .getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + role));
    }
}

// Service에서 사용:
@Service
public class OrderService {
    public void createOrder(OrderRequest request) {
        Long userId = SecurityUtils.getCurrentUserId();
        // ...
    }
}
// 주의: AOP로 @AuthenticationPrincipal처럼 주입하는 것이 더 명시적
// SecurityUtils는 Service 레이어에서 필요한 경우 사용
```

### 4. 두 패턴 비교 — UserDetails vs Claims

```
UserDetails 방식 (DB 조회):
  필터:     loadUserByUsername() → DB 조회 → CustomUserDetails
  principal: CustomUserDetails (풍부한 사용자 정보)
  장점:     계정 상태 실시간 확인, 타입 안전
  단점:     매 요청 DB 조회 (성능)
  적합:     보안 중요 API, 계정 상태 변경 즉시 반영 필요

Claims 직접 방식 (DB 조회 없음):
  필터:     getClaims(token) → Claims
  principal: Claims (JWT에 포함된 정보만)
  장점:     DB 조회 없음 → 빠름, 확장성 우수
  단점:     계정 정지/권한 변경이 즉시 반영 안 됨
  적합:     고성능 API, 계정 상태 변경이 드문 서비스

@AuthenticationPrincipal 주입 타입:
  UserDetails 방식: @AuthenticationPrincipal CustomUserDetails user
  Claims 방식:      @AuthenticationPrincipal Claims claims
  JwtAuthToken 방식: JwtAuthenticationToken (파라미터 타입으로 직접 주입)
```

---

## 💻 실험으로 확인하기

### 실험 1: @AuthenticationPrincipal 주입 테스트

```java
@SpringBootTest
@AutoConfigureMockMvc
class AuthPrincipalTest {

    @Test
    @WithMockUser(username = "kim", roles = "USER")
    void authPrincipal_injected_correctly() throws Exception {
        mockMvc.perform(get("/api/me"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("kim"));
    }

    @Test
    void noAuth_authPrincipal_isNull() throws Exception {
        mockMvc.perform(get("/api/me"))
            .andExpect(status().isUnauthorized());
    }
}
```

### 실험 2: @WithUserDetails로 커스텀 UserDetails 테스트

```java
@SpringBootTest
@AutoConfigureMockMvc
class CustomUserDetailsTest {

    @Test
    @WithUserDetails(value = "kim", userDetailsServiceBeanName = "customUserDetailsService")
    void customUserDetails_injected_with_userId() throws Exception {
        mockMvc.perform(get("/api/profile"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userId").isNumber());
    }
}
```

### 실험 3: SpEL expression 동작 확인

```java
@Test
@WithMockUser(username = "kim")
void authPrincipalExpression_extractsField() throws Exception {
    // @AuthenticationPrincipal(expression = "username")
    mockMvc.perform(get("/api/username-only"))
        .andExpect(status().isOk())
        .andExpect(content().string("kim"));
}

// Controller:
@GetMapping("/api/username-only")
public String usernameOnly(
        @AuthenticationPrincipal(expression = "username") String username) {
    return username;
}
```

---

## 🔒 보안 체크리스트

```
@AuthenticationPrincipal 사용
  ☐ null 체크 또는 (required = false) 명시적 처리
  ☐ 미인증 요청에 null이 주입되는 경우 처리
  ☐ 타입 불일치 시 errorOnInvalidType=true 설정 검토

principal 설계
  ☐ UserDetails 구현 시 getPassword() → null 반환 (JWT 환경)
  ☐ equals()/hashCode() username 기반 구현 (SessionRegistry 정상 동작)
  ☐ Serializable 구현 (세션 직렬화 필요 시)

서비스 레이어
  ☐ SecurityUtils.getCurrentUser() 남용 금지 (테스트 어려움)
  ☐ 가능하면 파라미터로 전달받는 설계 권장
  ☐ AOP에서 SecurityContextHolder 접근 시 스레드 전략 확인
```

---

## 🤔 트레이드오프

```
UserDetails DB 조회 vs Claims 직접 사용:
  DB 조회:
    장점  계정 상태 최신, 타입 안전한 도메인 객체
    단점  모든 요청에 DB 조회 → 확장성 저하

  Claims 직접:
    장점  DB 조회 없음 → 확장성 우수
    단점  Claims 타입 캐스팅, 계정 변경 즉시 반영 안 됨

@CurrentUser vs @AuthenticationPrincipal:
  @CurrentUser (커스텀):
    장점  도메인 의미 명확, 코드 가독성 향상
    단점  추가 어노테이션 정의 필요

  @AuthenticationPrincipal (내장):
    장점  Spring 내장, 별도 정의 불필요
    단점  어노테이션만으로 의도 파악 어려움

SecurityUtils.getCurrentUser() vs 파라미터 전달:
  SecurityUtils (암묵적):
    장점  파라미터 없이 어디서나 접근
    단점  Service 계층이 Security에 결합 → 테스트 어려움

  파라미터 전달 (명시적):
    장점  의존성 명확, 단위 테스트 용이
    단점  메서드 시그니처 변경 필요
    → 권장: Controller에서 추출 후 Service로 전달
```

---

## 📌 핵심 정리

```
@AuthenticationPrincipal 동작
  AuthenticationPrincipalArgumentResolver
  → SecurityContextHolder.getContext().getAuthentication().getPrincipal()
  → expression SpEL 평가 (있는 경우)
  → 타입 검증 후 파라미터로 주입

principal 타입 결정
  UserDetails 방식: loadUserByUsername() → CustomUserDetails
  Claims 방식: getClaims() → Claims → JwtAuthenticationToken.getPrincipal()

두 패턴 선택 기준
  계정 상태 실시간 필요 → UserDetails (DB 조회)
  고성능, 계정 상태 변경 드문 경우 → Claims 직접

@CurrentUser 패턴
  @AuthenticationPrincipal을 래핑한 커스텀 어노테이션
  → 도메인 의미 명확, 코드 가독성 향상
```

---

## 🤔 생각해볼 문제

**Q1.** `@AuthenticationPrincipal CustomUserDetails user`에서 미인증 요청(JWT 없음)이 들어오면 `user`는 `null`입니다. `@AuthenticationPrincipal(expression = "userId")`를 사용하는 경우 `user`가 null일 때 SpEL 평가는 어떻게 되는가? NullPointerException이 발생하는가?

**Q2.** `CustomUserDetails`가 `equals()`와 `hashCode()`를 오버라이드하지 않은 상태에서 `SessionRegistryImpl`을 함께 사용하면 어떤 문제가 생기는가? JWT Stateless 환경에서는 이 문제가 발생하지 않는 이유는?

**Q3.** `JwtAuthenticationToken`을 커스텀으로 구현해 Claims를 principal로 사용하는 경우, `@PreAuthorize("@beanName.check(#userId, authentication)")`처럼 SpEL에서 `authentication`을 사용할 때 `authentication.getPrincipal()`의 타입이 `Claims`임을 어떻게 처리해야 하는가?

> 💡 **해설**
>
> **Q1.** `@AuthenticationPrincipal(expression = "userId")`에서 principal이 null이면 SpEL 평가의 루트 객체가 null이 됩니다. `DefaultListableBeanFactory`의 SpEL 컨텍스트는 null 루트 객체에 대한 프로퍼티 접근 시 `SpelEvaluationException`을 발생시킵니다. 이를 방지하려면 `@AuthenticationPrincipal(expression = "userId", errorOnInvalidType = false)`로 설정하거나, 해당 엔드포인트가 항상 인증을 요구하도록 `authorizeHttpRequests`에서 `authenticated()`를 설정합니다. 또는 `expression`에 null-safe 연산자를 사용할 수 있습니다: `@AuthenticationPrincipal(expression = "#root?.userId")`. `?`는 SpEL의 null-safe 네비게이션 연산자로 null이면 null을 반환합니다.
>
> **Q2.** `SessionRegistryImpl`은 `principals` Map에 실제 principal 객체를 키로 사용합니다. `equals()`가 오버라이드되지 않으면 `Object.equals()`(참조 동일성)가 사용되어, 같은 사용자도 매 요청마다 새 `CustomUserDetails` 객체가 생성되면 다른 키로 인식됩니다. 결과적으로 동일 사용자의 세션이 `principals` Map에 여러 개의 다른 키로 쌓여 동시 세션 제한이 동작하지 않습니다. JWT Stateless 환경에서는 `SecurityContextHolder`가 요청마다 초기화되고 세션에 SecurityContext를 저장하지 않으므로 `SessionRegistry`를 사용하지 않습니다. 따라서 이 문제가 발생하지 않습니다. 단, 세션 기반 인증과 함께 사용하거나 `SessionRegistry`로 로그인 사용자 목록을 관리하려면 `username` 기반의 `equals()/hashCode()` 구현이 필수입니다.
>
> **Q3.** `@beanName.check(#userId, authentication)`에서 `authentication.getPrincipal()`의 반환 타입이 `Claims`이므로, 빈의 `check()` 메서드 파라미터 타입도 이에 맞춰야 합니다. `check(Long userId, Authentication authentication)` 시그니처를 사용하고 내부에서 `(Claims) authentication.getPrincipal()`로 캐스팅하거나, `JwtAuthenticationToken`으로 캐스팅 후 `getUserId()`를 사용합니다. 또는 `authentication.getName()`(= username)을 사용해 username 기반으로 처리하면 인증 토큰 타입과 무관하게 동작합니다. 가장 안전한 방법은 `instanceof` 검사를 포함하는 것입니다: `if (authentication instanceof JwtAuthenticationToken jwtAuth) { ... }`.

---

<div align="center">

**[← 이전: Refresh Token 전략 (RTR)](./05-refresh-token-rotation.md)** | **[홈으로 🏠](../README.md)** | **[다음: JWT Token 만료 및 갱신 처리 ➡️](./07-jwt-expiry-handling.md)**

</div>
