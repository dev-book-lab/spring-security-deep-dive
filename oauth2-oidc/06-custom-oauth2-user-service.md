# Custom OAuth2UserService 작성 — 소셜 계정과 DB 사용자 연결 패턴

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `DefaultOAuth2UserService`를 확장해 소셜 계정을 DB 사용자와 연결하는 구현 패턴은?
- 첫 소셜 로그인 시 회원가입을 처리하는 올바른 방법은?
- `OAuth2User`와 `UserDetails`를 통합한 커스텀 principal 클래스 설계는?
- 제공자(Google, Kakao, Naver)별로 다른 속성 구조를 통합 처리하는 방법은?
- `OidcUserService`와 `DefaultOAuth2UserService`의 차이는? OpenID Connect에서 ID Token은 어떻게 처리되는가?
- `OAuth2UserService`에서 발생한 예외가 인증 흐름에 어떤 영향을 주는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### DefaultOAuth2UserService만으로는 부족한 이유

```
DefaultOAuth2UserService의 한계:
  → UserInfo를 받아 DefaultOAuth2User를 생성하는 것까지만 처리
  → DB에 사용자 정보 저장: 직접 구현 필요
  → 첫 로그인 시 회원가입: 직접 구현 필요
  → 기존 계정과 소셜 계정 연결: 직접 구현 필요
  → 권한(ROLE) 부여: 직접 구현 필요

실무에서 필요한 것:
  소셜 로그인 성공 →
  1. DB에서 이메일로 기존 회원 조회
  2. 있으면: 소셜 계정 정보 업데이트 (프로필 사진 등)
  3. 없으면: 새 회원 생성 (회원가입)
  4. DB 역할 기반 권한 부여
  5. 커스텀 principal 반환 (userId, email, roles 포함)
```

---

## 😱 흔한 보안 실수

### Before: 소셜 이메일만으로 기존 계정에 자동 연결

```java
// ❌ 이메일 인증 없이 소셜 이메일 = 기존 이메일로 자동 연결
// 공격자: 같은 이메일로 소셜 계정 생성 가능 (일부 소셜 제공자)
// → 타인 계정에 무단 접근

@Override
public OAuth2User loadUser(OAuth2UserRequest userRequest) {
    OAuth2User oAuth2User = super.loadUser(userRequest);
    String email = oAuth2User.getAttribute("email");
    // ← 이메일만으로 자동 연결: 보안 위험!
    User user = userRepository.findByEmail(email)
        .orElseGet(() -> registerNewUser(oAuth2User));
    return CustomOAuth2User.of(user, oAuth2User);
}

// ✅ 이메일 검증 여부 확인 후 연결
@Override
public OAuth2User loadUser(OAuth2UserRequest userRequest) {
    OAuth2User oAuth2User = super.loadUser(userRequest);
    String email = oAuth2User.getAttribute("email");
    Boolean emailVerified = oAuth2User.getAttribute("email_verified");

    // Google: email_verified=true 필수 확인
    if (!Boolean.TRUE.equals(emailVerified)) {
        throw new OAuth2AuthenticationException("Email not verified");
    }

    // 이메일 인증된 경우에만 기존 계정 연결
    User user = userRepository.findByEmail(email)
        .orElseGet(() -> registerNewUser(oAuth2User, userRequest));
    return CustomOAuth2User.of(user, oAuth2User);
}
```

### Before: OidcUserService와 OAuth2UserService 혼용 오류

```java
// ❌ OIDC 제공자(Google)에도 DefaultOAuth2UserService 사용
// OIDC 제공자는 OidcUserService를 사용해야 ID Token이 처리됨
http.oauth2Login(oauth2 -> oauth2
    .userInfoEndpoint(userInfo -> userInfo
        .userService(customOAuth2UserService)    // Google에도 이걸로 설정
        // ← OIDC ID Token이 무시됨
    )
);

// ✅ OIDC와 non-OIDC 구분
http.oauth2Login(oauth2 -> oauth2
    .userInfoEndpoint(userInfo -> userInfo
        .userService(customOAuth2UserService)    // 비OIDC (Kakao, Naver, GitHub)
        .oidcUserService(customOidcUserService)  // OIDC (Google, Apple)
    )
);
```

---

## ✨ 올바른 보안 구현

### CustomOAuth2UserService 완전 구현

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final SocialAccountRepository socialAccountRepository;
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // ① 소셜 제공자에서 사용자 정보 로드 (UserInfo Endpoint 호출)
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // ② 제공자별 속성 추출 (OAuthAttributes: 정규화 객체)
        OAuthAttributes attributes = OAuthAttributes.of(
            registrationId,
            userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint()
                .getUserNameAttributeName(),
            oAuth2User.getAttributes()
        );

        // ③ DB에서 기존 사용자 조회 또는 신규 생성
        User user = processUser(attributes, registrationId);

        log.info("OAuth2 login: provider={}, email={}, userId={}",
            registrationId, attributes.getEmail(), user.getId());

        // ④ 커스텀 principal 반환
        return CustomOAuth2User.builder()
            .userId(user.getId())
            .email(user.getEmail())
            .name(user.getName())
            .authorities(user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList()))
            .attributes(oAuth2User.getAttributes())
            .nameAttributeKey(attributes.getNameAttributeKey())
            .build();
    }

    private User processUser(OAuthAttributes attributes, String provider) {
        // 소셜 계정으로 기존 연결 조회
        return socialAccountRepository
            .findByProviderAndProviderId(provider, attributes.getProviderId())
            .map(social -> {
                // 기존 소셜 계정: 프로필 업데이트
                social.getUser().updateProfile(
                    attributes.getName(),
                    attributes.getPictureUrl());
                return social.getUser();
            })
            .orElseGet(() -> {
                // 신규: 이메일로 기존 회원 연결 또는 새 회원 생성
                User user = userRepository.findByEmail(attributes.getEmail())
                    .orElseGet(() -> createNewUser(attributes));

                // 소셜 계정 연결
                SocialAccount social = SocialAccount.builder()
                    .user(user)
                    .provider(provider)
                    .providerId(attributes.getProviderId())
                    .build();
                socialAccountRepository.save(social);
                return user;
            });
    }

    private User createNewUser(OAuthAttributes attributes) {
        User user = User.builder()
            .email(attributes.getEmail())
            .name(attributes.getName())
            .profileImage(attributes.getPictureUrl())
            .role(Role.USER)  // 기본 역할
            .build();
        return userRepository.save(user);
    }
}

// 제공자별 속성 정규화
@Getter
@Builder
public class OAuthAttributes {

    private Map<String, Object> attributes;
    private String nameAttributeKey;
    private String providerId;
    private String name;
    private String email;
    private String pictureUrl;

    public static OAuthAttributes of(String registrationId,
                                      String userNameAttributeName,
                                      Map<String, Object> attributes) {
        return switch (registrationId) {
            case "google" -> ofGoogle(userNameAttributeName, attributes);
            case "kakao"  -> ofKakao(userNameAttributeName, attributes);
            case "naver"  -> ofNaver(userNameAttributeName, attributes);
            case "github" -> ofGithub(userNameAttributeName, attributes);
            default -> throw new IllegalArgumentException(
                "Unsupported provider: " + registrationId);
        };
    }

    // Google: {sub, name, email, picture, email_verified}
    private static OAuthAttributes ofGoogle(String key, Map<String, Object> attrs) {
        return OAuthAttributes.builder()
            .attributes(attrs)
            .nameAttributeKey(key)
            .providerId((String) attrs.get("sub"))
            .name((String) attrs.get("name"))
            .email((String) attrs.get("email"))
            .pictureUrl((String) attrs.get("picture"))
            .build();
    }

    // Kakao: {id, kakao_account: {email, profile: {nickname, profile_image_url}}}
    @SuppressWarnings("unchecked")
    private static OAuthAttributes ofKakao(String key, Map<String, Object> attrs) {
        Map<String, Object> account = (Map<String, Object>) attrs.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");

        return OAuthAttributes.builder()
            .attributes(attrs)
            .nameAttributeKey(key)
            .providerId(String.valueOf(attrs.get("id")))
            .name((String) profile.get("nickname"))
            .email((String) account.get("email"))
            .pictureUrl((String) profile.get("profile_image_url"))
            .build();
    }

    // Naver: {response: {id, name, email, profile_image}}
    @SuppressWarnings("unchecked")
    private static OAuthAttributes ofNaver(String key, Map<String, Object> attrs) {
        Map<String, Object> response = (Map<String, Object>) attrs.get("response");

        return OAuthAttributes.builder()
            .attributes(attrs)
            .nameAttributeKey(key)
            .providerId((String) response.get("id"))
            .name((String) response.get("name"))
            .email((String) response.get("email"))
            .pictureUrl((String) response.get("profile_image"))
            .build();
    }

    // GitHub: {id, login, name, email, avatar_url}
    private static OAuthAttributes ofGithub(String key, Map<String, Object> attrs) {
        return OAuthAttributes.builder()
            .attributes(attrs)
            .nameAttributeKey(key)
            .providerId(String.valueOf(attrs.get("id")))
            .name((String) attrs.getOrDefault("name", attrs.get("login")))
            .email((String) attrs.get("email"))
            .pictureUrl((String) attrs.get("avatar_url"))
            .build();
    }
}
```

### OidcUserService — OIDC (Google, Apple)

```java
@Service
@RequiredArgsConstructor
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final UserRepository userRepository;
    private final OidcUserService delegate = new OidcUserService();

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // ① ID Token 검증 + UserInfo 로드 (OidcUserService가 처리)
        OidcUser oidcUser = delegate.loadUser(userRequest);

        // ② OIDC 표준 클레임 접근 (ID Token에서)
        String email = oidcUser.getEmail();
        String name  = oidcUser.getFullName();
        boolean emailVerified = Boolean.TRUE.equals(oidcUser.getEmailVerified());

        if (!emailVerified) {
            throw new OAuth2AuthenticationException("Email not verified by OIDC provider");
        }

        // ③ DB 처리
        User user = userRepository.findByEmail(email)
            .orElseGet(() -> createNewUser(email, name));

        // ④ OidcUser 구현체 반환 (ID Token 정보 보존)
        return new CustomOidcUser(user, oidcUser);
    }
}

// OIDC ID Token과 UserDetails를 통합한 커스텀 구현체
@Getter
public class CustomOidcUser implements OidcUser, UserDetails {

    private final User user;
    private final OidcUser oidcUser;

    @Override
    public Map<String, Object> getClaims()         { return oidcUser.getClaims(); }
    @Override
    public OidcUserInfo getUserInfo()               { return oidcUser.getUserInfo(); }
    @Override
    public OidcIdToken getIdToken()                 { return oidcUser.getIdToken(); }
    @Override
    public Map<String, Object> getAttributes()      { return oidcUser.getAttributes(); }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
            .map(r -> new SimpleGrantedAuthority(r.getName()))
            .collect(Collectors.toList());
    }

    @Override
    public String getName() { return oidcUser.getSubject(); } // OIDC sub

    // UserDetails
    @Override public String getPassword()             { return null; }
    @Override public String getUsername()             { return user.getEmail(); }
    @Override public boolean isAccountNonExpired()    { return true; }
    @Override public boolean isAccountNonLocked()     { return !user.isLocked(); }
    @Override public boolean isCredentialsNonExpired(){ return true; }
    @Override public boolean isEnabled()              { return user.isActive(); }
}
```

---

## 🔬 내부 동작 원리

### 1. OidcUserService vs DefaultOAuth2UserService

```
DefaultOAuth2UserService:
  → 비OIDC 제공자: Kakao, Naver, GitHub 등
  → UserInfo Endpoint에서 사용자 정보만 가져옴
  → ID Token 없음 (OAuth2 only)

OidcUserService:
  → OIDC 제공자: Google, Apple, Okta 등
  → ID Token 검증 (JWK Set으로 서명 확인)
  → ID Token의 클레임 + UserInfo Endpoint 정보 통합
  → OidcUser 반환 (OidcIdToken, OidcUserInfo 포함)

스프링 자동 선택:
  ClientRegistration에 issuerUri 또는 jwkSetUri가 있으면 → OidcUserService
  없으면 → DefaultOAuth2UserService

OidcIdToken의 추가 클레임:
  iss (Issuer): "https://accounts.google.com"
  aud (Audience): client_id
  exp (Expiration): 토큰 만료 시각
  iat (Issued At): 발급 시각
  nonce: 재사용 방지 (인가 요청 시 포함된 nonce와 비교)
  at_hash: Access Token 해시 (바인딩 검증)
```

### 2. OAuth2User + UserDetails 통합 패턴

```java
// CustomOAuth2User: OAuth2User와 UserDetails를 모두 구현
@Getter
@Builder
public class CustomOAuth2User implements OAuth2User, UserDetails {

    private final Long userId;
    private final String email;
    private final String name;
    private final List<GrantedAuthority> authorities;
    private final Map<String, Object> attributes;
    private final String nameAttributeKey;

    // OAuth2User 구현
    @Override
    public Map<String, Object> getAttributes() { return attributes; }
    @Override
    public String getName() {
        return String.valueOf(attributes.get(nameAttributeKey));
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return authorities; }

    // UserDetails 구현 (자체 인증과 통합 시 필요)
    @Override public String getPassword() { return null; }
    @Override public String getUsername() { return email; }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}

// 사용:
@GetMapping("/api/profile")
public ProfileResponse getProfile(
        @AuthenticationPrincipal CustomOAuth2User user) {
    return ProfileResponse.of(user.getUserId(), user.getEmail(), user.getName());
}
```

---

## 💻 실험으로 확인하기

### 실험 1: 소셜 로그인 후 DB 저장 확인

```java
@SpringBootTest
class CustomOAuth2UserServiceTest {

    @Autowired CustomOAuth2UserService userService;
    @Autowired UserRepository userRepository;

    @Test
    void firstGoogleLogin_createsNewUser() {
        // given: 구글 사용자 정보 Mock
        OAuth2UserRequest request = mockGoogleRequest("kim@gmail.com");

        // when: 첫 소셜 로그인
        OAuth2User result = userService.loadUser(request);

        // then: DB에 새 사용자 생성
        assertThat(userRepository.findByEmail("kim@gmail.com")).isPresent();
        assertThat(result).isInstanceOf(CustomOAuth2User.class);
        assertThat(result.getAuthorities())
            .extracting(GrantedAuthority::getAuthority)
            .contains("ROLE_USER");
    }

    @Test
    void secondGoogleLogin_updatesExistingUser() {
        // given: 이미 DB에 사용자 존재
        userRepository.save(User.builder().email("kim@gmail.com").build());

        // when: 재로그인
        userService.loadUser(mockGoogleRequest("kim@gmail.com"));

        // then: 새 사용자 생성 없음
        assertThat(userRepository.count()).isEqualTo(1);
    }
}
```

### 실험 2: 제공자별 속성 정규화 테스트

```java
@Test
void kakaoAttributes_normalized_correctly() {
    Map<String, Object> kakaoAttrs = Map.of(
        "id", 1234567890L,
        "kakao_account", Map.of(
            "email", "kim@kakao.com",
            "profile", Map.of(
                "nickname", "김철수",
                "profile_image_url", "https://..."
            )
        )
    );

    OAuthAttributes attrs = OAuthAttributes.of("kakao", "id", kakaoAttrs);

    assertThat(attrs.getEmail()).isEqualTo("kim@kakao.com");
    assertThat(attrs.getName()).isEqualTo("김철수");
    assertThat(attrs.getProviderId()).isEqualTo("1234567890");
}
```

### 실험 3: SecurityContext에서 커스텀 principal 접근

```java
@Test
@WithMockUser // 실제로는 @WithCustomOAuth2User 구현 필요
void customOAuth2User_accessible_via_security_context() throws Exception {
    mockMvc.perform(get("/api/profile"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.email").value("kim@gmail.com"))
        .andExpect(jsonPath("$.userId").isNumber());
}
```

---

## 🔒 보안 체크리스트

```
소셜 계정 연결
  ☐ 이메일 검증 여부(email_verified) 확인 후 기존 계정 연결
  ☐ providerId + provider 조합으로 소셜 계정 식별 (이메일은 변경 가능)
  ☐ 사용자에게 연결 전 확인 UI 제공 (선택)

권한 부여
  ☐ 소셜 로그인 후 기본 역할 부여 (ROLE_USER)
  ☐ 관리자 역할은 소셜 로그인으로 자동 부여 금지
  ☐ 이메일 도메인 기반 역할 부여 주의 (도메인 탈취 시 위험)

회원 가입 처리
  ☐ 필수 정보(이메일) 없는 경우 처리 (GitHub private email)
  ☐ 추가 정보 입력 페이지 연결 (전화번호, 닉네임 등)
  ☐ 서비스 약관 동의 흐름 연결

OIDC 설정
  ☐ OIDC 제공자: OidcUserService 사용
  ☐ nonce 검증 자동 처리 확인 (Spring Security가 자동)
  ☐ ID Token 만료 검증 자동 처리 확인
```

---

## 🤔 트레이드오프

```
이메일 기반 자동 연결 vs 명시적 연결:
  자동 연결:
    장점  사용자 편의 (기존 계정 찾기 자동)
    단점  이메일 미인증 소셜 계정으로 타인 계정 탈취 가능
    → email_verified=true 확인 필수

  명시적 연결:
    장점  사용자가 직접 확인 → 보안 강화
    단점  UX 복잡 (연결 확인 단계 추가)

OAuthAttributes 정규화 vs 제공자별 처리:
  정규화:
    장점  UserService 로직이 단순해짐 (제공자 무관)
    단점  OAuthAttributes 정의/유지 필요

  제공자별 처리:
    장점  각 제공자의 전체 속성 활용 가능
    단점  UserService가 제공자별 분기 로직으로 복잡해짐

CustomOAuth2User가 UserDetails도 구현:
  장점  자체 로그인 + 소셜 로그인에서 동일 principal 타입 사용
  단점  인터페이스 구현 증가, getPassword() null 반환이 혼란스러울 수 있음
```

---

## 📌 핵심 정리

```
CustomOAuth2UserService 역할
  DefaultOAuth2UserService.loadUser() 위임으로 UserInfo 로드
  OAuthAttributes로 제공자별 속성 정규화
  DB 조회/생성: 소셜 계정 연결 또는 신규 가입
  CustomOAuth2User 반환 (userId, roles 포함)

OidcUserService (Google 등 OIDC)
  ID Token 검증 (JWK 서명) + 클레임 추출
  OidcUser 반환 (OidcIdToken, OidcUserInfo 포함)
  http.oauth2Login().userInfoEndpoint().oidcUserService() 설정

제공자별 속성 구조 차이
  Google: 평탄한 구조 (email, name 직접 접근)
  Kakao:  kakao_account.profile.nickname (중첩)
  Naver:  response.name (중첩)
  → OAuthAttributes.of(registrationId, ...) 로 정규화

이메일 기반 계정 연결
  email_verified 확인 필수
  providerId + provider로 기존 소셜 계정 식별
  이메일로 기존 회원 조회 (이메일 인증된 경우에만)
```

---

## 🤔 생각해볼 문제

**Q1.** GitHub OAuth2 로그인에서 사용자가 이메일을 비공개로 설정하면 `email` 속성이 `null`로 반환됩니다. 이때 `CustomOAuth2UserService`에서 이메일 없이도 회원가입을 처리하는 방법과, GitHub의 emails API(`GET /user/emails`)를 호출해 이메일을 별도로 가져오는 방법은?

**Q2.** `CustomOAuth2UserService.loadUser()` 내부에서 `@Transactional`을 사용해 DB 작업을 수행합니다. `loadUser()`는 Spring Security의 Authentication 흐름 중에 호출되는데, 이때 트랜잭션 경계는 어떻게 설정되며 `@Transactional`이 올바르게 동작하는가?

**Q3.** 소셜 로그인으로 가입한 사용자가 나중에 일반 이메일/비밀번호 로그인도 사용하고 싶다고 요청합니다. 기존 소셜 계정에 비밀번호를 추가해 두 가지 로그인 방식을 동시에 지원하는 설계를 제안하라.

> 💡 **해설**
>
> **Q1.** GitHub의 `email` 속성이 null인 경우 두 가지 방법이 있습니다. 첫째, GitHub emails API 호출: `CustomOAuth2UserService`에서 `OAuth2AuthorizedClient`의 Access Token으로 `GET https://api.github.com/user/emails`를 추가 호출합니다. 반환된 이메일 목록 중 `primary: true`이고 `verified: true`인 이메일을 사용합니다. 이 추가 API 호출을 위해 `user:email` scope를 `ClientRegistration`에 추가해야 합니다. 둘째, 이메일 없이 회원가입: `providerId`(GitHub user id)만으로 회원을 식별하고 이메일을 선택 항목으로 처리합니다. 이 경우 이메일 기반 계정 연결이 불가능하므로 사용자에게 이메일을 나중에 추가하도록 안내합니다.
>
> **Q2.** `CustomOAuth2UserService.loadUser()`는 `OAuth2LoginAuthenticationProvider.authenticate()` 내부에서 호출됩니다. `AbstractAuthenticationProcessingFilter`가 이를 호출하는 시점은 Filter 실행 중이므로 일반적인 Spring MVC 트랜잭션 컨텍스트와 다릅니다. 그러나 `@Transactional`은 AOP 기반으로 동작하며, `CustomOAuth2UserService`가 Spring Bean이고 AOP Proxy를 통해 호출되면 정상적으로 트랜잭션이 적용됩니다. Filter는 Spring MVC 밖에 있지만 `loadUser()`는 Spring Context의 Bean을 통해 호출되므로 `@Transactional`이 올바르게 동작합니다. 단, 주의할 점은 `@Transactional(propagation=REQUIRED)` 기본 설정에서 이미 진행 중인 트랜잭션이 있으면 참여하고 없으면 새로 생성합니다.
>
> **Q3.** "소셜 + 비밀번호 하이브리드 로그인" 설계: `users` 테이블에 `password` 컬럼을 nullable로 추가합니다. 소셜로 가입한 사용자는 초기에 `password=null`입니다. "비밀번호 설정" 기능 제공: 로그인 상태에서 비밀번호를 설정하면 `PasswordEncoder`로 해싱 후 저장합니다. `UserDetailsService`를 구현해 이메일 + 비밀번호 로그인 지원: `password=null`인 사용자는 비밀번호 로그인 불가(`BadCredentialsException`). 소셜 로그인과 비밀번호 로그인 모두 동일한 `User` 레코드에 매핑됩니다. `social_accounts` 테이블에서 해당 사용자의 소셜 계정 목록을 관리합니다. 중요: 비밀번호 설정 시 현재 소셜 로그인으로 인증된 상태를 확인해 타인이 비밀번호를 임의로 설정하는 것을 방지합니다.

---

<div align="center">

**[← 이전: OAuth2AuthorizedClient 관리](./05-oauth2-authorized-client.md)** | **[홈으로 🏠](../README.md)** | **[다음: JWT Bearer Token Resource Server ➡️](./07-resource-server-jwt.md)**

</div>
