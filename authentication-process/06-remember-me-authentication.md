# Remember-Me 인증 메커니즘 — 토큰 기반과 영속 토큰 기반 전략 비교

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `RememberMeAuthenticationFilter`가 실행되는 조건은 무엇인가?
- `TokenBasedRememberMeServices`가 발행하는 쿠키의 구조는 무엇이며 어떻게 검증하는가?
- `PersistentTokenBasedRememberMeServices`가 더 안전한 이유는 무엇인가?
- Remember-Me 토큰이 탈취됐을 때 두 전략에서 피해 범위의 차이는?
- `RememberMeAuthenticationFilter`가 `UsernamePasswordAuthenticationFilter` 뒤에 위치하는 이유는?
- Remember-Me로 로그인한 사용자와 폼 로그인한 사용자를 코드에서 어떻게 구분하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 세션이 만료될 때마다 재로그인 요구는 UX를 해친다

```
세션 기반 인증의 한계:
  사용자가 브라우저를 닫으면 세션 쿠키(JSESSIONID)가 사라짐
  서버 세션 타임아웃(기본 30분) 후 세션 만료
  → 매번 다시 로그인 필요 → 불편함

Remember-Me 해결책:
  로그인 시 "로그인 상태 유지" 체크박스 선택
  → 장기 유효 쿠키(remember-me) 발행 (14일, 30일 등)
  → 브라우저 재시작 후에도 쿠키가 유지
  → 세션 없이 remember-me 쿠키로 자동 재인증

보안 고려사항:
  장기 유효 쿠키 = 장기간 탈취 가능 → 신중한 전략 선택 필요
  Spring Security: 두 가지 전략 제공
  ① 간단하지만 덜 안전한 토큰 기반
  ② 복잡하지만 더 안전한 영속 토큰 기반
```

---

## 😱 흔한 보안 실수

### Before: TokenBasedRememberMeServices의 key를 약하게 설정

```java
// ❌ 예측 가능한 key → 쿠키 위조 가능
http.rememberMe(rm -> rm
    .key("myapp")  // 짧고 예측 가능한 key
    .tokenValiditySeconds(14 * 24 * 60 * 60)
);

// TokenBasedRememberMeServices의 쿠키 구조:
// Base64(username + ":" + expirationTime + ":" + HMAC)
// HMAC = MD5(username + ":" + expirationTime + ":" + password + ":" + key)
//
// key가 짧으면 → 브루트포스로 key 추측 가능
// key + password로 유효한 쿠키 위조 가능

// ✅ 강력하고 무작위적인 key 사용
http.rememberMe(rm -> rm
    .key(UUID.randomUUID().toString()) // 애플리케이션 시작 시 매번 변경
    // 또는 고정 값이 필요하면:
    .key(environment.getProperty("security.remember-me.key")) // 환경변수에서 로드
    .tokenValiditySeconds(7 * 24 * 60 * 60) // 7일
);

// ⚠️ 주의: UUID.randomUUID()를 key로 사용하면
// 서버 재시작 시 기존 Remember-Me 쿠키가 모두 무효화됨
// → PersistentTokenBasedRememberMeServices 권장
```

### Before: 관리자 권한 작업을 Remember-Me 인증으로 허용

```java
// ❌ 보안 취약: Remember-Me로 로그인한 사용자에게 민감 작업 허용
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN") // Remember-Me 사용자도 접근 가능
);

// ✅ 민감 작업은 완전한 인증(폼 로그인) 요구
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/admin/delete/**")
        .access("hasRole('ADMIN') and isFullyAuthenticated()")
        // isFullyAuthenticated(): Remember-Me 인증은 false, 폼 로그인은 true
);

// isFullyAuthenticated() SpEL:
// → 현재 Authentication이 RememberMeAuthenticationToken이면 false
// → UsernamePasswordAuthenticationToken(인증 완료)이면 true
```

---

## ✨ 올바른 보안 구현

### 두 전략 비교와 선택

```java
// ── 전략 1: TokenBasedRememberMeServices (간단, 덜 안전) ────────────
@Bean
public SecurityFilterChain tokenBasedChain(HttpSecurity http) throws Exception {
    http.rememberMe(rm -> rm
        .rememberMeParameter("remember-me")  // 폼 체크박스 name
        .rememberMeCookieName("remember-me") // 쿠키 이름
        .tokenValiditySeconds(7 * 24 * 60 * 60) // 7일
        .key("my-very-long-random-secret-key-32chars-minimum") // HMAC key
        .userDetailsService(userDetailsService)
        // 쿠키 위조 방어: HMAC에 비밀번호 포함
        // 비밀번호 변경 시 기존 쿠키 자동 무효화
    );
    return http.build();
}

// ── 전략 2: PersistentTokenBasedRememberMeServices (권장) ──────────
@Bean
public PersistentTokenRepository persistentTokenRepository() {
    JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
    repo.setDataSource(dataSource);
    // 테이블 자동 생성 (개발 환경에서만):
    // repo.setCreateTableOnStartup(true);
    return repo;
}

@Bean
public SecurityFilterChain persistentChain(HttpSecurity http) throws Exception {
    http.rememberMe(rm -> rm
        .tokenRepository(persistentTokenRepository())
        .tokenValiditySeconds(30 * 24 * 60 * 60) // 30일
        .userDetailsService(userDetailsService)
    );
    return http.build();
}

// PersistentTokenBasedRememberMeServices가 사용하는 테이블:
// CREATE TABLE persistent_logins (
//   username  VARCHAR(64) NOT NULL,
//   series    VARCHAR(64) PRIMARY KEY,    -- 토큰 시리즈 (고정)
//   token     VARCHAR(64) NOT NULL,       -- 실제 토큰 (사용마다 갱신)
//   last_used TIMESTAMP NOT NULL
// );
```

---

## 🔬 내부 동작 원리

### 1. RememberMeAuthenticationFilter — 실행 조건

```java
// RememberMeAuthenticationFilter.java
public class RememberMeAuthenticationFilter extends GenericFilterBean
        implements ApplicationEventPublisherAware {

    private RememberMeServices rememberMeServices;
    private AuthenticationManager authenticationManager;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        // ① SecurityContext에 이미 Authentication이 있으면 실행 안 함
        // (이미 폼 로그인이나 JWT로 인증된 경우)
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        // ② remember-me 쿠키에서 Authentication 추출 시도
        Authentication rememberMeAuth =
            this.rememberMeServices.autoLogin(
                (HttpServletRequest) request,
                (HttpServletResponse) response);

        if (rememberMeAuth != null) {
            try {
                // ③ RememberMeAuthenticationProvider로 검증
                rememberMeAuth = authenticationManager.authenticate(rememberMeAuth);

                // ④ SecurityContext에 저장
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(rememberMeAuth);
                SecurityContextHolder.setContext(context);
                onSuccessfulAuthentication(request, response, rememberMeAuth);

            } catch (AuthenticationException ex) {
                // 쿠키 위조 또는 만료 → 쿠키 제거
                this.rememberMeServices.loginFail(request, response);
                onUnsuccessfulAuthentication(request, response, ex);
            }
        }

        chain.doFilter(request, response);
    }
}
```

### 2. TokenBasedRememberMeServices — 쿠키 생성과 검증

```java
// TokenBasedRememberMeServices.java
public class TokenBasedRememberMeServices extends AbstractRememberMeServices {

    // 쿠키 생성 (로그인 성공 시 호출)
    @Override
    protected void onLoginSuccess(HttpServletRequest request,
                                   HttpServletResponse response,
                                   Authentication successfulAuthentication) {
        String username = successfulAuthentication.getName();
        UserDetails user = getUserDetailsService().loadUserByUsername(username);
        long expiryTime = System.currentTimeMillis() + 1000L * getTokenValiditySeconds();

        // 서명 생성: MD5(username:expiryTime:password:key)
        // 비밀번호를 서명에 포함 → 비밀번호 변경 시 쿠키 자동 무효화
        String signatureValue = makeTokenSignature(expiryTime, username,
            user.getPassword(), this.encodingAlgorithm);

        // 쿠키 값: Base64(username:expiryTime:algorithm:signature)
        setCookie(
            new String[]{username, Long.toString(expiryTime),
                         this.encodingAlgorithm.name(), signatureValue},
            getTokenValiditySeconds(), request, response);
    }

    // 쿠키 검증 (자동 로그인 시도 시)
    @Override
    protected UserDetails processAutoLoginCookie(String[] cookieTokens,
                                                  HttpServletRequest request,
                                                  HttpServletResponse response) {
        // 쿠키 파싱: [username, expiryTime, algorithm, signature]
        if (cookieTokens.length < 4) {
            throw new InvalidCookieException("...");
        }
        long tokenExpiryTime = Long.parseLong(cookieTokens[1]);

        // 만료 확인
        if (tokenExpiryTime < System.currentTimeMillis()) {
            throw new InvalidCookieException("Remember-me login has expired");
        }

        // 사용자 로드
        UserDetails userDetails = getUserDetailsService()
            .loadUserByUsername(cookieTokens[0]);

        // 서명 재계산 후 비교
        String expectedSignature = makeTokenSignature(
            tokenExpiryTime, userDetails.getUsername(),
            userDetails.getPassword(), this.encodingAlgorithm);

        if (!equals(expectedSignature, cookieTokens[3])) {
            throw new InvalidCookieException("Cookie token signature mismatch");
        }

        return userDetails;
    }
}
```

### 3. PersistentTokenBasedRememberMeServices — 더 안전한 전략

```java
// PersistentTokenBasedRememberMeServices.java
public class PersistentTokenBasedRememberMeServices
        extends AbstractRememberMeServices {

    private PersistentTokenRepository tokenRepository;

    // 쿠키 생성: series + token 쌍을 DB에 저장
    @Override
    protected void onLoginSuccess(HttpServletRequest request,
                                   HttpServletResponse response,
                                   Authentication successfulAuthentication) {
        String username = successfulAuthentication.getName();

        // series: 세션의 고유 식별자 (영구적)
        // token:  실제 인증 토큰 (매 사용마다 갱신)
        PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(
            username,
            generateSeriesData(),  // SecureRandom으로 생성
            generateTokenData(),   // SecureRandom으로 생성
            new Date()
        );
        tokenRepository.createNewToken(persistentToken);

        // 쿠키: Base64(series:token)
        addCookie(persistentToken, request, response);
    }

    // 쿠키 검증 (자동 로그인)
    @Override
    protected UserDetails processAutoLoginCookie(String[] cookieTokens,
                                                  HttpServletRequest request,
                                                  HttpServletResponse response) {
        // series, token 추출
        String presentedSeries = cookieTokens[0];
        String presentedToken = cookieTokens[1];

        // DB에서 series로 저장된 토큰 조회
        PersistentRememberMeToken token =
            this.tokenRepository.getTokenForSeries(presentedSeries);

        if (token == null) {
            throw new RememberMeAuthenticationException("No persistent token found for series id");
        }

        // ① 토큰 불일치: 탈취 감지!
        if (!presentedToken.equals(token.getTokenValue())) {
            // series가 존재하지만 token이 다름 → 누군가 탈취 후 사용했을 가능성
            // → 이 series의 모든 토큰 삭제 (해당 사용자의 모든 Remember-Me 세션 종료)
            this.tokenRepository.removeUserTokens(token.getUsername());
            throw new CookieTheftException(
                "Invalid remember-me token (Series/token mismatch). " +
                "Implies previous cookie theft attack.");
        }

        // ② 유효한 토큰 → 새 token 값으로 갱신 (series는 유지)
        // 매 사용마다 token이 바뀌므로 캡처 재사용 감지 가능
        PersistentRememberMeToken newToken = new PersistentRememberMeToken(
            token.getUsername(), presentedSeries,
            generateTokenData(), new Date());
        this.tokenRepository.updateToken(presentedSeries, newToken.getTokenValue(), new Date());

        // ③ 새 쿠키 발행 (갱신된 token 포함)
        addCookie(newToken, request, response);

        return getUserDetailsService().loadUserByUsername(token.getUsername());
    }
}
```

### 4. 두 전략 보안 비교

```
쿠키 탈취 시나리오 비교:

  TokenBasedRememberMeServices:
    쿠키 값: Base64(username:expiryTime:signature)
    서명: MD5(username:expiryTime:password:key)

    탈취 시:
    → 만료 전까지 공격자가 자유롭게 사용 가능
    → 쿠키 만료 전에 비밀번호를 변경해야 무효화됨
    → 탈취를 감지할 방법 없음

  PersistentTokenBasedRememberMeServices:
    쿠키 값: Base64(series:token)
    series: 고정 식별자 (DB 기본 키)
    token: 매 사용마다 새 값으로 갱신

    탈취 시:
    → 공격자가 먼저 쿠키를 사용하면 DB의 token이 변경됨
    → 피해자가 다음 자동 로그인 시도 시:
      series 매칭 ✓, token 불일치 ✗ → CookieTheftException
      → 해당 사용자의 모든 Remember-Me 세션 삭제
      → "누군가가 당신의 세션을 탈취했을 수 있습니다" 알림 가능
```

### 5. isFullyAuthenticated() vs isAuthenticated() 차이

```java
// AuthenticationTrustResolverImpl.java
public class AuthenticationTrustResolverImpl implements AuthenticationTrustResolver {

    private Class<? extends Authentication> anonymousClass = AnonymousAuthenticationToken.class;
    private Class<? extends Authentication> rememberMeClass = RememberMeAuthenticationToken.class;

    @Override
    public boolean isAnonymous(Authentication authentication) {
        return anonymousClass.isAssignableFrom(authentication.getClass());
    }

    @Override
    public boolean isRememberMe(Authentication authentication) {
        return rememberMeClass.isAssignableFrom(authentication.getClass());
    }
}

// SecurityExpressionRoot.java
public boolean isFullyAuthenticated() {
    Authentication auth = getAuthentication();
    return !trustResolver.isAnonymous(auth) && !trustResolver.isRememberMe(auth);
    // 폼 로그인 = true
    // Remember-Me = false
    // 익명 = false
}

public boolean isAuthenticated() {
    return !trustResolver.isAnonymous(getAuthentication());
    // 폼 로그인 = true
    // Remember-Me = true ← 차이
    // 익명 = false
}

// 활용 패턴:
@PreAuthorize("isFullyAuthenticated()") // 비밀번호 변경, 결제 등 민감 작업
public void changePassword(...) { ... }

@PreAuthorize("isAuthenticated()")      // 일반 보호 리소스 (Remember-Me 허용)
public void viewProfile(...) { ... }
```

---

## 💻 실험으로 확인하기

### 실험 1: Remember-Me 쿠키 구조 분석

```bash
# Remember-Me 체크박스 포함 로그인
curl -c cookies.txt -X POST http://localhost:8080/login \
  -d "username=kim&password=1234&remember-me=true"

# 쿠키 확인
cat cookies.txt | grep remember-me
# → remember-me  ZGV2...  ← Base64 인코딩된 값

# Base64 디코딩
echo "ZGV2..." | base64 -d
# → kim:1735689600000:PBKDF2:abc123def456...
# → username:expiryTimestamp:algorithm:signature
```

### 실험 2: PersistentToken 갱신 확인 (DB)

```sql
-- 로그인 후 persistent_logins 테이블 확인
SELECT username, series, token, last_used
FROM persistent_logins
WHERE username = 'kim';
-- series: 고정 (세션 전체 기간)
-- token: 자동 로그인 시마다 변경됨

-- 자동 로그인 전
-- series='abc123', token='token-v1', last_used='2024-01-01 00:00:00'

-- 자동 로그인 후
-- series='abc123', token='token-v2', last_used='2024-01-02 00:00:00'
-- (series 유지, token 변경, last_used 갱신)
```

### 실험 3: isFullyAuthenticated() 접근 제어 확인

```java
@GetMapping("/sensitive")
@PreAuthorize("isFullyAuthenticated()")
public String sensitiveAction() {
    return "Allowed only with full authentication (not Remember-Me)";
}

@GetMapping("/normal")
@PreAuthorize("isAuthenticated()")
public String normalAction() {
    return "Allowed for any authenticated user (including Remember-Me)";
}
```

```bash
# Remember-Me로 자동 로그인한 후:
curl -b cookies.txt http://localhost:8080/normal
# → "Allowed for any authenticated user (including Remember-Me)"

curl -b cookies.txt http://localhost:8080/sensitive
# → 403 Forbidden (isFullyAuthenticated() = false)
# → 로그인 페이지로 리다이렉트 (ExceptionTranslationFilter 처리)
```

### 실험 4: 쿠키 탈취 감지 시뮬레이션

```bash
# 1. Remember-Me 로그인 → 쿠키 탈취됐다고 가정
# 공격자가 먼저 자동 로그인 시도
curl -b "remember-me=<stolen-cookie>" http://localhost:8080/api/users
# → 200 OK (공격자가 DB의 token 사용 → 새 token으로 갱신)

# 2. 피해자가 자동 로그인 시도 (기존 쿠키 사용)
curl -b "remember-me=<original-cookie>" http://localhost:8080/api/users
# → series 일치, token 불일치 → CookieTheftException
# → persistent_logins에서 kim의 모든 행 삭제
# → 응답: 로그인 페이지로 리다이렉트 + 보안 경고
```

---

## 🔒 보안 체크리스트

```
Remember-Me 설정
  ☐ key: 최소 32자 이상의 무작위 문자열 (환경변수에서 로드)
  ☐ 프로덕션: PersistentTokenBasedRememberMeServices 사용
  ☐ 토큰 유효 기간을 최소화 (최대 30일 권장)
  ☐ persistent_logins 테이블에 인덱스 추가 (username, series 컬럼)

접근 제어
  ☐ 비밀번호 변경, 결제, 개인정보 수정 등 민감 작업:
     isFullyAuthenticated() 적용
  ☐ 일반 보호 리소스: isAuthenticated() 적용
  ☐ Remember-Me 로그인 시 민감 작업 → 재인증 페이지로 안내

쿠키 보안
  ☐ Secure 속성: HTTPS에서만 전송
  ☐ HttpOnly 속성: JavaScript 접근 차단 (기본 적용됨)
  ☐ SameSite 속성: CSRF 방어 강화
```

---

## 🤔 트레이드오프

```
TokenBased vs PersistentToken:
  TokenBasedRememberMeServices:
    장점  DB 없이 동작, 구현 단순
    단점  탈취 감지 불가, 비밀번호 변경 전까지 위조된 쿠키 무효화 불가
          여러 서버 사용 시 key를 공유해야 함

  PersistentTokenBasedRememberMeServices:
    장점  탈취 감지 가능 (CookieTheftException)
          특정 디바이스의 Remember-Me만 무효화 가능
          사용 기록 추적 가능
    단점  DB 테이블 필요, 매 자동 로그인마다 DB 쓰기 발생

Remember-Me 유효 기간:
  짧음 (7일):
    장점  탈취 피해 기간 최소화
    단점  자주 재로그인 필요 → 사용자 불편

  길음 (30~90일):
    장점  사용자 경험 향상
    단점  탈취 시 장기간 악용 가능
    → PersistentToken의 탈취 감지로 리스크 완화
```

---

## 📌 핵심 정리

```
RememberMeAuthenticationFilter 실행 조건
  SecurityContext에 Authentication이 없을 때만 실행
  → 폼 로그인 성공 후에는 실행 안 됨 (이미 인증됨)
  → 세션 만료 + remember-me 쿠키 있을 때 자동 재인증

TokenBasedRememberMeServices 쿠키 구조
  Base64(username:expiryTime:algorithm:signature)
  signature = HMAC(username:expiryTime:password:key)
  → 비밀번호 변경 시 자동 무효화

PersistentTokenBasedRememberMeServices 보안 장점
  series: 고정 (세션 전체 기간)
  token: 매 사용마다 갱신
  탈취 감지: series 일치 + token 불일치 → CookieTheftException
  → 해당 사용자의 모든 Remember-Me 세션 삭제

isFullyAuthenticated() vs isAuthenticated()
  isFullyAuthenticated(): RememberMe 인증 = false
  isAuthenticated():      RememberMe 인증 = true
  민감 작업: isFullyAuthenticated() 적용 권장
```

---

## 🤔 생각해볼 문제

**Q1.** `RememberMeAuthenticationFilter`가 순서 3000에 위치하고 `UsernamePasswordAuthenticationFilter`가 순서 1900에 위치합니다. 사용자가 폼 로그인으로 인증에 성공한 후 같은 요청에서 remember-me 쿠키가 발행됩니다. 다음 요청에서 세션이 유효한 경우 `RememberMeAuthenticationFilter`가 실행되지 않는 이유는?

**Q2.** `PersistentTokenBasedRememberMeServices`는 탈취 감지 시 해당 사용자의 모든 Remember-Me 세션을 삭제합니다. 다중 디바이스 사용자(PC, 모바일, 태블릿)의 경우 이것이 과도한 조치가 될 수 있습니다. 이를 개선하는 방법을 설계하라.

**Q3.** Remember-Me 토큰은 `RememberMeAuthenticationToken`으로 `SecurityContext`에 저장됩니다. 로그아웃 시 세션은 무효화되지만 remember-me 쿠키를 삭제하지 않으면 어떤 문제가 발생하는가?

> 💡 **해설**
>
> **Q1.** `RememberMeAuthenticationFilter.doFilter()`의 첫 번째 조건은 `SecurityContextHolder.getContext().getAuthentication() != null`입니다. 세션이 유효한 경우 `SecurityContextHolderFilter`가 요청 시작 시 `HttpSession`에서 `SecurityContext`를 복원합니다. 이미 `Authentication`이 설정된 상태이므로 `RememberMeAuthenticationFilter`는 쿠키 처리 없이 `chain.doFilter()`로 넘깁니다. 즉, 세션이 살아 있는 동안은 remember-me 쿠키를 사용할 필요가 없습니다.
>
> **Q2.** 현재 `PersistentTokenBasedRememberMeServices`는 `series` 단위로 토큰을 관리하지만 탈취 감지 시 `removeUserTokens(username)`으로 모든 series를 삭제합니다. 개선 방법으로는 탈취 감지 시 해당 `series`만 삭제하는 방법이 있습니다. 더 나아가 디바이스 정보(User-Agent, IP)를 함께 저장해 "의심스러운 series"만 삭제하거나, 사용자에게 이메일로 "비정상 로그인 감지" 알림을 보내고 직접 삭제하도록 하는 UX를 제공할 수 있습니다. 이를 위해 `persistent_logins` 테이블에 `device_info`, `ip_address` 컬럼을 추가하고 `PersistentTokenBasedRememberMeServices`를 커스텀 구현으로 확장해야 합니다.
>
> **Q3.** 로그아웃 시 `LogoutHandler` 목록에 `TokenRememberMeServices`(또는 `PersistentRememberMeServices`)가 포함되어 있으면 자동으로 remember-me 쿠키를 삭제하고 DB에서 토큰을 제거합니다. 하지만 `rememberMe()`를 설정하지 않거나 커스텀 로그아웃을 구현할 때 이 핸들러를 누락하면 세션은 무효화됐지만 쿠키는 남아 있습니다. 다음 요청에서 `SecurityContextHolderFilter`가 `HttpSession`에서 `SecurityContext`를 복원하지 못하므로 `RememberMeAuthenticationFilter`가 실행되고 남아 있는 쿠키로 자동 재인증이 됩니다. 사용자가 로그아웃을 했음에도 불구하고 remember-me 쿠키만으로 다시 로그인 상태가 되는 심각한 보안 문제입니다.

---

<div align="center">

**[← 이전: UsernamePasswordAuthenticationFilter 분석](./05-username-password-authentication-filter.md)** | **[홈으로 🏠](../README.md)** | **[다음: Custom Authentication Provider 작성 ➡️](./07-custom-authentication-provider.md)**

</div>
