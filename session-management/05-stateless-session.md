# Stateless Session (JWT 환경) — STATELESS 설정이 Security 내부에 미치는 영향

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `SessionCreationPolicy.STATELESS`는 어떤 컴포넌트의 동작을 어떻게 바꾸는가?
- JWT 환경에서 `SecurityContextRepository`를 어떻게 교체해야 하는가?
- `NullSecurityContextRepository`와 `HttpSessionSecurityContextRepository`의 차이는?
- 매 요청마다 JWT를 파싱해 `SecurityContext`를 재구성하는 정확한 흐름은?
- `STATELESS` 설정에서도 세션이 생성될 수 있는 의외의 케이스는?
- Stateless 환경에서 `@SessionScope` Bean과 Spring MVC의 세션 관련 기능은 어떻게 되는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 서버 세션의 한계와 JWT의 등장

```
세션 기반 인증의 한계:
  1. 수평 확장(Scale-out) 문제
     서버 A에서 로그인 → 세션이 서버 A 메모리에
     다음 요청이 서버 B로 → 서버 B는 세션 없음 → 인증 실패
     해결: Sticky Session 또는 공유 세션 저장소(Redis)
     → 추가 인프라 비용, 단일 장애 지점(SPOF) 위험

  2. 모바일/앱 클라이언트
     쿠키를 기본으로 사용하지 않는 환경
     REST API 클라이언트가 세션 관리를 기대하지 않음

  3. 마이크로서비스
     서비스 간 인증 전파 → 세션을 공유하거나 매번 검증 필요

JWT (JSON Web Token) 해결:
  인증 정보를 토큰 자체에 서명해서 저장
  서버는 토큰 서명만 검증 → 상태 없음(Stateless)
  어느 서버로 요청해도 같은 토큰으로 인증 가능

Spring Security STATELESS 설정:
  SessionCreationPolicy.STATELESS
  → 세션을 생성하지도, 조회하지도 않음
  → 매 요청마다 토큰을 파싱해 SecurityContext 재구성
```

---

## 😱 흔한 보안 실수

### Before: STATELESS 설정에서 세션이 여전히 생성되는 케이스 방치

```java
// ❌ 문제: STATELESS 설정했는데 다른 컴포넌트가 세션을 생성함

// 1. Spring MVC의 FlashAttribute 사용 시 세션 생성
// 2. @SessionAttributes를 사용하는 Controller
// 3. OAuth2 로그인 흐름 (state parameter를 세션에 저장)
// 4. 개발자가 HttpSession을 직접 주입받아 사용

@RestController
public class ApiController {
    @GetMapping("/api/data")
    public Data getData(HttpSession session) { // ← 세션 직접 접근!
        session.setAttribute("lastAccess", new Date()); // 세션 생성됨!
        ...
    }
}

// ✅ JWT 환경에서 세션 의존 완전 제거
@RestController
public class ApiController {
    @GetMapping("/api/data")
    public Data getData(Authentication authentication) { // 세션 없이 처리
        CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();
        ...
    }
}
```

### Before: JWT 필터에서 예외를 체인에 던져 ExceptionTranslationFilter가 처리 못 하게 함

```java
// ❌ 문제: RuntimeException throw → DispatcherServlet 레벨에서 처리 → 500 응답
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(...) {
        try {
            String token = extractToken(request);
            Claims claims = jwtUtil.parseToken(token);
            // SecurityContext 설정...
        } catch (JwtException e) {
            throw new RuntimeException("Invalid JWT", e); // ❌ 500
        }
        chain.doFilter(request, response);
    }
}

// ✅ 인증 실패 시 SecurityContext 비운 채로 체인 진행
// ExceptionTranslationFilter가 401로 처리
@Override
protected void doFilterInternal(...) {
    try {
        String token = extractToken(request);
        if (token != null) {
            Claims claims = jwtUtil.parseToken(token);
            Authentication auth = createAuthentication(claims);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
    } catch (JwtException e) {
        log.warn("Invalid JWT token: {}", e.getMessage());
        SecurityContextHolder.clearContext(); // 인증 정보 없음으로 처리
    }
    chain.doFilter(request, response); // 체인 계속 진행
    // 인증 없으면 AuthorizationFilter에서 AccessDeniedException
    // → ExceptionTranslationFilter → 401
}
```

---

## ✨ 올바른 보안 구현

### JWT 인증 완전한 STATELESS 설정

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class JwtSecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ① Stateless 세션 정책
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // ② SecurityContext 저장소를 NullRepository로 교체
            // (세션에 SecurityContext 저장/로드 안 함)
            .securityContext(ctx -> ctx
                .securityContextRepository(new NullSecurityContextRepository())
                // 또는 RequestAttributeSecurityContextRepository (요청 범위)
            )
            // ③ 세션 기반 기능 비활성화
            .csrf(csrf -> csrf.disable()) // CSRF는 세션 기반 → Stateless에서 불필요
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            // ④ JWT 필터 등록
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            // ⑤ URL 접근 제어
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}

// JWT 인증 필터
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
        SecurityContextHolder.getContextHolderStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain)
            throws ServletException, IOException {

        // ① Authorization 헤더에서 토큰 추출
        String token = resolveToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            try {
                // ② 토큰에서 사용자 정보 추출
                String username = jwtTokenProvider.getUsername(token);

                // ③ UserDetails 로드 (DB 조회 — 계정 상태 확인)
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // ④ 인증 완료 토큰 생성
                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

                // ⑤ SecurityContext에 저장 (요청 범위 — 세션에 저장 안 함)
                SecurityContext context = securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authentication);
                securityContextHolderStrategy.setContext(context);

            } catch (UsernameNotFoundException | JwtException e) {
                log.warn("JWT auth failed: {}", e.getMessage());
                securityContextHolderStrategy.clearContext();
            }
        }

        chain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

---

## 🔬 내부 동작 원리

### 1. SessionCreationPolicy.STATELESS가 바꾸는 동작

```java
// SessionManagementConfigurer.java가 STATELESS 처리 시:

// ① SecurityContextRepository → NullSecurityContextRepository
// STATELESS 설정 시 자동으로 교체
public class NullSecurityContextRepository implements SecurityContextRepository {

    @Override
    public SecurityContext loadDeferredContext(HttpServletRequest request) {
        // 세션에서 로드하지 않음 → 항상 빈 컨텍스트 반환
        return new DeferredSecurityContext() {
            @Override
            public SecurityContext get() {
                return SecurityContextHolder.createEmptyContext();
            }
            @Override
            public boolean isGenerated() { return true; }
        };
    }

    @Override
    public void saveContext(SecurityContext context,
                             HttpServletRequest request,
                             HttpServletResponse response) {
        // 세션에 저장하지 않음 → 아무것도 하지 않음
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false; // 항상 false → SecurityContext가 세션에 없음
    }
}

// ② HttpSessionSecurityContextRepository (세션 기반)와 비교:
// 세션 기반: 요청 → 세션 로드 → SecurityContext 복원 → 필터 처리 → 세션에 저장
// Stateless:  요청 → 빈 SecurityContext → JWT 필터가 재구성 → 요청 끝 → 버림
```

### 2. SessionCreationPolicy 상세 비교

```java
// SessionCreationPolicy 옵션:
public enum SessionCreationPolicy {

    // 항상 새 세션 생성 (매 요청마다)
    ALWAYS,

    // 세션이 없어도 생성하지 않음
    // 단, 다른 컴포넌트(Spring MVC 등)가 생성한 세션은 사용
    NEVER,

    // 필요할 때만 세션 생성 (기본값)
    // 인증 성공 시 세션 생성, Remember-Me 등
    IF_REQUIRED,

    // 세션 생성 안 함, 기존 세션도 사용 안 함
    // SecurityContext를 세션에서 로드/저장 안 함
    STATELESS
}

// STATELESS vs NEVER:
// NEVER: Spring Security는 세션 안 만들지만 MVC가 만든 세션을 읽을 수 있음
// STATELESS: 어떤 세션도 읽거나 쓰지 않음 (가장 순수한 비상태)
```

### 3. 매 요청마다 SecurityContext 재구성 흐름

```
JWT 요청 처리 흐름:

  GET /api/orders
  Authorization: Bearer eyJhbGc...

  ① SecurityContextHolderFilter
     NullSecurityContextRepository.loadDeferredContext()
     → 빈 SecurityContext 생성 (세션 조회 없음)
     SecurityContextHolder에 빈 컨텍스트 설정

  ② JwtAuthenticationFilter
     "Bearer eyJhbGc..." → 토큰 추출
     jwtTokenProvider.validateToken() → 유효
     claims에서 username 추출
     userDetailsService.loadUserByUsername() → UserDetails (DB 조회)
     UsernamePasswordAuthenticationToken 생성
     SecurityContextHolder.getContext().setAuthentication(auth)
     → SecurityContext에 인증 정보 저장 (메모리, 현재 요청 범위)

  ③ AuthorizationFilter
     SecurityContextHolder.getContext().getAuthentication() → 인증된 Authentication
     권한 검사 통과

  ④ Controller 실행
     @AuthenticationPrincipal → JwtAuthenticationFilter가 설정한 UserDetails

  ⑤ 요청 완료
     NullSecurityContextRepository.saveContext() → 아무것도 하지 않음
     SecurityContextHolder.clearContext() → 메모리에서 제거
     (다음 요청은 다시 ①부터)
```

### 4. DB 조회 없이 JWT 클레임만으로 인증하는 방식

```java
// DB 조회를 줄이기 위해 JWT 클레임에서 직접 UserDetails 구성
// 트레이드오프: 계정 정지/삭제 즉시 반영 불가 (토큰 만료 전까지 유효)

@Component
public class JwtAuthenticationFilterWithoutDb extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, ...) {
        String token = resolveToken(request);
        if (token != null && jwtTokenProvider.validateToken(token)) {
            // DB 조회 없이 JWT 클레임에서 직접 Authentication 생성
            Authentication auth = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        chain.doFilter(request, response);
    }
}

// JwtTokenProvider
public Authentication getAuthentication(String token) {
    Claims claims = parseToken(token);
    String username = claims.getSubject();

    // 클레임에서 권한 추출
    List<SimpleGrantedAuthority> authorities = ((List<String>)
        claims.get("roles", List.class))
        .stream()
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());

    // DB 조회 없이 UserDetails 구성
    UserDetails userDetails = User.builder()
        .username(username)
        .password("") // JWT 환경에서는 사용 안 함
        .authorities(authorities)
        .build();

    return new UsernamePasswordAuthenticationToken(
        userDetails, null, authorities);
}
// 장점: DB 조회 없음 → 빠름
// 단점: 계정 정지/삭제가 토큰 만료 전까지 즉시 반영 안 됨
//       → 블랙리스트 토큰 저장소(Redis) 병행 사용 권장
```

---

## 💻 실험으로 확인하기

### 실험 1: STATELESS에서 세션 생성 여부 확인

```java
@GetMapping("/api/test")
public Map<String, Object> test(HttpServletRequest request) {
    HttpSession session = request.getSession(false); // false: 없으면 null
    return Map.of(
        "sessionExists", session != null,
        "sessionId", session != null ? session.getId() : "none"
    );
}
// STATELESS 설정 후: {"sessionExists": false, "sessionId": "none"}
// IF_REQUIRED 설정: {"sessionExists": true, "sessionId": "..."}
```

### 실험 2: 요청 간 SecurityContext 공유 안 됨 확인

```bash
# 요청 1: JWT 없이 → 인증 안 됨
curl http://localhost:8080/api/test
# → 401

# 요청 2: JWT 포함 → 인증됨
curl -H "Authorization: Bearer <valid-jwt>" http://localhost:8080/api/test
# → 200

# 요청 3: JWT 없이 다시 → 세션 없으므로 인증 안 됨 (세션 기반이었다면 인증됨)
curl http://localhost:8080/api/test
# → 401 (STATELESS: 이전 인증 정보 없음)
```

### 실험 3: 토큰 만료 처리 확인

```bash
# 만료된 JWT로 접근
curl -H "Authorization: Bearer <expired-jwt>" http://localhost:8080/api/orders
# → 401 {"error": "JWT_EXPIRED", "message": "토큰이 만료되었습니다"}
# JwtAuthenticationFilter에서 JwtExpiredException catch → SecurityContext 비움
# → AuthorizationFilter → AccessDeniedException
# → ExceptionTranslationFilter → AuthenticationEntryPoint → 401
```

---

## 🔒 보안 체크리스트

```
STATELESS 설정
  ☐ SessionCreationPolicy.STATELESS 명시
  ☐ CSRF 비활성화 (Stateless 환경 전제 조건 확인 후)
  ☐ 세션 기반 기능 비활성화 (formLogin, httpBasic 등)

JWT 필터 구현
  ☐ 토큰 검증 실패 시 SecurityContext.clearContext() 후 chain.doFilter() 계속
  ☐ 예외를 chain으로 던지지 않음 → 500 방지
  ☐ Authorization 헤더만 허용 (URL 파라미터 방식 금지 — 서버 로그 노출)

토큰 보안
  ☐ 짧은 액세스 토큰 만료 시간 (15분~1시간)
  ☐ 리프레시 토큰은 DB/Redis에 저장 (Stateless 아님)
  ☐ 토큰 블랙리스트: 로그아웃/계정정지 시 Redis에 무효화 토큰 저장
  ☐ 알고리즘: RS256 또는 ES256 (HS256은 시크릿 키 관리 주의)

세션 완전 제거 확인
  ☐ HttpSession 직접 주입 금지
  ☐ @SessionAttributes, @SessionScope 사용 금지
  ☐ Spring MVC FlashAttribute 사용 금지
```

---

## 🤔 트레이드오프

```
Stateless(JWT) vs Stateful(Session):
  Stateless(JWT):
    장점  수평 확장 용이 (서버 공유 상태 없음)
          서비스 간 인증 전파 쉬움 (토큰 그대로 전달)
    단점  토큰 즉시 무효화 불가 (만료 전까지 유효)
          토큰 탈취 시 만료 전까지 악용 가능
          블랙리스트를 위한 Redis 등 저장소 필요하면 "Stateless"가 아님

  Stateful(Session):
    장점  즉각적인 세션 무효화 가능
          서버에서 완전한 제어 가능
    단점  수평 확장 시 공유 세션 저장소 필요
          모바일/앱 클라이언트에서 쿠키 관리 복잡

DB 조회 여부:
  매 요청마다 DB 조회:
    장점  계정 정지/삭제 즉시 반영
    단점  DB 부하, 응답 지연

  JWT 클레임만 사용:
    장점  DB 부하 없음, 빠름
    단점  계정 정지가 토큰 만료 전까지 즉시 반영 안 됨
    → 짧은 토큰 만료 + 리프레시 토큰 + 블랙리스트 조합으로 완화
```

---

## 📌 핵심 정리

```
SessionCreationPolicy.STATELESS 효과
  NullSecurityContextRepository 사용 → 세션에서 로드/저장 안 함
  세션 생성 안 함
  SecurityContext는 요청 범위 메모리에만 존재

매 요청 SecurityContext 재구성
  JwtAuthenticationFilter:
    1. Authorization: Bearer 헤더에서 토큰 추출
    2. 토큰 검증 (서명, 만료)
    3. 클레임에서 사용자 정보 추출
    4. SecurityContextHolder에 Authentication 설정
  요청 완료 시: clearContext() → 메모리에서 제거

NullSecurityContextRepository
  loadDeferredContext(): 항상 빈 SecurityContext 반환
  saveContext(): 아무것도 하지 않음
  → 세션 I/O 없음 → 성능 향상

주의 사항
  HttpSession 직접 사용 시 세션 생성됨 (STATELESS 의도 위반)
  OAuth2, SAML 등 세션을 요구하는 프로토콜과 혼용 주의
```

---

## 🤔 생각해볼 문제

**Q1.** `SessionCreationPolicy.STATELESS` 설정에서 `OAuth2LoginConfigurer`를 함께 사용하면 어떤 문제가 발생하는가? OAuth2 Authorization Code Flow에서 세션이 필요한 이유는 무엇인가?

**Q2.** JWT 액세스 토큰의 만료 시간을 15분으로 설정하고 리프레시 토큰으로 갱신하는 구조에서, 리프레시 토큰을 DB에 저장하면 이미 "완전한 Stateless"가 아닙니다. 그럼에도 이 구조가 순수 세션 기반보다 확장성에서 유리한 이유는?

**Q3.** `JwtAuthenticationFilter`가 매 요청마다 `userDetailsService.loadUserByUsername()`으로 DB를 조회하는 방식과 JWT 클레임에서 직접 `Authentication`을 생성하는 방식을 비교할 때, "계정 정지 즉시 반영"이 필요한 고보안 서비스에서는 어떤 하이브리드 접근법을 설계하겠는가?

> 💡 **해설**
>
> **Q1.** OAuth2 Authorization Code Flow에서는 상태(state) 파라미터를 세션에 저장해 CSRF를 방어합니다. 인가 서버로 리다이렉트 전에 `state` 값을 세션에 저장하고, 콜백 시 세션의 `state`와 비교해 위조 여부를 확인합니다. `STATELESS` 설정에서는 세션에 `state`를 저장할 수 없어 이 검증이 불가능합니다. 또한 `OAuth2AuthorizationRequest`(클라이언트 ID, redirect_uri, scope 등)도 세션에 저장하는데 `STATELESS`에서는 이것도 불가능합니다. 해결 방법으로는 OAuth2 로그인은 별도 `SecurityFilterChain`에서 `IF_REQUIRED` 정책으로 처리하고, OAuth2 로그인 완료 후 JWT 발급 → 이후 API 호출은 `STATELESS` JWT 방식으로 분리하는 구조가 일반적입니다.
>
> **Q2.** 리프레시 토큰을 DB에 저장해도 확장성이 세션 기반보다 유리한 이유는 빈도의 차이입니다. 세션 기반에서는 모든 API 요청(초당 수천 건)이 세션 저장소(Redis)를 조회합니다. 리프레시 토큰 방식에서는 액세스 토큰 검증은 서명만 확인(메모리 연산)하므로 DB/Redis 조회가 없고, 리프레시 토큰 DB 조회는 15분에 한 번만 발생합니다. 즉, "인가 서버"와 "리소스 서버"가 분리된 구조에서 리소스 서버는 완전 Stateless로 운영하고 인가 서버만 DB를 유지합니다. 수평 확장 시 리소스 서버(가장 부하가 많은 서버)는 공유 상태 없이 자유롭게 확장할 수 있습니다.
>
> **Q3.** 하이브리드 접근법으로 짧은 토큰 + Redis 블랙리스트 + 선택적 DB 조회를 조합합니다. 액세스 토큰 만료 시간을 5~15분으로 매우 짧게 설정합니다. 계정 정지/비밀번호 변경 시 해당 사용자의 JWT ID(jti 클레임)를 Redis 블랙리스트에 추가합니다. `JwtAuthenticationFilter`에서 DB 조회 없이 JWT 클레임만 사용하되, Redis 블랙리스트 조회(O(1) 연산)만 수행합니다. 이렇게 하면 DB 조회 비용 없이 계정 정지를 수초 내 반영할 수 있습니다. 리프레시 토큰 갱신 시점에는 DB에서 계정 상태를 확인해 계정이 정지된 경우 리프레시 토큰 발급을 거부합니다. 이 구조는 DB 조회를 "액세스 토큰 만료 시(15분마다)"로 제한하면서도 즉각적인 계정 정지 효과를 줍니다.

---

<div align="center">

**[← 이전: SessionRegistry 활용](./04-session-registry.md)** | **[홈으로 🏠](../README.md)** | **[다음: CSRF Protection 메커니즘 ➡️](./06-csrf-protection.md)**

</div>
