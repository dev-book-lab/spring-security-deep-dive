# JWT Bearer Token Resource Server — JwkSet URI 검증과 Scope 기반 권한 매핑

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `oauth2ResourceServer(jwt())` DSL 설정이 등록하는 Filter와 Converter는?
- `JwtDecoder`가 JWK Set URI에서 공개키를 가져와 서명을 검증하는 과정은?
- `NimbusJwtDecoder`가 JWK Set을 캐싱하고 키 교체(Key Rotation)를 처리하는 방법은?
- `scope` 클레임이 Spring Security의 `GrantedAuthority`로 변환되는 과정은?
- 커스텀 `JwtAuthenticationConverter`로 scope가 아닌 roles 클레임을 권한으로 매핑하는 방법은?
- `@EnableResourceServer`(deprecated)와 `oauth2ResourceServer()` DSL의 핵심 차이는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### Resource Server의 역할

```
OAuth2 생태계에서의 역할 분리:

  인가 서버 (Authorization Server):
    → 사용자 인증, Access Token 발급, Refresh Token 관리
    → Spring Authorization Server, Keycloak, Auth0 등

  ★ 리소스 서버 (Resource Server): 이 문서
    → Access Token을 검증하고 보호된 API 제공
    → 인가 서버의 공개키(JWK Set)로 JWT 서명 검증
    → scope/role 기반 권한 제어

  클라이언트 앱:
    → 인가 서버에서 Access Token 발급
    → Resource Server API 호출 (Bearer 토큰 첨부)

Resource Server가 JWT를 직접 검증하는 이유:
  → Introspection 방식 (인가 서버에 매번 검증 요청): 지연, 단일 실패 지점
  → JWT 로컬 검증 (공개키 캐싱): 빠름, 확장성 우수
  → 인가 서버 없이 서명만으로 검증 → 분산 환경에 적합
```

---

## 😱 흔한 보안 실수

### Before: scope 없이 모든 JWT를 그대로 허용

```java
// ❌ JWT 서명만 검증하고 scope/claims를 확인하지 않음
// → 인가 서버에서 발급한 어떤 토큰이든 모든 API 허용
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2
        .jwt(Customizer.withDefaults()) // 서명만 검증
    )
    .authorizeHttpRequests(auth -> auth
        .anyRequest().authenticated() // ← scope 검증 없음
    );
    return http.build();
}

// ✅ scope 기반 접근 제어 필수
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(HttpMethod.GET, "/api/orders/**")
        .hasAuthority("SCOPE_orders:read")  // scope 검증
    .requestMatchers(HttpMethod.POST, "/api/orders")
        .hasAuthority("SCOPE_orders:write")
    .anyRequest().authenticated()
);
```

### Before: jwkSetUri 없이 자체 서명 키 사용 (마이크로서비스)

```java
// ❌ 모든 리소스 서버에 동일 secretKey 공유
// → secretKey 노출 시 모든 서버 위험
// → 키 교체 시 모든 서버 동시 업데이트 필요
@Bean
public JwtDecoder jwtDecoder(@Value("${jwt.secret}") String secret) {
    return NimbusJwtDecoder.withSecretKey(
        new SecretKeySpec(Decoders.BASE64.decode(secret), "HmacSHA256")
    ).build();
}

// ✅ RS256 + jwkSetUri 사용 (인가 서버의 공개키로 검증)
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withJwkSetUri(
        "https://auth-server/.well-known/jwks.json"
    ).build();
    // → 인가 서버만 privateKey 보유
    // → 리소스 서버는 공개키로 검증 (배포 안전)
    // → 키 교체: JWKS에 새 키 추가 → 리소스 서버 자동 갱신
}
```

---

## ✨ 올바른 보안 구현

### Resource Server 완전 설정

```java
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            // ① Resource Server 설정
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())              // JwtDecoder 지정
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                    // scope → SCOPE_xxx + roles → ROLE_xxx 매핑
                )
                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                // → 401: WWW-Authenticate: Bearer realm="..."
                .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                // → 403: WWW-Authenticate: Bearer error="insufficient_scope"
            )
            // ② scope 기반 접근 제어
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/api/orders/**")
                    .hasAuthority("SCOPE_orders:read")
                .requestMatchers(HttpMethod.POST, "/api/orders")
                    .hasAuthority("SCOPE_orders:write")
                .requestMatchers("/api/admin/**")
                    .hasRole("ADMIN")              // ROLE_ 자동 추가
                .anyRequest().authenticated()
            );
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
            .withJwkSetUri("https://auth-server/.well-known/jwks.json")
            .build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter =
            new JwtGrantedAuthoritiesConverter();
        // 기본: scope → SCOPE_xxx
        // 커스텀: roles → ROLE_xxx
        authoritiesConverter.setAuthoritiesClaimName("roles"); // 클레임명
        authoritiesConverter.setAuthorityPrefix("ROLE_");      // 접두사

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
```

---

## 🔬 내부 동작 원리

### 1. oauth2ResourceServer(jwt()) 등록 컴포넌트

```java
// OAuth2ResourceServerConfigurer.jwt() 처리 시 등록되는 것들:

// ① BearerTokenAuthenticationFilter (순서: ~1)
//    → Authorization: Bearer 헤더 추출
//    → BearerTokenExtractor: "Bearer " 이후 토큰 문자열 추출
//    → JwtDecoder.decode(token) → Jwt 객체 (파싱 + 검증)
//    → JwtAuthenticationConverter.convert(jwt) → AbstractAuthenticationToken
//    → SecurityContextHolder에 저장

// ② JwtDecoder (NimbusJwtDecoder)
//    → JWKS 조회 + 캐싱
//    → JWT 파싱, 서명 검증, 클레임 추출

// ③ JwtAuthenticationConverter
//    → Jwt → JwtAuthenticationToken (Authentication)
//    → JwtGrantedAuthoritiesConverter: scope 클레임 → GrantedAuthority

// ④ BearerTokenAuthenticationEntryPoint
//    → 401 응답 시 WWW-Authenticate: Bearer realm="..." 헤더 추가

// 요청 처리 흐름:
// BearerTokenAuthenticationFilter
// → "Bearer eyJ..." 추출
// → NimbusJwtDecoder.decode():
//    JWKS 캐시에서 kid로 PublicKey 조회
//    RSA_VERIFY(header.payload, signature, publicKey)
//    exp, iss 등 클레임 검증
// → JwtAuthenticationConverter.convert(jwt):
//    scope 클레임 → SCOPE_orders:read 등 GrantedAuthority
// → JwtAuthenticationToken (isAuthenticated=true) → SecurityContext
```

### 2. NimbusJwtDecoder — JWK Set 캐싱과 Key Rotation

```java
// NimbusJwtDecoder 내부 동작:

// 초기화:
NimbusJwtDecoder decoder = NimbusJwtDecoder
    .withJwkSetUri("https://auth-server/.well-known/jwks.json")
    // JwkSet 캐싱 전략 설정 (선택):
    .cache(Cache.of(100, Duration.ofMinutes(5))) // 최대 100개, 5분 캐시
    .build();

// 검증 흐름:
// 1. JWT Header에서 kid (Key ID) 추출
// 2. JwkSetCache에서 해당 kid의 PublicKey 조회
// 3. 캐시 미스: JWKS URI에서 최신 키 목록 다운로드
// 4. RSA_VERIFY(header.payload, signature, publicKey) 검증
// 5. 클레임(exp, iss, aud 등) 검증

// Key Rotation 지원:
// 인가 서버가 새 키로 교체 시:
// → 새 kid가 JWT Header에 설정됨
// → 리소스 서버: 캐시에 새 kid 없음 → JWKS 재조회
// → 새 PublicKey 캐시 후 검증 성공
// → 무중단 키 교체 가능

// 직접 PublicKey로 JwtDecoder 생성 (JWKS 없는 경우):
RSAPublicKey publicKey = ...; // PEM 파일 로드
NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
```

### 3. scope 클레임 → GrantedAuthority 변환

```java
// JWT 예시 (인가 서버가 발급):
// {
//   "iss": "https://auth-server",
//   "sub": "user-123",
//   "scope": "orders:read orders:write profile",  // 공백 구분
//   "roles": ["ADMIN", "USER"],                   // 배열 형태
//   "exp": 1700003599
// }

// 기본 변환 (JwtGrantedAuthoritiesConverter):
// scope 클레임 → 공백 분리 → "SCOPE_" 접두사 추가
// "orders:read orders:write profile"
// → SCOPE_orders:read, SCOPE_orders:write, SCOPE_profile

// Spring Security 권한 체크:
// .hasAuthority("SCOPE_orders:read")  ← SCOPE_ 접두사 명시 필요
// .hasAuthority("orders:read")        ← 이렇게 하면 안 됨 (접두사 불일치)

// 커스텀 변환 (roles 클레임):
JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
converter.setAuthoritiesClaimName("roles"); // "roles" 클레임 사용
converter.setAuthorityPrefix("ROLE_");      // "ROLE_" 접두사
// ["ADMIN", "USER"] → ROLE_ADMIN, ROLE_USER

// 복합 변환 (scope + roles 모두):
@Bean
public JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter scopeConverter =
        new JwtGrantedAuthoritiesConverter(); // scope → SCOPE_*

    JwtGrantedAuthoritiesConverter roleConverter =
        new JwtGrantedAuthoritiesConverter();
    roleConverter.setAuthoritiesClaimName("roles");
    roleConverter.setAuthorityPrefix("ROLE_");

    // 두 변환 결과를 합산
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(jwt -> {
        Collection<GrantedAuthority> scopes = scopeConverter.convert(jwt);
        Collection<GrantedAuthority> roles  = roleConverter.convert(jwt);
        List<GrantedAuthority> all = new ArrayList<>(scopes);
        all.addAll(roles);
        return all;
    });
    return converter;
}

// 권한 체크:
.requestMatchers("/api/orders").hasAuthority("SCOPE_orders:read") // scope
.requestMatchers("/api/admin").hasRole("ADMIN")                   // role
```

### 4. @EnableResourceServer (deprecated) vs oauth2ResourceServer() DSL

```
@EnableResourceServer (Spring Security OAuth2 5.x 이전):
  → 별도 spring-security-oauth2 의존성 필요
  → ResourceServerConfigurerAdapter 상속해 설정
  → DefaultTokenServices, TokenStore 등 구버전 API
  → Spring Security 6.x에서 미지원

oauth2ResourceServer() DSL (현재 표준):
  → Spring Security 5.1+에서 통합 지원
  → spring-security-oauth2-resource-server 의존성
  → JwtDecoder, JwtAuthenticationConverter API
  → BearerTokenAuthenticationFilter (새로운 필터)
  → Opaque Token 지원 (TokenIntrospection)

마이그레이션:
  spring-security-oauth2 (구버전 의존성) 제거
  spring-boot-starter-oauth2-resource-server 추가
  ResourceServerConfigurerAdapter → SecurityFilterChain @Bean으로 전환
```

### 5. Opaque Token vs JWT — Resource Server 선택

```java
// Opaque Token 방식 (Introspection):
// → 인가 서버에 매 요청마다 검증 요청
// → 인가 서버가 토큰 상태를 중앙에서 관리
// → 즉시 무효화 가능
http.oauth2ResourceServer(oauth2 -> oauth2
    .opaqueToken(opaque -> opaque
        .introspectionUri("https://auth-server/oauth2/introspect")
        .introspectionClientCredentials(clientId, clientSecret)
    )
);

// JWT 방식 (로컬 검증):
// → JWK Set으로 로컬에서 서명 검증 (인가 서버 없이)
// → 즉시 무효화 불가 (만료 전까지 유효)
// → 인가 서버 부하 없음, 지연 없음
http.oauth2ResourceServer(oauth2 -> oauth2
    .jwt(jwt -> jwt.jwkSetUri("https://auth-server/.well-known/jwks.json"))
);

// 선택 기준:
// 즉시 무효화 중요 → Opaque Token
// 성능/확장성 중요 → JWT (짧은 만료 + 블랙리스트 조합)
```

---

## 💻 실험으로 확인하기

### 실험 1: JWT 검증 및 scope 권한 확인

```bash
# Resource Server에 Bearer 토큰으로 API 호출
TOKEN="eyJ..." # 인가 서버에서 발급된 JWT

# scope=orders:read 있는 토큰 → 성공
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/orders
# → 200 OK

# scope=orders:write 없는 토큰 → 거부
curl -H "Authorization: Bearer $TOKEN" \
  -X POST http://localhost:8080/api/orders \
  -d '{"item":"book"}'
# → 403 Forbidden
# WWW-Authenticate: Bearer error="insufficient_scope"

# 토큰 없이 요청
curl http://localhost:8080/api/orders
# → 401 Unauthorized
# WWW-Authenticate: Bearer realm="..."
```

### 실험 2: JWKS 캐시 동작 확인 (Key Rotation)

```java
@Test
void jwksCache_refreshedOnNewKid() {
    // given: 기존 kid로 서명된 토큰
    String oldToken = signWithKey("kid-1", oldPrivateKey);

    // JwtDecoder는 kid-1을 캐시에 가지고 있음
    assertDoesNotThrow(() -> jwtDecoder.decode(oldToken));

    // when: 인가 서버가 새 키로 교체
    mockJwksEndpoint.respondWith(newJwks); // kid-1, kid-2 포함
    String newToken = signWithKey("kid-2", newPrivateKey);

    // then: kid-2가 캐시 미스 → JWKS 재조회 → 검증 성공
    assertDoesNotThrow(() -> jwtDecoder.decode(newToken));
}
```

### 실험 3: scope 변환 결과 확인

```java
@Test
void scopeClaim_convertedTo_scopeAuthorities() {
    Jwt jwt = Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .claim("scope", "orders:read orders:write")
        .claim("roles", List.of("ADMIN"))
        .build();

    JwtAuthenticationConverter converter = jwtAuthenticationConverter();
    AbstractAuthenticationToken token = converter.convert(jwt);

    assertThat(token.getAuthorities())
        .extracting(GrantedAuthority::getAuthority)
        .containsExactlyInAnyOrder(
            "SCOPE_orders:read",   // scope → SCOPE_ 접두사
            "SCOPE_orders:write",
            "ROLE_ADMIN"           // roles → ROLE_ 접두사
        );
}
```

---

## 🔒 보안 체크리스트

```
JwtDecoder 설정
  ☐ jwkSetUri 설정: 인가 서버의 JWK Set 엔드포인트
  ☐ iss(Issuer) 검증 설정: 다른 인가 서버의 토큰 거부
  ☐ aud(Audience) 검증 설정: 다른 리소스 서버용 토큰 거부
  ☐ JWKS 캐시 TTL 설정 (기본값 확인)

scope/role 기반 접근 제어
  ☐ 모든 API 엔드포인트에 scope 또는 role 검증 적용
  ☐ SCOPE_ 접두사 확인 (hasAuthority("SCOPE_xxx"))
  ☐ anyRequest().authenticated()만으로는 부족

보안 강화
  ☐ iss 검증 설정 (인가 서버 위장 방지)
  ☐ aud 검증 설정 (cross-service token 재사용 방지)
  ☐ exp 검증은 자동 (NimbusJwtDecoder 기본)
  ☐ 짧은 Access Token 수명 (1시간 이하)
```

---

## 🤔 트레이드오프

```
JWT 로컬 검증 vs Opaque Token Introspection:
  JWT:
    장점  인가 서버 없이 로컬 검증 → 빠름, 확장성
    단점  즉시 무효화 불가 (블랙리스트 필요)

  Opaque Token:
    장점  즉시 무효화 가능 (인가 서버에서 삭제)
    단점  매 요청 인가 서버 호출 → 지연, 단일 실패 지점

jwkSetUri vs publicKey 직접 설정:
  jwkSetUri:
    장점  Key Rotation 자동 지원, 인가 서버와 연동
    단점  인가 서버 의존성 (인가 서버 장애 시 JWKS 로드 실패)

  publicKey 직접:
    장점  인가 서버 없이 동작
    단점  Key Rotation 시 모든 리소스 서버 재배포 필요

scope vs roles 기반 권한:
  scope:
    장점  OAuth2 표준 (클라이언트가 요청한 권한 범위)
    → "orders:read", "profile" 등 세밀한 API 권한

  roles:
    장점  직관적 (ADMIN, USER 등 사용자 역할)
    단점  OAuth2 스펙 외 커스텀 클레임
    → 커스텀 JwtGrantedAuthoritiesConverter 필요
```

---

## 📌 핵심 정리

```
oauth2ResourceServer(jwt()) 등록 컴포넌트
  BearerTokenAuthenticationFilter: Bearer 헤더 추출 + JWT 검증
  NimbusJwtDecoder: JWKS 조회, 서명 검증, 클레임 파싱
  JwtAuthenticationConverter: JWT → JwtAuthenticationToken + GrantedAuthority

JWK Set 검증 흐름
  JWT Header kid → JWKS 캐시 조회 → 미스: JWKS URI 재조회
  RSA_VERIFY(header.payload, sig, publicKey) → 성공 → 클레임 검증

scope → GrantedAuthority 기본 변환
  scope 클레임 공백 분리 → "SCOPE_" 접두사 추가
  .hasAuthority("SCOPE_orders:read")로 검증

커스텀 변환 (roles 클레임)
  JwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles")
  .setAuthorityPrefix("ROLE_")
  → .hasRole("ADMIN")으로 검증

@EnableResourceServer vs oauth2ResourceServer():
  @EnableResourceServer: deprecated (Spring Security 6.x 미지원)
  oauth2ResourceServer(): 현재 표준, spring-boot-starter-oauth2-resource-server
```

---

## 🤔 생각해볼 문제

**Q1.** `NimbusJwtDecoder`가 JWKS를 캐싱하는 중에 인가 서버가 완전히 다운됐습니다. 캐시 TTL이 5분인 경우 최대 5분까지는 기존 캐시로 검증이 가능합니다. 캐시가 만료된 후에는 JWKS 재조회 실패로 모든 API 요청이 실패합니다. 이 단일 실패 지점(SPOF) 문제를 완화하는 방법은?

**Q2.** 마이크로서비스 A, B, C가 모두 같은 인가 서버에서 발급한 JWT를 검증합니다. 클라이언트가 서비스 A에서 발급받은 토큰을 직접 서비스 B의 API에 사용하면 어떻게 되는가? `aud` 클레임 검증이 없는 경우와 있는 경우를 비교하라.

**Q3.** JWT의 `scope` 클레임에 `"admin"` 값을 추가해 `.hasAuthority("SCOPE_admin")`으로 관리자 기능을 제어하는 방식과, `roles` 클레임에 `["ADMIN"]`을 추가해 `.hasRole("ADMIN")`으로 제어하는 방식의 보안적 차이는?

> 💡 **해설**
>
> **Q1.** JWKS 단일 실패 지점 완화 방법: 첫째, Stale-While-Revalidate 패턴: 캐시가 만료되더라도 새로운 JWKS 로드가 실패하면 기존 캐시를 일정 시간(예: 추가 1시간) 더 사용합니다. `NimbusJwtDecoder`에 커스텀 `JWKSource`를 주입해 이 동작을 구현합니다. 둘째, 다중 JWKS URI: 인가 서버를 다중화하고 JWKS URI도 로드 밸런서 뒤에 배치합니다. 셋째, JWKS 스냅샷을 로컬 파일/캐시에 주기적으로 저장하고 JWKS 로드 실패 시 스냅샷을 폴백으로 사용합니다. 넷째, Circuit Breaker 패턴으로 JWKS 로드 실패 시 빠르게 실패 처리하고 복구를 시도합니다.
>
> **Q2.** `aud` 검증이 없는 경우: 서비스 A용 토큰이 서비스 B에서 그대로 수락됩니다. 공격자가 서비스 A에서 유효하게 얻은 토큰을 서비스 B로 재사용할 수 있습니다(토큰 혼용 공격). `aud` 검증이 있는 경우: 서비스 A용 토큰의 `aud=service-a`이고 서비스 B가 `.requireAudience("service-b")`를 설정하면 검증 실패 → 403입니다. 인가 서버는 클라이언트가 특정 서비스를 위한 토큰을 요청할 때 `aud` 클레임에 해당 서비스 식별자를 포함시켜야 합니다. Spring Security에서 설정: `NimbusJwtDecoder.withJwkSetUri(...).jwtProcessorCustomizer(processor -> processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder().audience("service-b").build(), ...)))`.
>
> **Q3.** 보안적 차이는 토큰 발급 권한에 있습니다. `scope` 기반: 클라이언트(앱)가 인가 요청 시 `scope=admin`을 명시해야 합니다. 인가 서버는 사용자가 실제로 admin 권한을 가졌는지 확인 후 scope를 포함할지 결정합니다. OAuth2 스펙에서 scope는 클라이언트가 요청하는 권한 범위이므로, 인가 서버가 사용자 권한을 기반으로 실제 부여할 scope를 결정합니다. `roles` 기반: 커스텀 클레임이므로 인가 서버 구현에 따라 다릅니다. 일반적으로 사용자의 DB 역할을 그대로 토큰에 포함합니다. 두 방식 모두 인가 서버가 올바르게 구현됐다면 보안은 동일합니다. 실무에서는 API 접근 권한에는 `scope`(세밀한 권한), 사용자 역할에는 `roles`를 함께 사용하는 것이 관례입니다.

---

<div align="center">

**[← 이전: Custom OAuth2UserService 작성](./06-custom-oauth2-user-service.md)** | **[홈으로 🏠](../README.md)** | **[Chapter 7으로 이동: Advanced Security ➡️](../advanced-security/01-cors-configuration.md)**

</div>
