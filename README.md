<div align="center">

# 🔐 Spring Security Deep Dive

**"HTTP 요청이 Filter Chain을 통과해 인증·인가되는 전체 여정"**

<br/>

> *"@PreAuthorize를 쓰는 것과, FilterChainProxy가 15개 Filter를 어떤 순서로 거쳐 인증을 결정하는지 아는 것은 다르다"*

FilterChainProxy.doFilter() 한 줄씩 분석부터 AuthenticationManager → ProviderManager → UserDetailsService 전체 체인,  
JWT 토큰이 SecurityContext에 저장되는 과정, OAuth2 Authorization Code Flow의 모든 단계까지  
**왜 이렇게 설계됐는가** 라는 질문으로 Spring Security 내부를 끝까지 파헤칩니다

<br/>

[![GitHub](https://img.shields.io/badge/GitHub-dev--book--lab-181717?style=flat-square&logo=github)](https://github.com/dev-book-lab)
[![Java](https://img.shields.io/badge/Java-17%2B-orange?style=flat-square&logo=openjdk)](https://www.java.com)
[![Spring Security](https://img.shields.io/badge/Spring_Security-6.x-6DB33F?style=flat-square&logo=springsecurity&logoColor=white)](https://docs.spring.io/spring-security/reference/)
[![Docs](https://img.shields.io/badge/Docs-45개-blue?style=flat-square&logo=readthedocs&logoColor=white)](./README.md)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square&logo=opensourceinitiative&logoColor=white)](./LICENSE)

</div>

---

## 🎯 이 레포에 대하여

Spring Security에 관한 자료는 넘쳐납니다. 하지만 대부분은 **"어떻게 설정하나"** 에서 멈춥니다.

| 일반 자료 | 이 레포 |
|----------|---------|
| `"@PreAuthorize("hasRole('ADMIN')")`를 붙이면 권한 검사가 됩니다" | `FilterSecurityInterceptor`가 `AccessDecisionManager`를 통해 `GrantedAuthority` 목록과 `ConfigAttribute`를 비교하는 Voter 체인 전 과정 |
| `"JWT 필터를 만들어 Security Config에 등록하세요"` | `UsernamePasswordAuthenticationFilter` 앞에 커스텀 `JwtAuthenticationFilter`를 추가했을 때 `SecurityContextHolder`에 `Authentication`이 저장되는 정확한 시점과 `ExceptionTranslationFilter`가 그 뒤를 받는 방식 |
| `"UserDetailsService를 구현하면 됩니다"` | `DaoAuthenticationProvider`가 `UserDetailsService.loadUserByUsername()`을 호출한 뒤 `PasswordEncoder.matches()`로 검증하고 `UsernamePasswordAuthenticationToken`을 생성해 `SecurityContext`에 저장하는 내부 코드 |
| `"OAuth2 로그인은 oauth2Login()으로 설정하세요"` | `OAuth2LoginAuthenticationFilter`가 Authorization Code를 받아 Token Endpoint를 호출하고 `OAuth2User`를 `SecurityContext`에 저장하기까지의 `OAuth2AuthorizationCodeAuthenticationProvider` 전 과정 |
| `"CSRF 토큰을 헤더에 담아야 합니다"` | `CsrfFilter`가 `CsrfTokenRepository`에서 토큰을 로드하고 `X-CSRF-TOKEN` 헤더와 비교하는 시점, `SameSite` 쿠키 정책과의 관계 |
| 이론 나열 | 실행 가능한 코드 + Spring Security 소스코드 직접 추적 + Postman/curl 인증 실험 + `@WithMockUser` 검증 |

---

## 🚀 빠른 시작

각 챕터의 첫 문서부터 바로 학습을 시작하세요!

[![Architecture](https://img.shields.io/badge/🔹_Security_Architecture-FilterChainProxy와_15개_Filter-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](./security-architecture/01-delegating-filter-proxy.md)
[![Authentication](https://img.shields.io/badge/🔹_Authentication_Process-AuthenticationManager_체인-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](./authentication-process/01-authentication-manager-provider-manager.md)
[![Authorization](https://img.shields.io/badge/🔹_Authorization-@PreAuthorize_동작_원리-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](./authorization-method-security/01-pre-authorize-vs-secured.md)
[![Session](https://img.shields.io/badge/🔹_Session_Management-Session_Fixation_방어-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](./session-management/01-session-fixation-attack.md)
[![JWT](https://img.shields.io/badge/🔹_JWT_Authentication-JWT_구조_완전_분석-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](./jwt-authentication/01-jwt-structure-analysis.md)
[![OAuth2](https://img.shields.io/badge/🔹_OAuth2_&_OIDC-Authorization_Code_Flow-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](./oauth2-oidc/01-oauth2-grant-types.md)
[![Advanced](https://img.shields.io/badge/🔹_Advanced_Security-CORS_설정과_Security_Headers-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](./advanced-security/01-cors-configuration.md)

---

## 📚 전체 학습 지도

> 💡 각 섹션을 클릭하면 상세 문서 목록이 펼쳐집니다

<br/>

### 🔹 Chapter 1: Security Architecture

> **핵심 질문:** HTTP 요청이 들어왔을 때 `FilterChainProxy`는 15개 Filter를 정확히 어떤 순서로 실행하는가?

<details>
<summary><b>DelegatingFilterProxy부터 SecurityContext 생명주기까지 완전 분해 (7개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. DelegatingFilterProxy와 FilterChainProxy 관계](./security-architecture/01-delegating-filter-proxy.md) | Servlet Container가 관리하는 `DelegatingFilterProxy`와 Spring이 관리하는 `FilterChainProxy`의 책임 분리, `springSecurityFilterChain` Bean이 등록되는 시점 |
| [02. SecurityFilterChain 구성과 우선순위](./security-architecture/02-security-filter-chain.md) | 여러 `SecurityFilterChain`이 등록될 때 `RequestMatcher`로 체인을 선택하는 과정, `@Order`와 `securityMatcher()`의 상호작용 |
| [03. Security Filter 15개 완전 정복](./security-architecture/03-security-filters-order.md) | `DisableEncodeUrlFilter`부터 `FilterSecurityInterceptor`까지 모든 Filter의 실행 순서·역할·건너뛸 수 있는 조건, `FilterOrderRegistration`에서 순서를 결정하는 방식 |
| [04. SecurityContext & SecurityContextHolder](./security-architecture/04-security-context-holder.md) | `ThreadLocal` 기반 `SecurityContextHolder`가 요청 스레드에 `Authentication`을 저장하고 정리하는 생명주기, `MODE_INHERITABLETHREADLOCAL` 전략과 비동기 환경 함정 |
| [05. Authentication 객체 구조](./security-architecture/05-authentication-object.md) | `Principal`, `Credentials`, `Authorities`의 역할 분리, `UsernamePasswordAuthenticationToken`이 인증 전·후에 다른 필드를 갖는 이유, `isAuthenticated()` 플래그 의미 |
| [06. GrantedAuthority vs Role 차이](./security-architecture/06-granted-authority-vs-role.md) | `ROLE_` 접두사 규칙의 기원, `hasRole()`과 `hasAuthority()`가 내부적으로 다르게 처리되는 방식, `RoleHierarchy`로 계층적 권한을 설정하는 메커니즘 |
| [07. SecurityContextPersistenceFilter 동작](./security-architecture/07-security-context-persistence-filter.md) | 요청 시작 시 `HttpSession`에서 `SecurityContext`를 복원하고 응답 후 저장하는 흐름, `SecurityContextRepository`의 역할, Stateless JWT 환경에서 이 Filter를 비활성화해야 하는 이유 |

</details>

<br/>

### 🔹 Chapter 2: Authentication Process

> **핵심 질문:** 폼 로그인 요청이 들어왔을 때 `AuthenticationManager`는 어떤 경로로 사용자를 인증하는가?

<details>
<summary><b>AuthenticationManager부터 Custom Provider 작성까지 (7개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. AuthenticationManager vs ProviderManager 차이](./authentication-process/01-authentication-manager-provider-manager.md) | `AuthenticationManager` 인터페이스와 `ProviderManager` 구현체의 관계, 부모 `ProviderManager`로 위임하는 계층 구조, 전역 vs 로컬 AuthenticationManager 분리 전략 |
| [02. AuthenticationProvider 체인 동작](./authentication-process/02-authentication-provider-chain.md) | `ProviderManager`가 등록된 Provider를 순서대로 `supports()`로 확인하는 과정, `DaoAuthenticationProvider`·`AnonymousAuthenticationProvider` 등 기본 Provider 목록 |
| [03. UserDetailsService 구현과 커스터마이징](./authentication-process/03-user-details-service.md) | `UserDetailsService.loadUserByUsername()`의 계약, `UserDetails` 인터페이스의 각 필드(`isAccountNonExpired`, `isEnabled` 등)가 인증 흐름에 미치는 영향, 캐싱 전략 |
| [04. PasswordEncoder 종류와 선택](./authentication-process/04-password-encoder.md) | `BCryptPasswordEncoder`·`Argon2PasswordEncoder`·`SCryptPasswordEncoder` 비교, `DelegatingPasswordEncoder`로 여러 인코더를 혼용하는 마이그레이션 전략, 인코딩 업그레이드 |
| [05. UsernamePasswordAuthenticationFilter 분석](./authentication-process/05-username-password-authentication-filter.md) | 폼 로그인 요청이 들어올 때 `attemptAuthentication()` → `successfulAuthentication()` / `unsuccessfulAuthentication()` 흐름, `AuthenticationSuccessHandler`가 호출되는 정확한 시점 |
| [06. Remember-Me 인증 메커니즘](./authentication-process/06-remember-me-authentication.md) | 토큰 기반(`TokenBasedRememberMeServices`)과 영속 토큰 기반(`PersistentTokenBasedRememberMeServices`) 전략 비교, `RememberMeAuthenticationFilter` 실행 조건 |
| [07. Custom Authentication Provider 작성](./authentication-process/07-custom-authentication-provider.md) | `AuthenticationProvider` 구현으로 SMS OTP·API Key 인증 추가, `supports()` 메서드로 처리 가능한 토큰 타입을 선언하는 방식, `AuthenticationManagerBuilder`에 등록하는 방법 |

</details>

<br/>

### 🔹 Chapter 3: Authorization & Method Security

> **핵심 질문:** `@PreAuthorize`가 붙은 메서드는 어떻게 AOP Proxy를 통해 권한 검사를 수행하는가?

<details>
<summary><b>@PreAuthorize 동작 원리부터 Custom Authorization Logic까지 (6개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. @PreAuthorize vs @Secured vs @RolesAllowed](./authorization-method-security/01-pre-authorize-vs-secured.md) | 세 어노테이션의 SpEL 지원 여부·처리 클래스 차이, `@EnableMethodSecurity`와 `@EnableGlobalMethodSecurity(deprecated)` 전환 시 달라지는 동작 |
| [02. Method Security 동작 원리 (AOP Proxy)](./authorization-method-security/02-method-security-aop.md) | `AuthorizationManagerBeforeMethodInterceptor`가 AOP Proxy를 통해 메서드 호출 전에 인터셉트하는 과정, `MethodSecurityExpressionHandler`가 SpEL 컨텍스트를 초기화하는 방식 |
| [03. FilterSecurityInterceptor 내부 구조](./authorization-method-security/03-filter-security-interceptor.md) | URL 기반 접근 제어를 처리하는 `FilterSecurityInterceptor`가 `SecurityMetadataSource`에서 `ConfigAttribute`를 로드하고 `AccessDecisionManager`를 호출하는 전 과정 |
| [04. AccessDecisionManager와 Voter 체인](./authorization-method-security/04-access-decision-manager.md) | `AffirmativeBased`·`ConsensusBased`·`UnanimousBased` 전략 비교, `RoleVoter`·`WebExpressionVoter`·`AuthenticatedVoter`가 각각 `ACCESS_GRANTED`를 반환하는 조건 |
| [05. SpEL을 활용한 복잡한 권한 검사](./authorization-method-security/05-spel-authorization.md) | `@PreAuthorize("@permissionEvaluator.check(#id, authentication)")` 패턴, `PermissionEvaluator` 커스터마이징으로 도메인 객체 기반 권한 검사 구현 |
| [06. Custom Authorization Logic](./authorization-method-security/06-custom-authorization.md) | `AuthorizationManager<MethodInvocation>` 구현으로 어노테이션 없이 동적 권한 검사, `SecurityContextHolder` 없이 `AuthorizationDecision`을 반환하는 함수형 스타일 |

</details>

<br/>

### 🔹 Chapter 4: Session Management

> **핵심 질문:** Session Fixation 공격이란 무엇이며, Spring Security는 이를 어떻게 자동으로 방어하는가?

<details>
<summary><b>Session 보안 공격 방어부터 CSRF Protection까지 (6개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. Session Fixation 공격과 방어](./session-management/01-session-fixation-attack.md) | 공격자가 미리 발급한 Session ID를 피해자에게 심는 공격 메커니즘, Spring Security가 인증 성공 후 `changeSessionId()` 또는 새 세션을 생성해 방어하는 정확한 시점 |
| [02. Concurrent Session Control (동시 로그인 제한)](./session-management/02-concurrent-session-control.md) | `maximumSessions(1)` 설정 시 `SessionAuthenticationStrategy`가 기존 세션을 만료시키는 방식, `ConcurrentSessionFilter`가 만료된 세션 요청을 처리하는 흐름 |
| [03. Session Timeout 처리](./session-management/03-session-timeout.md) | `server.servlet.session.timeout` 설정과 `SessionManagementFilter`의 관계, 세션 만료 후 `InvalidSessionStrategy`가 호출되는 조건, `InvalidSessionUrl` 설정 |
| [04. SessionRegistry 활용](./session-management/04-session-registry.md) | `SessionRegistry`로 현재 로그인한 사용자 목록 조회, 관리자가 특정 사용자의 세션을 강제 종료하는 구현, `SessionInformation.expireNow()`의 동작 방식 |
| [05. Stateless Session (JWT 환경)](./session-management/05-stateless-session.md) | `SessionCreationPolicy.STATELESS` 설정이 `SecurityContextRepository`와 `SessionManagementFilter`에 미치는 영향, 세션 없이 매 요청마다 SecurityContext를 재구성하는 과정 |
| [06. CSRF Protection 메커니즘](./session-management/06-csrf-protection.md) | `CsrfFilter`가 동기화 토큰 패턴으로 요청 위조를 방어하는 원리, `CookieCsrfTokenRepository` vs `HttpSessionCsrfTokenRepository` 차이, REST API에서 CSRF를 비활성화해도 안전한 조건 |

</details>

<br/>

### 🔹 Chapter 5: JWT Authentication

> **핵심 질문:** Custom JWT Filter는 어떻게 토큰을 검증하고 `SecurityContext`에 `Authentication`을 저장하는가?

<details>
<summary><b>JWT 구조 분석부터 Refresh Token Rotation까지 (7개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. JWT 구조 완전 분석 (Header, Payload, Signature)](./jwt-authentication/01-jwt-structure-analysis.md) | Base64URL 인코딩된 세 파트의 역할, `alg`·`typ` 헤더 필드가 검증 알고리즘 선택에 미치는 영향, `iss`·`sub`·`exp`·`iat` 표준 클레임의 의미와 검증 순서 |
| [02. Custom JWT Authentication Filter 작성](./jwt-authentication/02-custom-jwt-filter.md) | `OncePerRequestFilter`를 상속해 `Authorization: Bearer` 헤더를 추출하는 구현, `UsernamePasswordAuthenticationFilter` 앞에 배치해야 하는 이유, `shouldNotFilter()` 패턴 |
| [03. JWT Token 발급 과정 (JwtTokenProvider)](./jwt-authentication/03-jwt-token-provider.md) | `io.jsonwebtoken` 라이브러리로 토큰을 서명하는 과정, `secretKey` 관리 전략 (환경 변수·`@Value`), `Claims`에 `userId`·`roles` 커스텀 클레임을 추가하는 방법 |
| [04. JWT Token 검증과 SecurityContext 저장](./jwt-authentication/04-jwt-validation-security-context.md) | `JwtParser.parseClaimsJws()`가 서명·만료 시간을 검증하는 내부 과정, 검증 성공 후 `Authentication` 객체를 생성해 `SecurityContextHolder`에 저장하는 정확한 코드 경로 |
| [05. Refresh Token 전략 (RTR — Refresh Token Rotation)](./jwt-authentication/05-refresh-token-rotation.md) | Access Token 만료 시 Refresh Token으로 재발급하는 흐름, RTR 전략에서 이전 Refresh Token을 무효화해 탈취 감지하는 방법, Redis 기반 Refresh Token 저장소 구현 |
| [06. Claims 추출과 사용](./jwt-authentication/06-claims-extraction.md) | Filter 이후 Controller에서 `@AuthenticationPrincipal`로 커스텀 `UserDetails`를 주입받는 패턴, `JwtAuthenticationToken.getPrincipal()`에서 Claims를 꺼내 사용하는 방법 |
| [07. JWT Token 만료 및 갱신 처리](./jwt-authentication/07-jwt-expiry-handling.md) | `ExpiredJwtException`이 Filter에서 발생했을 때 `ExceptionTranslationFilter`를 거치지 않고 직접 `401` 응답을 보내야 하는 이유, 만료 5분 전 Silent Refresh 클라이언트 전략 |

</details>

<br/>

### 🔹 Chapter 6: OAuth2 & OpenID Connect

> **핵심 질문:** "카카오로 로그인" 버튼을 눌렀을 때 `OAuth2LoginAuthenticationFilter`는 내부적으로 어떤 일을 하는가?

<details>
<summary><b>OAuth2 Grant Type 분석부터 Resource Server 구현까지 (7개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. OAuth2 4가지 Grant Type](./oauth2-oidc/01-oauth2-grant-types.md) | Authorization Code·Implicit·Resource Owner Password·Client Credentials 각 Grant Type의 사용 시나리오, PKCE 확장이 Authorization Code Flow를 강화하는 방법 |
| [02. Authorization Code Flow 완전 분석](./oauth2-oidc/02-authorization-code-flow.md) | `/oauth2/authorization/{registrationId}` 요청부터 Authorization Code 수신, Token Endpoint 호출, 사용자 정보 로드까지의 10단계 전 과정, `state` 파라미터가 CSRF를 방지하는 방식 |
| [03. OAuth2LoginAuthenticationFilter 동작](./oauth2-oidc/03-oauth2-login-filter.md) | `OAuth2AuthorizationCodeAuthenticationProvider`가 Authorization Code를 Access Token으로 교환하는 과정, `OAuth2UserService`를 호출해 `OAuth2User`를 로드하는 흐름 |
| [04. ClientRegistration과 InMemoryClientRegistrationRepository](./oauth2-oidc/04-client-registration.md) | `ClientRegistration`의 각 필드(`clientId`, `redirectUri`, `scopes`, `authorizationGrantType`)가 실제 HTTP 요청에서 어떻게 사용되는가, Google·Kakao 설정 비교 |
| [05. OAuth2AuthorizedClient 관리](./oauth2-oidc/05-oauth2-authorized-client.md) | `OAuth2AuthorizedClientRepository`가 Access Token을 세션에 저장하는 방식, `@RegisteredOAuth2AuthorizedClient`로 Controller에서 토큰을 주입받는 패턴, 토큰 자동 갱신 |
| [06. Custom OAuth2UserService 작성](./oauth2-oidc/06-custom-oauth2-user-service.md) | `DefaultOAuth2UserService`를 확장해 소셜 계정을 DB 사용자와 연결하는 구현, 첫 로그인 시 회원가입 처리, `OAuth2User`와 `UserDetails`를 통합하는 패턴 |
| [07. JWT Bearer Token Resource Server](./oauth2-oidc/07-resource-server-jwt.md) | `@EnableResourceServer`(deprecated) 대신 `oauth2ResourceServer(jwt())` DSL 설정, `JwtDecoder`가 JWK Set URI에서 공개키를 가져와 서명을 검증하는 과정, scope 기반 권한 매핑 |

</details>

<br/>

### 🔹 Chapter 7: Advanced Security Topics

> **핵심 질문:** 실무에서 자주 마주치는 CORS, Security Headers, 멀티 테넌시 보안 이슈를 어떻게 올바르게 구성하는가?

<details>
<summary><b>CORS 설정부터 Multi-tenancy Security까지 (5개 문서)</b></summary>

<br/>

| 문서 | 다루는 내용 |
|------|------------|
| [01. CORS Configuration (CorsFilter vs @CrossOrigin)](./advanced-security/01-cors-configuration.md) | `CorsFilter`와 `@CrossOrigin`이 처리되는 필터 체인 위치 차이, Preflight 요청(`OPTIONS`)이 인증 필터를 통과해야 하는 이유, `CorsConfigurationSource` 빈 등록 방식 |
| [02. Security Headers (CSP, HSTS, X-Frame-Options)](./advanced-security/02-security-headers.md) | `HeadersConfigurer`가 자동으로 추가하는 헤더 목록, `Content-Security-Policy`로 XSS를 방어하는 디렉티브 구성, HSTS `max-age`와 `includeSubDomains` 설정이 적용되는 조건 |
| [03. Security Events & Listeners](./advanced-security/03-security-events.md) | `AuthenticationSuccessEvent`·`AuthenticationFailureBadCredentialsEvent`·`AuthorizationDeniedEvent`를 `ApplicationListener`로 처리하는 패턴, 로그인 실패 횟수 제한 구현 |
| [04. Method Security with SpEL 고급 활용](./advanced-security/04-method-security-spel-advanced.md) | `@PostFilter`·`@PreFilter`로 컬렉션 반환값·파라미터를 필터링하는 방식, `returnObject`·`filterObject` 내장 변수, 커스텀 `SecurityExpressionRoot`로 도메인 특화 SpEL 함수 추가 |
| [05. Multi-tenancy Security 전략](./advanced-security/05-multi-tenancy-security.md) | 테넌트별 `SecurityFilterChain` 분리 전략, `TenantContextHolder`와 `SecurityContextHolder` 연계, Row-Level Security와 `@PreAuthorize`를 결합한 데이터 격리 패턴 |

</details>

---

## 🗺️ 목적별 학습 경로

<details>
<summary><b>🟢 "Spring Security가 마법처럼 느껴진다" — 핵심 흐름 파악 (1주)</b></summary>

<br/>

```
Day 1  Ch1-01  DelegatingFilterProxy와 FilterChainProxy 관계
Day 2  Ch1-03  Security Filter 15개 완전 정복
Day 3  Ch1-04  SecurityContext & SecurityContextHolder ← 핵심
Day 4  Ch2-01  AuthenticationManager vs ProviderManager
Day 5  Ch2-03  UserDetailsService 구현과 커스터마이징
Day 6  Ch3-01  @PreAuthorize vs @Secured vs @RolesAllowed
Day 7  Ch4-06  CSRF Protection 메커니즘
```

</details>

<details>
<summary><b>🔵 "JWT 인증을 구현했지만 원리를 모른다" — JWT 완전 정복 (1주)</b></summary>

<br/>

```
Day 1  Ch1-04  SecurityContext & SecurityContextHolder
Day 2  Ch1-07  SecurityContextPersistenceFilter 동작
Day 3  Ch4-05  Stateless Session (JWT 환경)
Day 4  Ch5-01  JWT 구조 완전 분석
Day 5  Ch5-02  Custom JWT Authentication Filter 작성
Day 6  Ch5-04  JWT Token 검증과 SecurityContext 저장
Day 7  Ch5-05  Refresh Token 전략 (RTR)
```

</details>

<details>
<summary><b>🟣 "OAuth2 Authorization Code Flow를 설명하지 못한다" — OAuth2 정복 (1주)</b></summary>

<br/>

```
Day 1  Ch6-01  OAuth2 4가지 Grant Type
Day 2  Ch6-02  Authorization Code Flow 완전 분석 ← 핵심
Day 3  Ch6-03  OAuth2LoginAuthenticationFilter 동작
Day 4  Ch6-04  ClientRegistration 구성
Day 5  Ch6-06  Custom OAuth2UserService 작성
Day 6  Ch6-07  JWT Bearer Token Resource Server
Day 7  Ch5-04  SecurityContext에 저장하는 방식 비교 (JWT vs OAuth2)
```

</details>

<details>
<summary><b>🔴 "Spring Security 소스코드를 직접 읽고 내부를 완전히 이해하고 싶다" — 전체 정복 (7주)</b></summary>

<br/>

```
1주차  Chapter 1 전체 — Security Architecture 완전 분해
        → FilterChainProxy.doFilterInternal()에 브레이크포인트를 걸고 15개 Filter 스택 트레이스 확인

2주차  Chapter 2 전체 — Authentication Process 내부
        → DaoAuthenticationProvider.retrieveUser()에서 UserDetailsService 호출 시점 직접 추적

3주차  Chapter 3 전체 — Authorization & Method Security
        → @PreAuthorize가 붙은 메서드 호출 시 AOP Proxy가 개입하는 지점 디버거로 확인

4주차  Chapter 4 전체 — Session Management
        → SessionFixationProtectionStrategy.onAuthentication() 소스 직접 읽기

5주차  Chapter 5 전체 — JWT Authentication
        → JwtAuthenticationFilter에서 SecurityContext에 저장되는 과정을 curl 실험으로 검증

6주차  Chapter 6 전체 — OAuth2 & OpenID Connect
        → OAuth2LoginAuthenticationFilter 소스로 Authorization Code → Access Token 교환 과정 추적

7주차  Chapter 7 전체 — Advanced Topics
        → CorsFilter와 @CrossOrigin이 동시에 설정됐을 때 충돌 시나리오 MockMvc로 재현
```

</details>

---

## 📖 각 문서 구성 방식

모든 문서는 동일한 구조로 작성됩니다.

| 섹션 | 설명 |
|------|------|
| 🎯 **핵심 질문** | 이 문서를 읽고 나면 답할 수 있는 질문 |
| 🔍 **왜 이 보안 메커니즘이 필요한가** | 공격 시나리오와 보안 설계 배경 |
| 😱 **흔한 보안 실수** | Before — 취약한 코드와 그 결과 |
| ✨ **올바른 보안 구현** | After — 안전한 코드와 원리 설명 |
| 🔬 **내부 동작 원리** | Spring Security 소스코드 직접 추적 + ASCII 구조도 |
| 💻 **실험으로 확인하기** | Postman/curl + `@WithMockUser` + 디버거 브레이크포인트 |
| 🔒 **보안 체크리스트** | 이 메커니즘을 도입할 때 반드시 확인할 항목 |
| ⚖️ **트레이드오프** | 이 설계의 장단점, 언제 다른 방법을 택할 것인가 |
| 📌 **핵심 정리** | 한 화면 요약 |
| 🤔 **생각해볼 문제** | 개념을 더 깊이 이해하기 위한 질문 + 해설 |

---

## 🔬 핵심 분석 대상 — FilterChainProxy 요청 흐름

이 레포의 모든 챕터는 아래 Filter 실행 흐름을 완전히 이해하는 것을 목표로 합니다.

```java
// FilterChainProxy.doFilterInternal() — 실행되는 Filter 목록 (순서)
//
// ① Ch1-07 SecurityContextHolderFilter          HTTP Session에서 SecurityContext 복원
// ② Ch4-06 CsrfFilter                           CSRF 토큰 검증
//          CorsFilter                           CORS Preflight 처리
// ③ Ch2-05 UsernamePasswordAuthenticationFilter 폼 로그인 처리
//          JwtAuthenticationFilter (Custom)     JWT 검증 → SecurityContext 저장  ← Ch5
//          BasicAuthenticationFilter            Basic Auth 처리
//          BearerTokenAuthenticationFilter      OAuth2 Resource Server          ← Ch6-07
// ④        RequestCacheAwareFilter              이전 요청 복원
//          SecurityContextHolderAwareRequestFilter
// ⑤        AnonymousAuthenticationFilter        인증 없는 요청에 익명 Authentication 부여
// ⑥ Ch4-01 SessionManagementFilter             세션 고정 방어, 동시 접속 제어
// ⑦        ExceptionTranslationFilter           AuthenticationException → 401
//                                               AccessDeniedException    → 403
// ⑧ Ch3-03 AuthorizationFilter                 URL 기반 권한 검사 (최종 관문)
//
//
// 인증 성공 후 흐름:
// JwtAuthenticationFilter
//   → JwtTokenProvider.validateToken()        서명 + 만료 시간 검증
//   → JwtTokenProvider.getAuthentication()    Claims → UsernamePasswordAuthenticationToken
//   → SecurityContextHolder.setContext()      ThreadLocal에 저장
//   → FilterChain.doFilter()                  다음 Filter로 진행
//   → DispatcherServlet → Controller
```

---

## 🔗 선행 학습 레포지토리

| 레포 | 주요 내용 | 연관 챕터 |
|------|----------|-----------|
| [spring-core-deep-dive](https://github.com/dev-book-lab/spring-core-deep-dive) | IoC 컨테이너, DI, **AOP**, Bean 생명주기, Proxy | Ch3(Method Security AOP Proxy), Ch7(Multi-tenancy) |
| [spring-mvc-deep-dive](https://github.com/dev-book-lab/spring-mvc-deep-dive) | DispatcherServlet, Filter vs Interceptor, ArgumentResolver | Ch1(DelegatingFilterProxy — Servlet Filter 이해 필수), Ch5(JWT Custom Filter 배치) |
| [spring-boot-internals](https://github.com/dev-book-lab/spring-boot-internals) | Auto-configuration, `SecurityAutoConfiguration` | Ch1(SecurityFilterChain 자동 등록 과정) |
| [spring-data-transaction](https://github.com/dev-book-lab/spring-data-transaction) | JPA, 트랜잭션 | Ch2(UserDetailsService DB 조회), Ch5(Refresh Token Redis 저장) |

> 💡 **선행 필수**: Spring Core의 **AOP / Proxy** 개념(Ch3 Method Security), Spring MVC의 **Servlet Filter** 개념(Ch1 FilterChain)이 반드시 필요합니다.  
> 나머지 챕터는 독립적으로 학습 가능합니다.

---

## 🛡️ OWASP Top 10 연계

각 챕터가 방어하는 OWASP 위협 목록입니다.

| OWASP | 위협 | 관련 챕터 |
|-------|------|----------|
| A01 | Broken Access Control | Ch3 Authorization, Ch7 Multi-tenancy |
| A02 | Cryptographic Failures | Ch5 JWT 서명, Ch2 PasswordEncoder |
| A03 | Injection | Ch3 SpEL 안전한 사용 |
| A05 | Security Misconfiguration | Ch1 Filter 순서, Ch7 Security Headers |
| A07 | Identification and Authentication Failures | Ch2 Authentication, Ch4 Session |
| A08 | Software and Data Integrity Failures | Ch5 JWT 검증, Ch6 OAuth2 state |
| A09 | Security Logging and Monitoring Failures | Ch7 Security Events |

---

## 🙏 Reference

- [Spring Security Reference Documentation](https://docs.spring.io/spring-security/reference/)
- [Spring Security Source Code (GitHub)](https://github.com/spring-projects/spring-security)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [jwt.io — JWT Debugger](https://jwt.io/)
- [Baeldung Spring Security Guides](https://www.baeldung.com/security-spring)

---

<div align="center">

**⭐️ 도움이 되셨다면 Star를 눌러주세요!**

Made with ❤️ by [Dev Book Lab](https://github.com/dev-book-lab)

<br/>

*"@PreAuthorize를 쓰는 것과, FilterChainProxy가 15개 Filter를 어떤 순서로 거쳐 인증을 결정하는지 아는 것은 다르다"*

</div>
