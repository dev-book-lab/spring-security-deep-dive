# CORS Configuration — CorsFilter vs @CrossOrigin과 Preflight 처리

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `CorsFilter`와 `@CrossOrigin`이 처리되는 필터 체인 위치 차이는?
- Preflight 요청(`OPTIONS`)이 인증 필터를 통과해야 하는 이유와 통과 방법은?
- `CorsConfigurationSource` Bean을 등록하는 올바른 방법은?
- CORS 오류가 `401`/`403`으로 응답되는 근본 원인은?
- `allowedOrigins`와 `allowedOriginPatterns`의 차이는?
- `allowCredentials(true)`와 `allowedOrigins("*")`를 동시에 설정할 수 없는 이유는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### CORS가 보안에서 중요한 이유

```
Same-Origin Policy (동일 출처 정책):
  브라우저는 스크립트가 다른 출처(origin)의 리소스에 접근하는 것을 차단
  → origin = scheme + host + port

  origin 예시:
    https://app.com      (기준)
    https://api.app.com  ← 다른 origin (host 다름)
    http://app.com       ← 다른 origin (scheme 다름)
    https://app.com:8080 ← 다른 origin (port 다름)

CORS (Cross-Origin Resource Sharing):
  서버가 "이 출처는 내 리소스에 접근해도 된다"고 브라우저에 알리는 메커니즘
  응답 헤더: Access-Control-Allow-Origin: https://app.com

  CORS 없이 크로스 오리진 API 호출 시:
  브라우저: "api.app.com은 네 출처(app.com)와 달라. 서버 응답을 차단한다"
  → CORS 오류 (서버는 200 응답했지만 브라우저가 차단)

Preflight Request (사전 요청):
  GET, HEAD, POST(단순 Content-Type) 외 요청은 먼저 OPTIONS로 확인
  브라우저: "api.app.com, app.com이 PUT /api/data를 요청해도 되나요?"
  서버: "네, Access-Control-Allow-Origin: https://app.com으로 허용합니다"
  브라우저: "확인됐습니다. 실제 PUT 요청을 보냅니다"
```

---

## 😱 흔한 보안 실수

### Before: Preflight OPTIONS 요청이 401로 거부

```java
// ❌ 문제: OPTIONS Preflight가 인증 필터에서 차단됨
// JwtAuthenticationFilter → OPTIONS에도 Authorization 헤더 요구
// → 브라우저는 Preflight에 인증 헤더를 포함하지 않음
// → 401 응답 → 브라우저: "CORS 실패"

// 증상: 실제 요청은 성공하지만 Preflight OPTIONS가 401 반환
// 브라우저 콘솔: "CORS preflight channel did not succeed"

// ✅ CORS 설정을 인증 필터보다 먼저 처리
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        // CORS를 Security 체인에 통합 (CorsFilter가 인증 전에 실행)
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        // CORS 처리 후 OPTIONS는 permitAll로 통과
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Preflight
            .anyRequest().authenticated()
        );
    return http.build();
}
```

### Before: allowedOrigins("*") + allowCredentials(true) 조합

```java
// ❌ 보안 위반: credentials=true이면 와일드카드 origin 허용 불가
CorsConfiguration config = new CorsConfiguration();
config.addAllowedOrigin("*");           // 모든 출처
config.setAllowCredentials(true);       // 쿠키/인증 허용
// → IllegalArgumentException 또는 브라우저 거부

// 이유:
// allowedOrigins("*") + credentials(true) = 공격자 사이트도 쿠키 첨부 가능
// → CSRF와 동일한 위험 → 브라우저가 CORS 스펙으로 금지

// ✅ 특정 출처만 명시 + credentials 허용
config.addAllowedOrigin("https://app.com");
config.setAllowCredentials(true);        // 특정 출처 + 쿠키 허용

// 또는 패턴으로:
config.addAllowedOriginPattern("https://*.app.com"); // 서브도메인 허용
config.setAllowCredentials(true);
```

---

## ✨ 올바른 보안 구현

### CorsConfigurationSource Bean 완전 설정

```java
@Configuration
@EnableWebSecurity
public class CorsSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable()) // REST API + JWT
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // ── 허용 출처 ──────────────────────────────────────────
        // 개발 환경:
        config.setAllowedOrigins(List.of(
            "http://localhost:3000",    // React 개발 서버
            "http://localhost:5173"     // Vite 개발 서버
        ));
        // 운영 환경 (환경 변수로 분리 권장):
        // config.setAllowedOriginPatterns(List.of("https://*.myapp.com"));

        // ── 허용 HTTP 메서드 ──────────────────────────────────
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE",
            "PATCH", "OPTIONS"));

        // ── 허용 헤더 ─────────────────────────────────────────
        config.setAllowedHeaders(List.of(
            "Authorization",        // Bearer 토큰
            "Content-Type",
            "X-Requested-With",
            "X-CSRF-TOKEN"          // CSRF 토큰 (세션 기반 시)
        ));

        // ── 클라이언트에 노출할 응답 헤더 ────────────────────
        config.setExposedHeaders(List.of(
            "Authorization",        // 갱신된 토큰을 응답 헤더에 포함 시
            "X-Total-Count"         // 페이징: 전체 건수
        ));

        // ── 자격증명 허용 (쿠키, Authorization 헤더) ─────────
        config.setAllowCredentials(true);

        // ── Preflight 캐시 시간 (초) ──────────────────────────
        config.setMaxAge(3600L); // 1시간: 브라우저가 Preflight 결과 캐시

        UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config); // API 경로만 적용
        return source;
    }
}
```

---

## 🔬 내부 동작 원리

### 1. CorsFilter vs @CrossOrigin 처리 위치

```
필터 체인에서의 위치:

  CorsFilter (등록 위치에 따름, Security 설정 시 인증 필터 앞)
  ↓
  SecurityContextHolderFilter (100)
  ↓
  JwtAuthenticationFilter (커스텀)
  ↓
  AuthorizationFilter (3600)
  ↓
  DispatcherServlet
  ↓
  @CrossOrigin (HandlerInterceptor 또는 @CrossOrigin 어노테이션 처리)

CorsFilter (FilterChain 레벨):
  → 모든 요청에 대해 CORS 헤더 처리
  → OPTIONS Preflight를 인증 필터 전에 처리 가능
  → Security 설정에서 .cors()로 통합 시 자동으로 올바른 위치에 삽입

@CrossOrigin (Controller 레벨):
  → DispatcherServlet 이후 처리 → 이미 인증 필터를 통과한 후
  → OPTIONS Preflight가 인증 필터에서 차단될 수 있음
  → Spring MVC 컨트롤러에 개별 설정 시 사용

핵심 차이:
  .cors() + CorsConfigurationSource → 인증 필터 전에 CORS 처리 가능
  @CrossOrigin만 → OPTIONS가 JwtAuthenticationFilter에서 401 반환 가능
```

### 2. http.cors()가 등록하는 것

```java
// CorsConfigurer.configure() 내부:
// http.cors() 설정 시:

// ① CorsFilter를 Security 필터 체인의 앞부분에 삽입
// 정확한 순서: SecurityContextHolderFilter 앞 (순서 값 = -1)

// ② CorsFilter 내부 동작:
public class CorsFilter extends OncePerRequestFilter {

    private final CorsConfigurationSource configSource;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) {

        CorsConfiguration corsConfiguration = configSource
            .getCorsConfiguration(request);

        boolean isValid = corsProcessor.processRequest(
            corsConfiguration, request, response);

        if (!isValid || CorsUtils.isPreFlightRequest(request)) {
            // ★ Preflight(OPTIONS): CORS 헤더 추가 후 즉시 응답 (인증 불필요)
            return;
        }

        // 일반 요청: CORS 헤더 추가 후 다음 필터로
        filterChain.doFilter(request, response);
    }
}

// CorsUtils.isPreFlightRequest():
// OPTIONS 메서드 + Origin 헤더 + Access-Control-Request-Method 헤더
// → 세 조건 모두 충족 시 Preflight로 판단
```

### 3. Preflight 요청 흐름 상세

```
브라우저 → React SPA에서 PUT /api/orders 호출 시:

  1단계: Preflight 요청
  OPTIONS /api/orders HTTP/1.1
  Origin: http://localhost:3000
  Access-Control-Request-Method: PUT
  Access-Control-Request-Headers: Authorization, Content-Type

  ★ CorsFilter가 처리:
  → CorsConfiguration 조회
  → Origin 허용 여부 확인
  → 허용 메서드/헤더 확인
  → Preflight이면 즉시 응답 (인증 필터 통과 안 함!)

  서버 → 브라우저:
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: http://localhost:3000
  Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
  Access-Control-Allow-Headers: Authorization, Content-Type
  Access-Control-Allow-Credentials: true
  Access-Control-Max-Age: 3600

  2단계: 실제 요청 (Preflight 성공 후)
  PUT /api/orders HTTP/1.1
  Origin: http://localhost:3000
  Authorization: Bearer eyJ...
  Content-Type: application/json

  서버 → CorsFilter → JwtAuthenticationFilter → AuthorizationFilter → Controller
  응답에 Access-Control-Allow-Origin 헤더 포함
```

### 4. allowedOrigins vs allowedOriginPatterns

```java
// allowedOrigins: 정확한 출처 문자열 매칭
config.setAllowedOrigins(List.of(
    "https://app.com",
    "https://www.app.com"
));
// → "https://beta.app.com" 불허

// allowedOriginPatterns: 와일드카드 패턴 (allowCredentials와 함께 사용 가능)
config.setAllowedOriginPatterns(List.of(
    "https://*.app.com",     // 서브도메인 모두 허용
    "http://localhost:[*]"   // localhost의 모든 포트
));
config.setAllowCredentials(true); // 패턴 + credentials 조합 가능

// 차이점:
// allowedOrigins("*") + allowCredentials(true) → 금지 (브라우저 스펙)
// allowedOriginPatterns("*") + allowCredentials(true) → 허용되지만 보안 위험
// → allowedOriginPatterns에 "https://*.app.com" 같은 제한적 패턴 사용 권장
```

### 5. 환경별 CORS 설정 분리

```java
@Configuration
public class CorsConfig {

    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Value("${app.cors.allowed-origin-patterns:}")
    private List<String> allowedOriginPatterns;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        if (!allowedOriginPatterns.isEmpty()) {
            config.setAllowedOriginPatterns(allowedOriginPatterns);
        } else {
            config.setAllowedOrigins(allowedOrigins);
        }

        config.setAllowedMethods(List.of("*"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

# application-dev.yml
app.cors.allowed-origins: http://localhost:3000, http://localhost:5173

# application-prod.yml
app.cors.allowed-origin-patterns: https://*.myapp.com
```

---

## 💻 실험으로 확인하기

### 실험 1: Preflight 수동 테스트

```bash
# Preflight 요청 직접 발송
curl -v -X OPTIONS http://localhost:8080/api/orders \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: Authorization, Content-Type"

# 기대 응답 헤더:
# < HTTP/1.1 200 OK
# < Access-Control-Allow-Origin: http://localhost:3000
# < Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
# < Access-Control-Allow-Headers: Authorization,Content-Type
# < Access-Control-Allow-Credentials: true
# < Access-Control-Max-Age: 3600

# 인증 없이도 200 응답 → Preflight가 인증 필터 통과 확인
```

### 실험 2: 허용되지 않은 출처 차단 확인

```bash
# 등록되지 않은 출처로 요청
curl -v http://localhost:8080/api/orders \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer validToken"

# 응답:
# < HTTP/1.1 403 Forbidden
# < Vary: Origin
# (Access-Control-Allow-Origin 헤더 없음)
# → 브라우저가 응답을 차단
```

### 실험 3: @CrossOrigin vs CorsConfigurationSource 우선순위

```java
@RestController
@CrossOrigin(origins = "http://localhost:3000") // Controller 레벨 설정
public class OrderController {
    // CorsConfigurationSource와 @CrossOrigin이 모두 설정된 경우:
    // 두 설정이 합산되거나 @CrossOrigin이 우선할 수 있음
    // → 예측 불가한 동작 방지를 위해 하나의 방법만 사용 권장
}
```

---

## 🔒 보안 체크리스트

```
출처 설정
  ☐ allowedOrigins에 정확한 출처만 나열 (와일드카드 금지)
  ☐ allowedOriginPatterns 사용 시 제한적 패턴
  ☐ allowedOrigins("*") + allowCredentials(true) 조합 금지
  ☐ 운영 환경에서 개발 서버(localhost) 출처 포함 금지

메서드/헤더 설정
  ☐ 필요한 메서드만 명시 (DELETE 등 위험 메서드 최소화)
  ☐ allowedHeaders에 필요한 헤더만 (Authorization, Content-Type 등)
  ☐ exposedHeaders에 클라이언트가 읽어야 하는 헤더만

Preflight 처리
  ☐ http.cors()로 Security 통합 (CorsFilter가 인증 전에 실행)
  ☐ OPTIONS /** permitAll 설정
  ☐ maxAge 설정으로 Preflight 요청 최소화 (3600초)
```

---

## 🤔 트레이드오프

```
CorsConfigurationSource (전역) vs @CrossOrigin (개별):
  CorsConfigurationSource:
    장점  전역 설정 → 누락 없음, 보안 정책 중앙화
    단점  Controller마다 다른 설정 어려움

  @CrossOrigin:
    장점  Controller마다 세밀한 설정 가능
    단점  분산된 설정 → 일관성 유지 어려움
          OPTIONS가 인증 필터에서 차단될 수 있음
    → 전역 CorsConfigurationSource + 예외 케이스에 @CrossOrigin 조합

allowedMethods("*") vs 명시적 메서드 목록:
  (*):
    장점  편리, 새 메서드 추가 시 수정 불필요
    단점  불필요한 메서드도 허용 (TRACE, CONNECT 등 위험)
  명시적:
    장점  최소 권한 원칙
    단점  새 메서드 추가 시 CORS 설정도 변경 필요
```

---

## 📌 핵심 정리

```
CORS 처리 위치
  http.cors() + CorsConfigurationSource → CorsFilter가 인증 전 처리
  @CrossOrigin → DispatcherServlet 이후 (인증 후) 처리
  → Preflight가 인증 필터 통과하려면 반드시 http.cors() 사용

Preflight 처리
  OPTIONS + Origin + Access-Control-Request-Method = Preflight
  CorsFilter: Preflight 감지 → CORS 헤더 추가 → 즉시 200 응답
  인증 필터 실행 안 됨 → 인증 없이 통과

allowCredentials(true) 제약
  allowedOrigins("*") + allowCredentials(true) = 금지
  → 특정 출처 명시 또는 allowedOriginPatterns로 해결

CorsConfiguration 주요 설정
  allowedOrigins / allowedOriginPatterns
  allowedMethods: GET, POST, PUT, DELETE, OPTIONS
  allowedHeaders: Authorization, Content-Type 등
  allowCredentials: true (쿠키/Authorization 헤더 허용)
  maxAge: Preflight 캐시 시간 (초)
```

---

## 🤔 생각해볼 문제

**Q1.** Spring Security의 `CorsFilter`가 Preflight OPTIONS 요청을 처리하고 즉시 응답을 반환한 후 `chain.doFilter()`를 호출하지 않습니다. 이때 Spring Boot Actuator의 `/actuator/health` 엔드포인트에 대한 CORS OPTIONS 요청도 동일하게 처리되는가? `CorsConfigurationSource`의 URL 패턴 매칭이 Actuator 경로에 적용되는 방식은?

**Q2.** `maxAge: 3600`으로 Preflight 결과를 1시간 동안 캐시하도록 설정했습니다. 운영 중에 허용 출처를 변경해야 할 때, 이미 브라우저에 캐시된 Preflight 결과는 어떻게 처리되는가? 캐시 무효화를 강제하는 방법은?

**Q3.** MSA 환경에서 서비스 A와 서비스 B가 각각 다른 도메인에서 운영됩니다. 서비스 A의 프론트엔드(React)가 서비스 B의 API를 직접 호출해야 할 때 CORS를 허용하는 것과, API Gateway를 통해 Same-Origin으로 라우팅하는 방식의 보안 트레이드오프는?

> 💡 **해설**
>
> **Q1.** `UrlBasedCorsConfigurationSource`에서 `/api/**` 패턴만 등록했다면, `/actuator/**` 경로는 CORS 설정이 없으므로 `getCorsConfiguration()`이 `null`을 반환합니다. `CorsFilter`는 설정이 없으면 CORS 헤더를 추가하지 않고 다음 필터로 진행합니다. Actuator의 OPTIONS 요청은 CorsFilter에서 처리되지 않아 인증 필터를 통과하게 됩니다. Actuator에도 CORS를 적용하려면 `source.registerCorsConfiguration("/**", config)`로 모든 경로에 적용하거나 Actuator 경로를 별도로 등록합니다.
>
> **Q2.** `maxAge: 3600`은 브라우저에 "이 Preflight 결과를 1시간 동안 캐시하라"고 지시합니다. 허용 출처를 변경해도 기존 브라우저의 캐시가 만료되기 전까지는 이전 설정이 적용됩니다. 강제 무효화 방법은 없지만 완화할 수 있습니다. 첫째, 변경 직후 `maxAge: 0`으로 짧게 설정해 이후 Preflight가 캐시되지 않게 합니다. 둘째, 사용자에게 브라우저 캐시 초기화를 안내합니다. 셋째, 서비스 URL 경로를 변경해 새로운 경로에 대한 Preflight가 발생하도록 유도합니다. 보안상 민감한 변경(출처 제한 강화)의 경우 maxAge를 짧게(300초) 유지하는 것이 안전합니다.
>
> **Q3.** 직접 CORS 허용: 서비스 B에서 서비스 A의 프론트엔드 도메인을 명시적으로 허용합니다. 서비스 B의 보안 설정을 외부(프론트엔드)에 맞게 변경해야 하고, 프론트엔드 도메인이 변경되면 서비스 B도 변경해야 합니다. 각 서비스가 CORS 정책을 독립적으로 관리합니다. API Gateway 라우팅: 프론트엔드와 API Gateway가 같은 도메인이므로 CORS가 불필요합니다. 브라우저는 Same-Origin 정책을 통과합니다. 서비스 B는 외부 직접 접근 없이 내부망에서만 통신합니다. 보안 관점에서 API Gateway 방식이 더 안전합니다. 서비스 B를 내부망에서만 접근 가능하게 하고 인증/인가를 Gateway에서 중앙화할 수 있습니다. 직접 CORS 허용 방식은 각 서비스가 개별 보안 정책을 유지해야 하므로 일관성 관리가 어렵습니다.

---

<div align="center">

**[홈으로 🏠](../README.md)** | **[다음: Security Headers ➡️](./02-security-headers.md)**

</div>
