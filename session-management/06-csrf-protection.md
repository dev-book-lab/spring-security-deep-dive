# CSRF Protection 메커니즘 — 동기화 토큰 패턴과 안전한 비활성화 조건

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- CSRF 공격이 실제로 어떻게 작동하며 왜 세션 기반 인증만 취약한가?
- `CsrfFilter`가 동기화 토큰 패턴으로 요청을 검증하는 정확한 코드 경로는?
- `HttpSessionCsrfTokenRepository`와 `CookieCsrfTokenRepository`의 내부 동작 차이는?
- `CookieCsrfTokenRepository`에서 JavaScript가 토큰을 읽을 수 있는 것이 오히려 의도된 설계인 이유는?
- REST API에서 `csrf().disable()`이 안전한 정확한 조건은 무엇인가?
- Spring Security 6.x에서 `CsrfTokenRequestAttributeHandler`와 `XorCsrfTokenRequestAttributeHandler`의 차이는?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### CSRF 공격 완전 해부

```
CSRF (Cross-Site Request Forgery) 공격 시나리오:

  전제: 피해자가 bank.com에 로그인 (세션 쿠키 JSESSIONID 보유)

  1단계: 공격자가 악성 페이지 준비
     <!-- evil.com/attack.html -->
     <html>
       <body onload="document.forms[0].submit()">
         <form action="https://bank.com/transfer" method="POST">
           <input type="hidden" name="to" value="attacker-account">
           <input type="hidden" name="amount" value="1000000">
         </form>
       </body>
     </html>

  2단계: 피해자가 evil.com을 방문
     → 브라우저가 bank.com에 POST /transfer 자동 전송
     → 브라우저는 bank.com의 JSESSIONID 쿠키를 자동으로 포함!
     → bank.com은 유효한 세션 → 인증된 사용자의 요청으로 처리
     → 계좌 이체 실행됨 → 공격 성공

  핵심 취약점:
    브라우저는 타 도메인 요청에도 해당 도메인의 쿠키를 자동 첨부
    공격자 페이지가 피해자 브라우저를 통해 요청을 보낼 수 있음

  CSRF가 성립하는 조건:
  ① 세션 쿠키 기반 인증 (또는 Basic Auth)
  ② 브라우저를 통한 요청
  ③ 부작용이 있는 요청 (상태 변경, 자금 이동 등)

  JWT Bearer 토큰 + Stateless가 안전한 이유:
  Authorization: Bearer <token> 헤더는 브라우저가 자동 첨부하지 않음
  → 공격자 페이지에서 JavaScript로 헤더를 설정하려면 Same-Origin Policy에 막힘
```

---

## 😱 흔한 보안 실수

### Before: 잘못된 이유로 CSRF 비활성화

```java
// ❌ "API이니까" 또는 "귀찮아서" CSRF 비활성화
// 하지만 세션 쿠키 기반 인증 + 브라우저 클라이언트를 사용한다면 여전히 취약

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable()) // ← 잘못된 판단
        .formLogin(Customizer.withDefaults())
        // formLogin + 브라우저 = 세션 쿠키 = CSRF 취약!
    ;
    return http.build();
}

// ✅ CSRF 비활성화 체크리스트 (모두 충족 시에만)
// 1. 세션 쿠키 또는 Basic Auth를 전혀 사용하지 않는가?
// 2. 모든 클라이언트가 Bearer 토큰을 Authorization 헤더로 전송하는가?
// 3. 브라우저를 통한 직접 폼 제출이 없는가?
// → 모두 Yes이면 csrf.disable() 안전
```

### Before: CookieCsrfTokenRepository에서 HttpOnly 설정

```java
// ❌ CookieCsrfTokenRepository를 HttpOnly=true로 설정하면
// JavaScript에서 쿠키를 읽을 수 없어 CSRF 토큰을 가져올 수 없음
// Angular, React 등 SPA 프레임워크의 자동 CSRF 처리가 동작하지 않음

CookieCsrfTokenRepository repo = CookieCsrfTokenRepository.withHttpOnlyFalse();
// withHttpOnlyFalse()가 기본값이어야 하는 이유:
// JavaScript로 쿠키의 XSRF-TOKEN 값을 읽어 X-XSRF-TOKEN 헤더에 설정해야 함
// HttpOnly=true이면 JavaScript가 읽지 못함 → CSRF 방어 효과 없음

// ❌ 잘못된 사용:
CookieCsrfTokenRepository repo = new CookieCsrfTokenRepository();
// 기본 CookieCsrfTokenRepository는 HttpOnly=true → JavaScript 접근 불가

// ✅ SPA 환경에서:
CookieCsrfTokenRepository repo = CookieCsrfTokenRepository.withHttpOnlyFalse();
// XSRF-TOKEN 쿠키 → JavaScript가 읽음 → X-XSRF-TOKEN 헤더로 전송
// CsrfFilter가 X-XSRF-TOKEN 헤더와 세션/쿠키의 토큰 비교
```

---

## ✨ 올바른 보안 구현

### 환경별 CSRF 설정

```java
// ── 전통적인 서버사이드 렌더링 (Thymeleaf, JSP) ─────────────────
@Bean
public SecurityFilterChain mvcChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(
                HttpSessionCsrfTokenRepository()) // 세션에 토큰 저장 (기본값)
        )
        // Thymeleaf에서 자동으로 _csrf 히든 필드 삽입됨
        // th:action 사용 시 CSRF 토큰 자동 포함
    ;
    return http.build();
}

// ── SPA (React, Angular, Vue) ─────────────────────────────────
@Bean
public SecurityFilterChain spaChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(
                CookieCsrfTokenRepository.withHttpOnlyFalse())
            // Angular의 HttpClient: X-XSRF-TOKEN 헤더 자동 설정
            // Axios: xsrfCookieName/xsrfHeaderName 설정
        )
    ;
    return http.build();
}

// ── REST API Only (Bearer 토큰, 브라우저 클라이언트 없음) ────────
@Bean
public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable()) // 안전: Bearer 토큰 방식
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    ;
    return http.build();
}
```

---

## 🔬 내부 동작 원리

### 1. CsrfFilter — 동기화 토큰 검증 전 과정

```java
// CsrfFilter.java (Filter 순서: 100, 매우 초반에 실행)
public final class CsrfFilter extends OncePerRequestFilter {

    private final CsrfTokenRepository tokenRepository;
    private RequestMatcher requireCsrfProtectionMatcher =
        DEFAULT_CSRF_MATCHER; // PUT, POST, DELETE, PATCH 메서드
    private CsrfTokenRequestHandler requestHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain)
            throws ServletException, IOException {

        // ① CSRF 토큰 로드 (세션 또는 쿠키에서)
        DeferredCsrfToken deferredCsrfToken =
            this.tokenRepository.loadDeferredToken(request, response);

        // ② request 속성에 토큰 설정 (Thymeleaf에서 접근용)
        this.requestHandler.handle(request, response, deferredCsrfToken::get);

        // ③ CSRF 검사가 필요한 메서드인가?
        if (!this.requireCsrfProtectionMatcher.matches(request)) {
            // GET, HEAD, OPTIONS, TRACE → 검사 불필요
            filterChain.doFilter(request, response);
            return;
        }

        // ④ 실제 CSRF 토큰 로드 (지연 로딩)
        CsrfToken csrfToken = deferredCsrfToken.get();

        // ⑤ 요청에서 CSRF 토큰 추출
        // 헤더(X-CSRF-TOKEN 또는 X-XSRF-TOKEN) 또는 파라미터(_csrf)
        String actualToken = this.requestHandler.resolveCsrfTokenValue(request, csrfToken);

        // ⑥ 저장된 토큰과 비교
        if (!equalsConstantTime(csrfToken.getToken(), actualToken)) {
            // 불일치 → 위조된 요청
            if (missingToken) {
                this.accessDeniedHandler.handle(request, response,
                    new MissingCsrfTokenException(actualToken));
            } else {
                this.accessDeniedHandler.handle(request, response,
                    new InvalidCsrfTokenException(csrfToken, actualToken));
            }
            return;
        }

        // ⑦ 검증 통과 → 다음 필터로
        filterChain.doFilter(request, response);
    }
}
```

### 2. HttpSessionCsrfTokenRepository — 세션에 토큰 저장

```java
// HttpSessionCsrfTokenRepository.java
public final class HttpSessionCsrfTokenRepository implements CsrfTokenRepository {

    private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME =
        HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");

    private String sessionAttributeName = DEFAULT_CSRF_TOKEN_ATTR_NAME;
    private String parameterName = "_csrf";   // 폼 히든 파라미터명
    private String headerName = "X-CSRF-TOKEN"; // HTTP 헤더명

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(
            headerName,     // 헤더명
            parameterName,  // 파라미터명
            createNewToken() // UUID 기반 랜덤 토큰
        );
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request,
                           HttpServletResponse response) {
        if (token == null) {
            // 토큰 삭제 (로그아웃 시)
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(sessionAttributeName);
            }
        } else {
            // 세션에 저장 (없으면 세션 생성)
            request.getSession().setAttribute(sessionAttributeName, token);
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return null;
        return (CsrfToken) session.getAttribute(sessionAttributeName);
    }
}
```

### 3. CookieCsrfTokenRepository — SPA를 위한 쿠키 방식

```java
// CookieCsrfTokenRepository.java
public final class CookieCsrfTokenRepository implements CsrfTokenRepository {

    static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN";
    static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";
    static final String DEFAULT_CSRF_HEADER_NAME = "X-XSRF-TOKEN";

    private boolean cookieHttpOnly;  // false여야 JS에서 읽기 가능

    public static CookieCsrfTokenRepository withHttpOnlyFalse() {
        CookieCsrfTokenRepository result = new CookieCsrfTokenRepository();
        result.setCookieHttpOnly(false); // JS 접근 허용 (SPA에서 필수)
        return result;
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request,
                           HttpServletResponse response) {
        String tokenValue = (token != null) ? token.getToken() : "";

        Cookie cookie = new Cookie(this.cookieName, tokenValue);
        cookie.setSecure(request.isSecure()); // HTTPS이면 Secure 설정
        cookie.setPath(getCookiePath(request));
        cookie.setHttpOnly(this.cookieHttpOnly); // false: JS 읽기 가능
        if (this.cookieMaxAge != null) {
            cookie.setMaxAge(this.cookieMaxAge);
        }
        if (this.cookieDomain != null) {
            cookie.setDomain(this.cookieDomain);
        }
        response.addCookie(cookie);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) {
            if (this.cookieName.equals(cookie.getName())) {
                String token = cookie.getValue();
                if (!StringUtils.hasLength(token)) return null;
                return new DefaultCsrfToken(headerName, parameterName, token);
            }
        }
        return null;
    }
}

// SPA에서의 동작:
// 1. 첫 요청 → 서버가 Set-Cookie: XSRF-TOKEN=abc123; Path=/
// 2. JavaScript: document.cookie → "XSRF-TOKEN=abc123" 읽기
// 3. AJAX POST: X-XSRF-TOKEN: abc123 헤더 포함
// 4. CsrfFilter: XSRF-TOKEN 쿠키값 vs X-XSRF-TOKEN 헤더값 비교 → 일치 → 통과
```

### 4. XorCsrfTokenRequestAttributeHandler — Spring Security 6.x BREACH 방어

```java
// Spring Security 6.x 기본: XorCsrfTokenRequestAttributeHandler
// 매 요청마다 XOR 마스킹으로 토큰값을 변환 → BREACH 공격 방어

// BREACH 공격:
// HTTPS 압축 + 동일 비밀값 반복 요청 → 응답 크기로 비밀값 추론 가능
// 매번 다른 마스킹값 사용 → 응답 크기가 달라짐 → BREACH 무효화

// 5.x 방식 (하위 호환 필요 시):
http.csrf(csrf -> csrf
    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
);

// 6.x 기본 (BREACH 방어):
http.csrf(csrf -> csrf
    .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler())
);
// → Thymeleaf, Spring Form Tag Library와 자동 연동
// → CookieCsrfTokenRepository와 함께 사용 시 클라이언트 조정 필요할 수 있음
```

### 5. 두 저장소 방식 비교

```
HttpSessionCsrfTokenRepository:
  저장: HttpSession 속성
  전송: 폼 히든 파라미터(_csrf) 또는 HTTP 헤더(X-CSRF-TOKEN)
  Thymeleaf: th:action 사용 시 자동으로 _csrf 히든 필드 삽입
  취약점: CSRF 토큰이 세션에 있으므로 Stateless 불가
  장점:  SameSite 쿠키 설정과 독립적

CookieCsrfTokenRepository:
  저장: XSRF-TOKEN 쿠키 (HttpOnly=false)
  전송: X-XSRF-TOKEN 헤더 (SPA 프레임워크가 자동 처리)
  Angular: HttpClient가 자동으로 X-XSRF-TOKEN 헤더 첨부
  Axios:   xsrfCookieName="XSRF-TOKEN", xsrfHeaderName="X-XSRF-TOKEN" 설정
  장점:   세션 불필요 → 약한 Stateless 가능 (세션이 CSRF용으로만 있을 필요 없음)
  주의:   HttpOnly=false → XSS 취약 시 토큰 탈취 가능
          → Content Security Policy (CSP)로 XSS 방어 필요
```

---

## 💻 실험으로 확인하기

### 실험 1: CSRF 토큰 검증 실패 확인

```bash
# 1. CSRF 토큰 없이 POST 요청
curl -X POST http://localhost:8080/transfer \
  -d "to=attacker&amount=1000"
# → 403 Forbidden
# CsrfFilter → InvalidCsrfTokenException (토큰 없음)

# 2. 올바른 CSRF 토큰 포함
# 먼저 GET으로 토큰 획득
curl -c cookies.txt http://localhost:8080/transfer-form
CSRF_TOKEN=$(grep JSESSIONID cookies.txt | ...) # 세션에서 토큰 추출

curl -X POST http://localhost:8080/transfer \
  -b cookies.txt \
  -d "to=myself&amount=100&_csrf=$CSRF_TOKEN"
# → 200 OK
```

### 실험 2: CookieCsrfTokenRepository 동작 확인

```bash
# GET 요청 → XSRF-TOKEN 쿠키 발급 확인
curl -v http://localhost:8080/api/test 2>&1 | grep "XSRF-TOKEN"
# → Set-Cookie: XSRF-TOKEN=abc123def456; Path=/

# POST 요청 - 쿠키는 있지만 헤더 없음
curl -X POST -b "XSRF-TOKEN=abc123def456" http://localhost:8080/api/data
# → 403 (X-XSRF-TOKEN 헤더 없음)

# POST 요청 - 쿠키 + 헤더
curl -X POST \
  -b "XSRF-TOKEN=abc123def456" \
  -H "X-XSRF-TOKEN: abc123def456" \
  http://localhost:8080/api/data
# → 200 OK
```

### 실험 3: Angular와 통합 (참고)

```typescript
// Angular HttpClient는 자동으로 CSRF 처리
// 기본 설정: XSRF-TOKEN 쿠키 읽기 → X-XSRF-TOKEN 헤더 설정

// app.module.ts (별도 설정 없이도 동작)
import { HttpClientModule, HttpClientXsrfModule } from '@angular/common/http';

@NgModule({
  imports: [
    HttpClientModule,
    HttpClientXsrfModule.withOptions({
      cookieName: 'XSRF-TOKEN',    // Spring Security 기본값과 일치
      headerName: 'X-XSRF-TOKEN'  // Spring Security 기본값과 일치
    })
  ]
})
```

---

## 🔒 보안 체크리스트

```
CSRF 활성화 여부 결정
  ☐ 브라우저 클라이언트 + 세션/쿠키 인증 → CSRF 반드시 활성화
  ☐ Bearer 토큰 + Authorization 헤더만 사용 → CSRF 비활성화 가능
  ☐ 모바일 앱만 → CSRF 비활성화 가능 (브라우저 아님)

저장소 선택
  ☐ 서버사이드 렌더링 → HttpSessionCsrfTokenRepository (기본)
  ☐ SPA (Angular/React) → CookieCsrfTokenRepository.withHttpOnlyFalse()
  ☐ CookieCsrfToken + XSS 방어 → Content-Security-Policy 헤더 필수

GET 요청 안전성
  ☐ GET 요청에는 부작용(상태 변경) 없도록 설계
  ☐ CSRF는 기본적으로 GET, HEAD, OPTIONS, TRACE 제외
  ☐ GET으로 데이터 변경하는 API 설계 금지

BREACH 방어
  ☐ Spring Security 6.x: XorCsrfTokenRequestAttributeHandler 기본 사용
  ☐ HTTPS 응답 압축(gzip) 사용 시 BREACH 취약 → XOR 마스킹으로 완화
```

---

## 🤔 트레이드오프

```
HttpSessionCsrfTokenRepository vs CookieCsrfTokenRepository:
  HttpSession:
    장점  서버에서 완전한 토큰 제어 (갱신, 삭제)
          XSS로 JavaScript가 토큰 탈취 불가 (세션 내부)
    단점  세션 의존 → Stateless 불가
          세션 만료 시 토큰도 만료 → 로그인 페이지 왔다갔다 문제

  CookieCsrfToken (HttpOnly=false):
    장점  SPA 프레임워크와 자동 연동
          세션 없이 동작 가능 (약한 Stateless)
    단점  XSS 취약 시 JavaScript가 토큰 탈취 가능
          CSP(Content-Security-Policy) 필수 보완책

SameSite 쿠키와 CSRF:
  SameSite=Strict: 크로스 사이트 쿠키 전송 완전 차단 → CSRF 방어
  SameSite=Lax:    최상위 탐색(링크 클릭)에서는 허용 → GET 기반 공격 가능
  SameSite=None:   모든 크로스 사이트 허용 (Secure 필요)

  SameSite만으로 CSRF 방어 대체 가능?
  → 현재는 모든 브라우저가 지원하므로 이론적으로 가능
  → 레거시 브라우저, 사용자 정의 HTTP 클라이언트(모바일 앱 내 웹뷰) 고려 필요
  → 추가 방어층으로 CSRF 토큰과 SameSite 함께 사용 권장
```

---

## 📌 핵심 정리

```
CSRF 공격 성립 조건
  ① 세션 쿠키 기반 인증
  ② 브라우저를 통한 자동 쿠키 첨부
  ③ 부작용 있는 요청 (POST/PUT/DELETE)
  → Bearer 토큰 + Authorization 헤더 방식은 CSRF 면역

CsrfFilter 동작
  순서 100 (초기 실행)
  GET/HEAD/OPTIONS/TRACE → 검사 제외
  POST/PUT/DELETE/PATCH → 토큰 검증
  불일치 → 403 Forbidden

두 저장소 선택
  HttpSessionCsrfTokenRepository: SSR(Thymeleaf/JSP), _csrf 파라미터
  CookieCsrfTokenRepository.withHttpOnlyFalse(): SPA, X-XSRF-TOKEN 헤더

안전한 disable() 조건
  ① 세션/쿠키 인증 완전 미사용
  ② Bearer 토큰으로만 인증
  ③ 브라우저 클라이언트 없음 (또는 CORS로 제한됨)
  → 셋 중 하나라도 불충족이면 CSRF 유지

Spring Security 6.x
  XorCsrfTokenRequestAttributeHandler: 기본, BREACH 공격 방어
  CsrfTokenRequestAttributeHandler: 하위 호환(5.x 방식)
```

---

## 🤔 생각해볼 문제

**Q1.** `CookieCsrfTokenRepository`를 사용하는 SPA에서 XSS 취약점이 발견됐습니다. 공격자가 JavaScript로 `XSRF-TOKEN` 쿠키를 읽어 CSRF 공격을 시도할 수 있습니다. 이 경우 XSS와 CSRF를 동시에 방어하는 설계를 제안하라.

**Q2.** Spring Security 6.x의 `XorCsrfTokenRequestAttributeHandler`는 매 응답마다 XOR 마스킹된 새 토큰값을 제공합니다. 이 토큰값은 응답마다 달라지지만 내부 실제 토큰은 동일합니다. Angular SPA가 이전 응답에서 받은 토큰을 다음 요청에 사용하면 검증이 실패하는가? Spring Security가 XOR 언마스킹으로 이를 처리하는 방식은?

**Q3.** 단일 페이지 앱(SPA)에서 로그아웃 후 브라우저 뒤로 가기 버튼으로 이전 페이지에 접근할 수 있습니다. 캐시에 CSRF 토큰이 남아있으면 로그아웃된 사용자가 여전히 CSRF 보호가 우회된 요청을 보낼 수 있는가?

> 💡 **해설**
>
> **Q1.** XSS와 CSRF 동시 방어 설계: 첫째, `Content-Security-Policy` 헤더로 XSS 자체를 방어합니다(`script-src 'self'`로 인라인 스크립트 및 외부 스크립트 차단). 둘째, CSRF 토큰을 쿠키가 아닌 응답 본문(JSON) 또는 응답 헤더(`X-CSRF-TOKEN`)로 전달하고 클라이언트 메모리에만 저장합니다. 쿠키가 아닌 메모리에 저장된 토큰은 XSS로 탈취하기 어렵습니다(페이지 새로고침 시 사라짐). 셋째, `HttpOnly=true` 세션 쿠키와 `Referrer-Policy: strict-origin-when-cross-origin` 헤더를 조합합니다. 넷째, Double Submit Cookie 패턴을 버리고 서버 측 토큰 검증(`HttpSessionCsrfTokenRepository`)으로 전환해 쿠키의 JavaScript 노출을 없앱니다.
>
> **Q2.** `XorCsrfTokenRequestAttributeHandler`는 응답마다 새로운 XOR 마스킹값을 적용해 토큰을 다르게 만들지만, CsrfFilter의 검증 시 XOR 언마스킹 후 실제 토큰값을 비교합니다. 즉, 다음 요청에 이전 응답에서 받은 마스킹된 토큰을 사용해도 언마스킹 후 동일한 실제 토큰값이 나오므로 검증을 통과합니다. Angular가 응답 헤더에서 새 토큰을 받아 업데이트하지 않아도 이전 토큰으로 계속 사용 가능합니다. 이는 의도된 설계로, 클라이언트가 매 응답마다 토큰을 갱신할 필요가 없게 합니다.
>
> **Q3.** 로그아웃 후 브라우저 뒤로 가기로 이전 페이지에 접근하는 경우, CSRF 토큰 자체는 여전히 브라우저 캐시나 쿠키에 남아있을 수 있습니다. 하지만 중요한 점은 CSRF 방어의 핵심은 "인증된 사용자만 요청 가능"한 것이 아니라 "요청이 같은 사이트의 폼/스크립트에서 비롯됐음을 증명"하는 것입니다. 로그아웃 후 실제 세션이 무효화됐다면, CSRF 토큰이 있더라도 서버의 세션에는 인증 정보가 없으므로 요청이 `AccessDeniedException`으로 거부됩니다. 따라서 로그아웃 시 서버 세션을 올바르게 무효화(`HttpSession.invalidate()`)하는 것이 핵심이며, CSRF 토큰이 남아있어도 세션 자체가 무효화됐으면 보안 문제가 없습니다. 단, `NullSecurityContextRepository`(Stateless)와 토큰 기반 인증을 혼용하는 경우는 별도로 검토 필요합니다.

---

<div align="center">

**[← 이전: Stateless Session (JWT 환경)](./05-stateless-session.md)** | **[홈으로 🏠](../README.md)** | **[Chapter 5으로 이동: JWT 구조와 검증 ➡️](../jwt-authentication/01-jwt-structure-analysis.md)**

</div>
