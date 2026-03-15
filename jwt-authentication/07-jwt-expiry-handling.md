# JWT Token 만료 및 갱신 처리 — ExpiredJwtException 처리와 Silent Refresh 전략

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `ExpiredJwtException`이 Filter에서 발생했을 때 `ExceptionTranslationFilter`를 거치지 않고 직접 `401` 응답을 보내야 하는 이유는?
- Filter에서 예외를 직접 처리하는 방식과 `AuthenticationEntryPoint`를 통해 처리하는 방식의 차이는?
- 만료 5분 전 Silent Refresh 클라이언트 전략을 어떻게 구현하는가?
- 만료된 토큰에서도 클레임을 추출해야 하는 경우(Refresh Token 재발급)에 `ExpiredJwtException`을 어떻게 활용하는가?
- Access Token이 만료됐을 때 401 응답에 포함할 정보는 무엇인가? (`WWW-Authenticate` 헤더)
- 동시 요청에서 여러 개의 Silent Refresh가 동시에 발생하는 Race Condition을 어떻게 방지하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 토큰 만료 처리가 복잡한 이유

```
토큰 만료 시나리오:
  1. 사용자가 15분 동안 활동 후 추가 요청
  2. Access Token 만료 → 서버: 401
  3. 클라이언트: 401이 "미인증"인지 "토큰 만료"인지 구분 필요
  4. 토큰 만료라면: Refresh Token으로 재발급 → 원래 요청 재시도
  5. Refresh Token도 만료라면: 로그인 페이지로 이동

단순 401로는 구분이 어렵다:
  → TOKEN_EXPIRED vs UNAUTHORIZED를 오류 코드로 명확히 구분 필요

만료 직전 Silent Refresh 전략:
  → 클라이언트가 exp 클레임을 읽어 만료 5분 전에 미리 갱신
  → 사용자는 토큰 갱신을 인식하지 못함

Race Condition:
  → 여러 탭/요청이 동시에 토큰 만료를 감지하면
     동시에 재발급 요청 → RTR에서 토큰 충돌 발생
  → 클라이언트 단에서 재발급 요청을 직렬화해야 함
```

---

## 😱 흔한 보안 실수

### Before: 만료 예외를 Filter 밖으로 던져 500 응답

```java
// ❌ ExpiredJwtException을 catch하지 않으면 DispatcherServlet까지 전파 → 500
@Override
protected void doFilterInternal(HttpServletRequest request, ...) {
    String token = extractToken(request);
    if (token != null) {
        Claims claims = jwtTokenProvider.getClaims(token); // ← 만료 시 예외 미처리
        setAuthentication(claims);
    }
    chain.doFilter(request, response);
}

// ✅ 모든 JwtException을 catch하여 처리
@Override
protected void doFilterInternal(HttpServletRequest request, ...) {
    String token = extractToken(request);
    if (token != null) {
        try {
            if (jwtTokenProvider.validateToken(token)) {
                setAuthentication(request, token);
            }
        } catch (ExpiredJwtException e) {
            log.info("Access token expired");
            // 만료: 401 + TOKEN_EXPIRED 코드 응답
            sendExpiredResponse(response);
            return; // chain 중단
        } catch (JwtException e) {
            log.warn("Invalid token: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            // chain 계속 → AuthorizationFilter → 401
        }
    }
    chain.doFilter(request, response);
}
```

### Before: 만료와 미인증을 구분하지 않는 응답

```java
// ❌ 모든 401을 동일하게 → 클라이언트가 재발급 시도 여부를 판단 불가
response.setStatus(401);
response.getWriter().write("{\"error\":\"UNAUTHORIZED\"}");

// ✅ RFC 6750 표준 + 커스텀 오류 코드로 명확히 구분
// 만료:
response.setStatus(401);
response.setHeader("WWW-Authenticate",
    "Bearer error=\"invalid_token\", error_description=\"Token expired\"");
response.getWriter().write(
    "{\"error\":\"TOKEN_EXPIRED\",\"message\":\"Access token has expired.\"}");

// 미인증(토큰 없음):
response.setStatus(401);
response.getWriter().write(
    "{\"error\":\"UNAUTHORIZED\",\"message\":\"Authentication required.\"}");
// → 클라이언트: TOKEN_EXPIRED → Refresh 시도
// → 클라이언트: UNAUTHORIZED → 로그인 페이지
```

---

## ✨ 올바른 보안 구현

### 서버: 만료 처리 전략 A — Filter에서 직접 응답

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final ObjectMapper objectMapper;

    private final SecurityContextHolderStrategy strategy =
        SecurityContextHolder.getContextHolderStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain)
            throws ServletException, IOException {

        String token = resolveToken(request);

        if (token != null) {
            try {
                if (jwtTokenProvider.validateToken(token)) {
                    String username = jwtTokenProvider.getUsername(token);
                    UserDetails userDetails =
                        userDetailsService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken authentication =
                        UsernamePasswordAuthenticationToken.authenticated(
                            userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContext context = strategy.createEmptyContext();
                    context.setAuthentication(authentication);
                    strategy.setContext(context);
                }
            } catch (ExpiredJwtException e) {
                // ★ 만료: Filter에서 직접 401 응답 (ExceptionTranslationFilter 우회)
                log.info("Access token expired for request: {}", request.getRequestURI());
                sendErrorResponse(response, "TOKEN_EXPIRED",
                    "Access token has expired. Please use refresh token.");
                return; // chain.doFilter 호출 안 함 → 이후 필터 실행 중단
            } catch (JwtException e) {
                log.warn("Invalid token [{}]: {}", e.getClass().getSimpleName(), e.getMessage());
                strategy.clearContext();
                // chain 계속 → AuthorizationFilter → 401 (UNAUTHORIZED)
            }
        }

        chain.doFilter(request, response);
    }

    private void sendErrorResponse(HttpServletResponse response,
                                    String errorCode, String message)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate",
            "Bearer error=\"invalid_token\", error_description=\"" + message + "\"");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");

        Map<String, String> errorBody = Map.of(
            "error", errorCode,
            "message", message
        );
        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }

    private String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/auth/");
    }
}
```

### 서버: 만료 처리 전략 B — AuthenticationEntryPoint에 위임

```java
// Filter에서: SecurityContext 비우고 request 속성에 오류 코드 저장
} catch (ExpiredJwtException e) {
    strategy.clearContext();
    request.setAttribute("JWT_EXPIRED", Boolean.TRUE);
    // chain 계속 → AuthorizationFilter → AccessDeniedException
    // → ExceptionTranslationFilter → AuthenticationEntryPoint 위임
}

// 커스텀 EntryPoint:
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                          HttpServletResponse response,
                          AuthenticationException authException) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Boolean isExpired = (Boolean) request.getAttribute("JWT_EXPIRED");
        if (Boolean.TRUE.equals(isExpired)) {
            response.setHeader("WWW-Authenticate",
                "Bearer error=\"invalid_token\", error_description=\"Token expired\"");
            response.getWriter().write(
                "{\"error\":\"TOKEN_EXPIRED\",\"message\":\"Access token expired.\"}");
        } else {
            response.getWriter().write(
                "{\"error\":\"UNAUTHORIZED\",\"message\":\"Authentication required.\"}");
        }
    }
}
```

---

## 🔬 내부 동작 원리

### 1. Filter에서 직접 응답 vs ExceptionTranslationFilter 경유 — 차이

```
전략 A: Filter에서 직접 응답
  ExpiredJwtException catch
  → sendErrorResponse(response) → HTTP 401 즉시 반환
  → chain.doFilter 호출 안 함 → AuthorizationFilter 실행 안 됨
  → ExceptionTranslationFilter 실행 안 됨
  장점: 가장 빠름, 응답 형식 완전 제어
  단점: EntryPoint와 오류 응답 로직이 중복될 수 있음

전략 B: SecurityContext 비우고 chain 계속
  ExpiredJwtException catch → clearContext() → chain.doFilter()
  → AuthorizationFilter: SecurityContext 비어 있음
    → AuthenticationCredentialsNotFoundException
  → ExceptionTranslationFilter: catch AuthenticationException
    → AuthenticationEntryPoint.commence()
    → 401 응답
  장점: 오류 응답 로직을 EntryPoint에 중앙화
  단점: 필터 체인을 더 많이 통과 → 약간의 성능 비용
        request 속성으로 오류 유형 전달 (간접적)

ExceptionTranslationFilter를 거치지 않고 직접 응답해야 하는 경우:
  → 만료 감지를 즉시 클라이언트에 알려야 할 때 (명확성)
  → EntryPoint에서 만료/미인증을 구분하기 어려울 때
  → JWT 외부 라이브러리를 사용해 EntryPoint 수정 불가 시
```

### 2. 만료된 토큰에서 클레임 추출 (Refresh 재발급용)

```java
// ExpiredJwtException의 getClaims() 활용
// Refresh 재발급 시 만료된 Access Token에서 userId를 꺼내야 하는 경우

public Claims getClaimsFromExpiredToken(String token) {
    try {
        return Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token) // 만료됐으면 ExpiredJwtException 발생
            .getBody();
    } catch (ExpiredJwtException e) {
        // ★ 만료됐어도 서명은 유효 → Claims 꺼낼 수 있음
        return e.getClaims();
        // getClaims()는 Header, Claims 포함
        // 서명이 유효하지 않으면 SignatureException이 먼저 발생 → Claims 없음
    }
    // → 만료 + 서명 유효 = 정상 재발급 대상
    // → 서명 위조 = SignatureException (재발급 거부)
}

// 활용 시나리오:
// POST /api/auth/refresh
//   Cookie: refreshToken=eyJ...RT...
// → Refresh Token 검증
// → getClaims(RT).get("userId") → userId 추출
// → DB에서 사용자 정보 조회 → 새 Access Token 발급
//
// 주의: RefreshToken은 만료되지 않아야 정상 재발급
// 만료된 RefreshToken → ExpiredJwtException → 재로그인 필요
```

### 3. exp 클레임 읽기 — 만료 시각 계산

```java
// 서버에서 만료까지 남은 시간 계산
public long getExpiresInSeconds(String token) {
    Claims claims = getClaims(token);
    Date expiration = claims.getExpiration();
    long now = System.currentTimeMillis();
    return (expiration.getTime() - now) / 1000; // 양수: 만료까지 남은 초
}

// 응답에 만료 정보 포함 (클라이언트 Silent Refresh에 활용)
@PostMapping("/api/auth/login")
public TokenResponse login(...) {
    String accessToken = createAccessToken(...);
    long expiresIn = jwtTokenProvider.getExpiresInSeconds(accessToken); // 900초 (15분)

    return TokenResponse.builder()
        .accessToken(accessToken)
        .expiresIn(expiresIn)        // ← 클라이언트가 타이머 설정에 사용
        .tokenType("Bearer")
        .build();
}
// 클라이언트: expiresIn - 300초(5분) 후에 Silent Refresh 예약
```

### 4. WWW-Authenticate 헤더 — RFC 6750 표준

```
RFC 6750 Bearer Token 오류 응답:
  WWW-Authenticate: Bearer realm="example",
                    error="invalid_token",
                    error_description="The access token expired"

error 값:
  invalid_request:  요청 형식 오류 (헤더 없음 등)
  invalid_token:    토큰 만료, 위조, 취소됨
  insufficient_scope: 권한 부족

클라이언트 처리 기준:
  error="invalid_token" + 응답 바디 error="TOKEN_EXPIRED"
    → Refresh Token으로 재발급 시도
  error="invalid_token" + 응답 바디 error="TOKEN_INVALID"
    → 로그인 페이지로 이동
  error="insufficient_scope"
    → "이 기능은 권한이 필요합니다" 안내
```

### 5. Silent Refresh — 만료 전 자동 갱신

```
타이머 기반 Silent Refresh 흐름:

  1. 로그인 응답: {accessToken, expiresIn: 900}
  2. 클라이언트: setTimeout(silentRefresh, (900 - 300) * 1000)
                 → 10분(600초) 후 갱신 예약

  3. 600초 후 silentRefresh() 실행:
     POST /api/auth/refresh (Cookie: refreshToken)
     → 새 accessToken 수신
     → 메모리의 accessToken 교체
     → 새 타이머 예약

  4. 사용자는 토큰 갱신을 전혀 인식하지 못함

동시 요청 Race Condition:
  → 만료 직전에 여러 요청이 동시에 발생
  → 각 요청이 독립적으로 재발급 시도
  → RTR에서 첫 번째 재발급 후 Refresh Token 교체
  → 나머지 요청: 이전 Refresh Token 재사용 → 탈취 감지 오판
  → 해결: 재발급 요청을 Promise로 직렬화 (아래 구현)
```

---

## 💻 실험으로 확인하기

### 실험 1: 만료 응답 형식 확인

```bash
# 만료된 Access Token으로 API 요청
curl -v -H "Authorization: Bearer <expired-token>" \
  http://localhost:8080/api/orders 2>&1 | grep -E "< HTTP|< WWW|{\"error"

# 기대 출력:
# < HTTP/1.1 401
# < WWW-Authenticate: Bearer error="invalid_token", error_description="Access token has expired..."
# {"error":"TOKEN_EXPIRED","message":"Access token has expired. Please use refresh token."}

# 정상 토큰 없이 요청 (미인증)
curl -v http://localhost:8080/api/orders 2>&1 | grep -E "< HTTP|{\"error"
# < HTTP/1.1 401
# {"error":"UNAUTHORIZED","message":"Authentication required."}
```

### 실험 2: 만료된 토큰에서 클레임 추출 확인

```java
@Test
void expiredToken_claimsStillExtractable() {
    // given: 1초 수명 토큰 발급
    String shortLivedToken = Jwts.builder()
        .setSubject("kim")
        .claim("userId", 1L)
        .setExpiration(new Date(System.currentTimeMillis() + 1000))
        .signWith(secretKey)
        .compact();

    // 1초 대기
    Thread.sleep(1100);

    // when: 만료됐지만 클레임 추출 가능
    Claims claims = jwtTokenProvider.getClaimsFromExpiredToken(shortLivedToken);

    // then
    assertThat(claims.getSubject()).isEqualTo("kim");
    assertThat(claims.get("userId", Long.class)).isEqualTo(1L);
}

@Test
void tamperedExpiredToken_throwsSignatureException() {
    // 서명이 위조된 만료 토큰은 getClaims() 불가
    String parts[] = validToken.split("\\.");
    String tampered = parts[0] + ".TAMPERED." + parts[2];

    assertThatThrownBy(() ->
        jwtTokenProvider.getClaimsFromExpiredToken(tampered))
        .isInstanceOf(SignatureException.class);
    // ExpiredJwtException 전에 SignatureException이 먼저 발생
}
```

### 실험 3: Silent Refresh 타이머 동작 확인

```typescript
// 클라이언트 테스트 (Jest)
describe('Silent Refresh', () => {
    jest.useFakeTimers();

    it('schedules refresh 5 minutes before expiry', async () => {
        const mockRefresh = jest.fn().mockResolvedValue({ accessToken: 'new-token' });
        const tokenManager = new TokenManager({ onRefresh: mockRefresh });

        // 로그인: 15분 수명 토큰
        tokenManager.setAccessToken('token', 900); // expiresIn: 900초

        // 600초(10분) 전에는 갱신 안 함
        jest.advanceTimersByTime(600_000 - 1);
        expect(mockRefresh).not.toHaveBeenCalled();

        // 600초 경과 → 갱신 실행
        jest.advanceTimersByTime(1);
        await Promise.resolve(); // microtask 실행
        expect(mockRefresh).toHaveBeenCalledTimes(1);
    });
});
```

### 실험 4: Race Condition 방지 — Promise 공유

```typescript
// TokenManager: 재발급 요청 직렬화
class TokenManager {
    private accessToken: string | null = null;
    private refreshPromise: Promise<string> | null = null;

    async getValidToken(): Promise<string> {
        if (this.accessToken && !this.isExpired(this.accessToken)) {
            return this.accessToken;
        }

        // 이미 재발급 중이면 같은 Promise 공유 (중복 요청 방지)
        if (this.refreshPromise) {
            return this.refreshPromise;
        }

        // 최초 재발급 요청
        this.refreshPromise = this.refresh()
            .then(newToken => {
                this.accessToken = newToken;
                this.refreshPromise = null; // 완료 후 초기화
                return newToken;
            })
            .catch(err => {
                this.refreshPromise = null; // 실패 시도 초기화
                throw err;
            });

        return this.refreshPromise;
    }

    private async refresh(): Promise<string> {
        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            credentials: 'include' // HttpOnly 쿠키 자동 포함
        });
        if (!response.ok) throw new Error('Refresh failed');
        const data = await response.json();
        return data.accessToken;
    }

    private isExpired(token: string): boolean {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.exp * 1000 < Date.now() + 300_000; // 5분 여유
    }
}

// axios 인터셉터:
const tokenManager = new TokenManager();

axios.interceptors.request.use(async config => {
    const token = await tokenManager.getValidToken();
    config.headers['Authorization'] = `Bearer ${token}`;
    return config;
});

axios.interceptors.response.use(
    res => res,
    async error => {
        if (error.response?.data?.error === 'TOKEN_EXPIRED') {
            // 서버에서 만료 감지 → 재발급 후 원래 요청 재시도
            const newToken = await tokenManager.getValidToken();
            error.config.headers['Authorization'] = `Bearer ${newToken}`;
            return axios(error.config);
        }
        return Promise.reject(error);
    }
);
```

---

## 🔒 보안 체크리스트

```
서버 만료 처리
  ☐ ExpiredJwtException 반드시 catch (500 방지)
  ☐ TOKEN_EXPIRED 오류 코드 명시 (UNAUTHORIZED와 구분)
  ☐ WWW-Authenticate 헤더 포함 (RFC 6750 준수)
  ☐ 만료 클레임 추출: getClaimsFromExpiredToken() 활용
  ☐ 서명이 유효하지 않은 만료 토큰은 재발급 거부 (SignatureException)

클라이언트 Silent Refresh
  ☐ expiresIn을 로그인/재발급 응답에 포함
  ☐ 만료 5분 전에 재발급 예약 (타이머)
  ☐ 재발급 요청 Promise 공유 (Race Condition 방지)
  ☐ 재발급 실패 시 로그인 페이지 이동

응답 설계
  ☐ TOKEN_EXPIRED: Refresh Token으로 재발급 유도
  ☐ UNAUTHORIZED: 로그인 페이지 이동
  ☐ 토큰 만료 로그: INFO 레벨 (정상 동작)
  ☐ 서명 위조 로그: WARN 레벨 (공격 의심)
```

---

## 🤔 트레이드오프

```
Filter 직접 응답 vs EntryPoint 위임:
  직접 응답:
    장점  최빠름, 응답 형식 완전 제어
    단점  오류 응답 로직이 필터에 분산

  EntryPoint 위임:
    장점  오류 처리 중앙화 (EntryPoint 한 곳만 수정)
    단점  필터 체인을 끝까지 통과 (약간 느림)
          request 속성으로 오류 유형 전달 (간접적)

타이머 기반 vs 인터셉터 기반 Silent Refresh:
  타이머:
    장점  API 요청 지연 없음 (미리 갱신)
    단점  탭 비활성 시 타이머 지연 가능 (브라우저 throttle)
          페이지 이탈 후 재진입 시 타이머 소멸

  인터셉터 (401 감지 후 재발급):
    장점  구현 단순, 탭 상태와 무관
    단점  첫 번째 실패 요청이 지연됨 (재발급 왕복 후 재시도)
          Race Condition 관리 필요

  실무 권장: 타이머 기반 + 인터셉터 폴백 조합
  (타이머로 선제 갱신, 놓친 경우 인터셉터로 보완)
```

---

## 📌 핵심 정리

```
ExpiredJwtException 처리
  Filter에서 catch → sendErrorResponse() → return
  chain.doFilter() 호출 않음 → ExceptionTranslationFilter 우회
  응답: 401 + TOKEN_EXPIRED 오류 코드 + WWW-Authenticate 헤더

만료 토큰에서 클레임 추출
  ExpiredJwtException.getClaims() → 만료됐어도 클레임 가능
  서명 유효성은 보장됨 (위조 시 SignatureException)
  → Refresh 재발급 흐름에서 userId 추출에 활용

Silent Refresh 핵심
  expiresIn 응답에 포함 → 클라이언트 타이머 설정
  만료 5분 전 자동 갱신 → 사용자 인식 없이 세션 유지

Race Condition 방지
  재발급 Promise 공유 (Promise 인스턴스 하나를 여러 요청이 공유)
  완료 시 Promise 초기화 → 다음 만료 시 새 Promise 생성

오류 코드 구분
  TOKEN_EXPIRED → Refresh 시도 → 성공 시 원래 요청 재시도
  UNAUTHORIZED  → 로그인 페이지 이동
```

---

## 🤔 생각해볼 문제

**Q1.** `ExpiredJwtException`을 Filter에서 catch해서 직접 `response.getWriter().write()`로 응답을 보낸 후 `return`하면 `chain.doFilter()`를 호출하지 않습니다. 이 경우 `SecurityContextHolderFilter`의 `finally` 블록(clearContext)은 실행되는가? 실행되지 않는다면 문제가 생기는가?

**Q2.** Silent Refresh에서 브라우저 탭이 비활성화(백그라운드) 상태가 되면 Chrome은 `setTimeout` 실행을 최소 1분 단위로 throttle합니다. 만료 5분 전에 예약한 타이머가 실제로 6분 후에 실행되어 토큰이 이미 만료된 상태가 된다면 어떻게 처리해야 하는가?

**Q3.** 만료된 Access Token을 서버가 `getClaimsFromExpiredToken()`으로 클레임을 추출해 Refresh Token 재발급에 활용하는 경우, 공격자가 의도적으로 서명이 유효한 만료 토큰을 재발급 엔드포인트로 직접 전송해 사용자의 새 Access Token을 발급받으려 시도할 수 있는가? 이를 방지하는 방법은?

> 💡 **해설**
>
> **Q1.** `SecurityContextHolderFilter`는 `GenericFilterBean`을 상속하며 `doFilter()` 메서드 내에서 `try { chain.doFilter(...) } finally { clearContext() }` 구조를 가집니다. `JwtAuthenticationFilter`에서 `chain.doFilter()`를 호출하지 않고 `return`하더라도, `SecurityContextHolderFilter`의 `chain.doFilter()` 자체가 반환되는 것이므로 `finally` 블록은 반드시 실행됩니다. Filter 체인은 각 필터가 자신의 `finally`를 독립적으로 관리하므로, 중간 필터에서 체인을 중단해도 이미 실행된 필터들의 `finally`는 모두 정상 실행됩니다. 따라서 `clearContext()`는 정상적으로 호출되어 ThreadLocal이 올바르게 정리됩니다.
>
> **Q2.** 탭 비활성화로 타이머가 지연되어 토큰이 이미 만료된 경우를 대비해 두 가지 방어 계층이 필요합니다. 첫째, Silent Refresh 함수 실행 시 먼저 현재 토큰의 `exp`를 확인합니다. 만료됐으면 타이머 기반 갱신이 아닌 즉시 재발급을 시도합니다. 둘째, axios 인터셉터(폴백)가 서버의 `TOKEN_EXPIRED` 응답을 감지해 재발급 후 재시도합니다. 탭이 다시 활성화되면 `document.addEventListener('visibilitychange', ...)`로 탭 활성화 이벤트를 감지해 즉시 토큰 상태를 확인하고 필요 시 재발급합니다. 이 세 가지 계층(타이머, visibilitychange, 인터셉터 폴백)을 조합하면 브라우저 throttle에 강인한 구현이 됩니다.
>
> **Q3.** 재발급 엔드포인트(`POST /api/auth/refresh`)는 만료된 Access Token이 아닌 Refresh Token으로만 재발급을 처리해야 합니다. Refresh Token은 HttpOnly 쿠키로 전달되고, 재발급 시 Refresh Token의 jti를 Redis에서 검증합니다. Access Token의 클레임을 재발급에 활용하는 경우는 오직 Refresh Token이 쿠키로 함께 전달된 상황에서 Refresh Token에서 userId를 꺼내는 용도로만 사용해야 합니다. 만약 공격자가 만료된 Access Token만 가지고 재발급 엔드포인트를 호출하면, 해당 요청에는 유효한 Refresh Token 쿠키가 없으므로 Redis에서 검증이 실패해 거부됩니다. 즉, 재발급의 인가 키는 항상 Refresh Token(Redis 검증)이어야 하고, 만료된 Access Token은 보조 정보(userId 추출) 역할만 해야 합니다.

---

<div align="center">

**[← 이전: Claims 추출과 사용](./06-claims-extraction.md)** | **[홈으로 🏠](../README.md)** | **[Chapter 6으로 이동: OAuth2 & OIDC ➡️](../oauth2-oidc/01-oauth2-grant-types.md)**

</div>
