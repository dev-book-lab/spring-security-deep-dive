# PasswordEncoder 종류와 선택 — BCrypt·Argon2·SCrypt와 무중단 마이그레이션

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `BCryptPasswordEncoder`의 `strength` 파라미터는 무엇을 의미하며 적절한 값은 얼마인가?
- `Argon2PasswordEncoder`와 `BCryptPasswordEncoder`의 근본적인 차이는 무엇인가?
- `DelegatingPasswordEncoder`는 어떻게 여러 인코더를 동시에 지원하는가?
- 기존 MD5 해시를 BCrypt로 마이그레이션할 때 서비스를 중단하지 않는 방법은?
- `PasswordEncoder.upgradeEncoding()`은 언제 호출되며 어떻게 활용하는가?
- 평문 비밀번호를 DB에 저장하는 레거시 시스템을 단계적으로 개선하는 방법은?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: 단순 해시(MD5, SHA)는 레인보우 테이블 공격에 취약하다

```
비밀번호 "password123"의 다양한 저장 방식:

  평문 저장:
    password123
    → DB 노출 시 즉시 모든 비밀번호 탈취

  MD5 해시:
    482c811da5d5b4bc6d497ffa98491e38
    → 레인보우 테이블로 즉시 역추적 가능
    → 같은 비밀번호는 항상 같은 해시 → 중복 패턴 노출

  SHA-256:
    ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
    → 여전히 레인보우 테이블 공격 가능
    → GPU로 초당 수십억 번 해시 계산 가능

  BCrypt (work factor=12):
    $2a$12$eImiTXuWVxfM37uY4JANjQ...
    → salt가 해시에 포함 → 같은 비밀번호도 다른 해시
    → 의도적으로 느림 (0.1~1초) → 브루트포스 비실용적
    → work factor 조절 → 하드웨어 발전에 대응

해결: 적응형 해시 함수 (Adaptive Hashing)
  의도적으로 느리게 설계 + salt 내장 + work factor 조절
  → BCrypt, Argon2, SCrypt
```

---

## 😱 흔한 보안 실수

### Before: SHA나 MD5로 비밀번호 해싱

```java
// ❌ 절대 사용 금지: SHA, MD5, SHA-256 단순 해시
@Bean
public PasswordEncoder passwordEncoder() {
    return new MessageDigestPasswordEncoder("SHA-256");
    // Spring Security 5.x부터 deprecated
    // Salt 없음 → 레인보우 테이블 공격에 취약
    // 속도가 너무 빠름 → 브루트포스 가능
}

// ❌ 더 나쁨: 평문 저장
@Bean
public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
    // 테스트 전용! 절대 프로덕션 사용 금지
}

// ✅ 최소 기준: BCrypt
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // strength=12 권장
}

// ✅ 더 강력: Argon2 (2015 Password Hashing Competition 우승)
@Bean
public PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder(
        16,    // saltLength (bytes)
        32,    // hashLength (bytes)
        1,     // parallelism
        65536, // memory (KB) — 64MB
        10     // iterations
    );
}
```

### Before: BCrypt strength를 너무 낮게 설정

```java
// ❌ 너무 약함: strength=4 (최솟값)
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(4);
    // 해싱 시간: ~1ms → 브루트포스 가능
}

// ❌ 너무 강함: strength=16
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(16);
    // 해싱 시간: ~수십 초 → 로그인 UX 최악
    // 서버 CPU 100% → DoS 공격 가능성
}

// ✅ 적절한 기준: 로그인에 0.1~1초가 걸리는 값
// 2024년 기준 서버에서 strength=12 → 약 0.3~0.5초
// 주기적으로 벤치마크 후 조정 필요
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}
```

---

## ✨ 올바른 보안 구현

### DelegatingPasswordEncoder — 다중 인코더 동시 지원

```java
// DelegatingPasswordEncoder: {id}encodedPassword 형식으로 저장
// {bcrypt}$2a$12$... → BCryptPasswordEncoder로 처리
// {argon2}$argon2id$... → Argon2PasswordEncoder로 처리
// {noop}plaintext → NoOpPasswordEncoder (마이그레이션 시 레거시 지원)

@Bean
public PasswordEncoder passwordEncoder() {
    // 기본 설정: PasswordEncoderFactories.createDelegatingPasswordEncoder()
    // 현재 기본 인코더: bcrypt
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}

// 커스텀 DelegatingPasswordEncoder:
@Bean
public PasswordEncoder passwordEncoder() {
    Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put("bcrypt", new BCryptPasswordEncoder(12));
    encoders.put("argon2", new Argon2PasswordEncoder(16, 32, 1, 65536, 10));
    encoders.put("noop", NoOpPasswordEncoder.getInstance()); // 레거시

    // 새로 인코딩할 때 사용할 기본 인코더
    return new DelegatingPasswordEncoder("argon2", encoders);
    // DB에는 "{argon2}$argon2id$..." 형식으로 저장
}
```

---

## 🔬 내부 동작 원리

### 1. PasswordEncoder 인터페이스

```java
// PasswordEncoder.java
public interface PasswordEncoder {

    // 평문 비밀번호를 인코딩 (단방향 해시)
    // 호출마다 다른 salt → 매번 다른 결과 (정상)
    String encode(CharSequence rawPassword);

    // 평문 비밀번호와 인코딩된 비밀번호 비교
    // rawPassword: 로그인 시 입력한 비밀번호
    // encodedPassword: DB에 저장된 해시
    boolean matches(CharSequence rawPassword, String encodedPassword);

    // 이 인코딩이 더 강한 인코더로 업그레이드가 필요한가?
    // 기본값: false (DelegatingPasswordEncoder에서 오버라이드)
    default boolean upgradeEncoding(String encodedPassword) {
        return false;
    }
}
```

### 2. BCryptPasswordEncoder 내부 구조

```java
// BCryptPasswordEncoder.java
public class BCryptPasswordEncoder implements PasswordEncoder {

    private final int strength;        // work factor (4~31, 기본 10)
    private final BCryptVersion version; // $2a$ (기본)
    private final SecureRandom random;

    public BCryptPasswordEncoder(int strength) {
        this.strength = strength;
        this.random = new SecureRandom();
    }

    @Override
    public String encode(CharSequence rawPassword) {
        // ① SecureRandom으로 16바이트 salt 생성
        byte[] salt = new byte[16];
        this.random.nextBytes(salt);

        // ② BCrypt 알고리즘 실행 (2^strength 번 반복)
        // strength=12 → 2^12 = 4096번 반복 → 약 0.3초
        return BCrypt.hashpw(rawPassword.toString(), BCrypt.gensalt(this.strength, this.random));
        // 결과: "$2a$12$<22자 salt><31자 해시>"
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword == null || encodedPassword.length() == 0) {
            return false;
        }
        // encodedPassword에서 salt 추출 → rawPassword에 같은 salt 적용 → 비교
        // (BCrypt 해시에 salt가 내장되어 있음)
        return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
    }
}

// BCrypt 해시 구조:
// $2a  $12  $eImiTXuWVxfM37uY4JANjQ  eK2...
// 버전  강도  22자 Base64 salt          31자 Base64 해시
```

### 3. DelegatingPasswordEncoder — 인코더 선택 메커니즘

```java
// DelegatingPasswordEncoder.java
public class DelegatingPasswordEncoder implements PasswordEncoder {

    private static final String PREFIX = "{";
    private static final String SUFFIX = "}";

    private final String idForEncode;              // 기본 인코더 ID ("bcrypt")
    private final PasswordEncoder passwordEncoderForEncode; // 기본 인코더
    private final Map<String, PasswordEncoder> idToPasswordEncoder; // 전체 맵

    @Override
    public String encode(CharSequence rawPassword) {
        // 새 인코딩: 기본 인코더 사용
        // 결과: "{bcrypt}$2a$12$..."
        return PREFIX + this.idForEncode + SUFFIX +
               this.passwordEncoderForEncode.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
        // ① ID 추출: "{bcrypt}$2a$12$..." → "bcrypt"
        String id = extractId(prefixEncodedPassword);
        // ② 매핑된 인코더 선택
        PasswordEncoder delegate = this.idToPasswordEncoder.get(id);
        if (delegate == null) {
            throw new IllegalArgumentException("There is no PasswordEncoder mapped for id '" + id + "'");
        }
        // ③ 인코더 ID 제거 후 실제 해시 비교
        String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
        return delegate.matches(rawPassword, encodedPassword);
    }

    @Override
    public boolean upgradeEncoding(String prefixEncodedPassword) {
        // 현재 인코딩 ID와 기본 인코더 ID가 다르면 업그레이드 필요
        String id = extractId(prefixEncodedPassword);
        if (!idForEncode.equals(id)) {
            return true; // "{noop}..." → BCrypt로 업그레이드 필요
        }
        // 같은 인코더라도 더 낮은 strength이면 업그레이드 권장
        return this.idToPasswordEncoder.get(id).upgradeEncoding(
            extractEncodedPassword(prefixEncodedPassword));
    }
}
```

### 4. 무중단 비밀번호 마이그레이션 전략

```java
// 시나리오: MD5 평문 저장 → BCrypt 마이그레이션

// ── 1단계: DelegatingPasswordEncoder + MD5 레거시 지원 ────────────
@Bean
public PasswordEncoder passwordEncoder() {
    Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put("bcrypt", new BCryptPasswordEncoder(12));
    encoders.put("md5", new MessageDigestPasswordEncoder("MD5")); // 레거시
    return new DelegatingPasswordEncoder("bcrypt", encoders);
}

// DB에서 MD5 해시 → "{md5}482c811da5d5b4bc6d497ffa98491e38"으로 마이그레이션
// (일회성 DB 업데이트 스크립트)

// ── 2단계: UserDetailsPasswordService로 자동 업그레이드 ───────────
@Service
@RequiredArgsConstructor
public class UpgradingUserDetailsPasswordService
        implements UserDetailsPasswordService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails updatePassword(UserDetails user, String newEncodedPassword) {
        // DaoAuthenticationProvider가 upgradeEncoding()=true 감지 시 자동 호출
        // newEncodedPassword: 새 인코더(BCrypt)로 재해싱된 비밀번호
        userRepository.updatePassword(user.getUsername(), newEncodedPassword);
        // 다음 로그인부터 "{bcrypt}..." 해시 사용
        return new CustomUserDetails(
            ((CustomUserDetails) user).getUserId(),
            user.getUsername(),
            newEncodedPassword,
            user.getAuthorities(),
            true, true, true, true
        );
    }
}

// 결과:
// 사용자가 다음 로그인 시 → MD5 비교 성공
//   → upgradeEncoding() = true (MD5 → BCrypt 업그레이드 필요)
//   → updatePassword() 자동 호출 → DB의 해시가 BCrypt로 교체
// 다음 로그인부터는 BCrypt로 검증
// 모든 사용자가 한 번씩 로그인하면 마이그레이션 완료
```

### 5. 각 인코더 성능과 보안 비교

```
인코더          설계 목표           특징                    2024년 기준 추천
────────────  ─────────────────  ─────────────────────── ────────────────
BCrypt        CPU 의존적 느린 해시  work factor로 속도 조절   strength=12~14
              (Blowfish 기반)     최대 72바이트 입력 제한    실무 표준

Argon2id      메모리+CPU 병렬성   memory, time, parallel    가장 강력
(PHC 우승)   을 결합한 최신 설계  3가지 파라미터로 조절     새 프로젝트 권장
              메모리 집약적       GPUResistance             64MB+ 권장

SCrypt        메모리+CPU 연동     N, r, p 파라미터          Argon2보다 구형
              (Litecoin 채굴 사용) 설정이 복잡               Argon2 권장

PBKDF2        NIST 표준 인증      iteration 횟수 조절        FIPS 요구 환경
              SHA 기반            상대적으로 GPU에 취약      (규정 준수용)

MD5, SHA     단순 해시           빠름 (취약점)              절대 사용 금지
```

---

## 💻 실험으로 확인하기

### 실험 1: BCrypt strength별 해싱 시간 벤치마크

```java
@GetMapping("/debug/bcrypt-benchmark")
public Map<String, String> benchmark() {
    String password = "testPassword123!";
    Map<String, String> result = new LinkedHashMap<>();

    for (int strength = 10; strength <= 14; strength++) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(strength);
        long start = System.currentTimeMillis();
        encoder.encode(password);
        long elapsed = System.currentTimeMillis() - start;
        result.put("strength=" + strength, elapsed + "ms");
    }
    return result;
}
```

```bash
curl http://localhost:8080/debug/bcrypt-benchmark
# {
#   "strength=10": "87ms",
#   "strength=11": "173ms",
#   "strength=12": "347ms",
#   "strength=13": "694ms",
#   "strength=14": "1388ms"
# }
# 약 2배씩 증가 (2^n 반복 구조)
# strength=12: 약 350ms → 적절한 보안/성능 균형
```

### 실험 2: DelegatingPasswordEncoder ID 추출 확인

```java
@GetMapping("/debug/encoder-format")
public Map<String, String> encoderFormat() {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    String encoded = encoder.encode("myPassword");

    return Map.of(
        "encoded", encoded,
        // {bcrypt}$2a$10$...
        "prefix", encoded.substring(0, encoded.indexOf('}') + 1),
        // {bcrypt}
        "matches", String.valueOf(encoder.matches("myPassword", encoded))
        // true
    );
}
```

### 실험 3: 업그레이드 자동화 동작 확인

```java
// DaoAuthenticationProvider에 UserDetailsPasswordService 주입 후
// "{noop}plaintext" 비밀번호로 로그인 시도

// 로그:
// DEBUG DaoAuthenticationProvider - Detected deprecated password encoding {noop}
// → updatePassword() 호출
// → DB에 "{bcrypt}$2a$12$..." 저장
// → 다음 로그인부터 BCrypt로 검증

@Test
void testPasswordUpgrade() {
    // given: noop 비밀번호로 저장된 사용자
    when(userDetailsService.loadUserByUsername("kim"))
        .thenReturn(User.withUsername("kim")
            .password("{noop}password123")
            .roles("USER")
            .build());

    // when: 로그인
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken("kim", "password123"));

    // then: updatePassword가 BCrypt 해시로 호출됨
    verify(userDetailsPasswordService).updatePassword(
        any(), argThat(pwd -> pwd.startsWith("{bcrypt}")));
}
```

---

## 🔒 보안 체크리스트

```
비밀번호 인코더 선택
  ☐ BCrypt(strength≥12) 또는 Argon2id 사용
  ☐ MD5, SHA, NoOp 절대 금지 (프로덕션)
  ☐ strength/파라미터는 서버에서 직접 벤치마크 후 결정 (0.1~1초 목표)

DelegatingPasswordEncoder 설정
  ☐ 새 인코딩 기본 ID = 현재 가장 강력한 인코더
  ☐ 레거시 인코더도 matches()를 위해 맵에 등록
  ☐ UserDetailsPasswordService 구현 → upgradeEncoding() 활성화

마이그레이션
  ☐ 기존 해시에 {id} 접두사 추가 (일회성 DB 업데이트)
  ☐ UserDetailsPasswordService 등록 → 로그인 시 자동 업그레이드
  ☐ 마이그레이션 완료 후 레거시 인코더 제거

입력 길이 제한
  ☐ BCrypt: 72바이트 초과 입력은 잘림 → 매우 긴 비밀번호 가능성 고려
  ☐ DoS 방지: 비밀번호 최대 길이 제한 (예: 72자 또는 128자)
```

---

## 🤔 트레이드오프

```
BCrypt vs Argon2id:
  BCrypt:
    장점  검증된 역사 (1999~), 광범위한 지원, 설정 단순
    단점  72바이트 제한, 메모리 비집약적 → GPU 공격 상대적 취약
          work factor만으로 조절 (메모리 증가 불가)

  Argon2id:
    장점  메모리+CPU+병렬성 동시 조절 → GPU/ASIC 저항성 최고
          PHC 공식 우승 알고리즘 (2015)
    단점  파라미터 조합이 복잡
          일부 구형 시스템에서 지원 안 됨

strength 높이기의 한계:
  장점  보안 강화 (브루트포스 비용 증가)
  단점  로그인 서버 CPU 부하 증가
        대용량 트래픽에서 로그인 응답 시간 증가
        DDoS: 로그인 엔드포인트 집중 공격 → CPU 고갈
  → 로그인 Rate Limiting + captcha 병행 필요
```

---

## 📌 핵심 정리

```
비밀번호 저장 원칙
  단방향 해시 + salt 내장 + 의도적으로 느림 = 적응형 해시
  BCrypt(strength=12) 또는 Argon2id = 현재 권장 표준

DelegatingPasswordEncoder
  DB 저장 형식: {id}encodedPassword
  matches() → ID 추출 → 해당 인코더로 비교
  upgradeEncoding() → 레거시 인코더 자동 업그레이드

무중단 마이그레이션 3단계
  1단계: 기존 해시에 {id} 접두사 추가 (DB 업데이트)
  2단계: DelegatingPasswordEncoder + 레거시 인코더 등록
  3단계: UserDetailsPasswordService로 로그인 시 자동 업그레이드

BCrypt strength 선택
  기준: 서버에서 약 0.3~0.5초
  2024년 기준: strength=12 (주기적 재검토 필요)
```

---

## 🤔 생각해볼 문제

**Q1.** BCrypt는 입력 비밀번호를 최대 72바이트로 제한합니다. 사용자가 72자 이상의 비밀번호를 설정하면 72자까지만 해싱됩니다. 이것이 보안 취약점이 될 수 있는 시나리오는 무엇이며, 어떻게 대응할 수 있는가?

**Q2.** `PasswordEncoder.encode()`는 항상 다른 결과를 반환하지만 `matches()`는 항상 `true`를 반환합니다. 이것이 가능한 이유는 무엇이며, "같은 비밀번호인지 비교"할 때 `encode()` 결과를 직접 비교하면 안 되는 이유는?

**Q3.** 로그인 엔드포인트에 비밀번호 해싱 비용을 이용한 CPU 소진 공격(Hash DoS)이 가능합니다. Spring Security 차원에서 이를 방어하는 방법과 애플리케이션 레벨에서 추가로 적용할 수 있는 대책을 설명하라.

> 💡 **해설**
>
> **Q1.** 공격자가 72자 이상의 비밀번호 "A×100" (A를 100번 반복)을 등록한 후, 실제 비밀번호 없이 "A×72"만 알아도 인증에 성공할 수 있습니다. 두 문자열의 BCrypt 결과가 동일하기 때문입니다. 이 취약점은 사용자가 매우 긴 비밀번호를 의도적으로 설정했을 때 발생합니다. 대응 방법으로는 최대 비밀번호 길이를 72자로 제한하거나, BCrypt 적용 전에 SHA-256 해시를 먼저 적용(`prehash`)하는 방법이 있습니다. 단, prehash 시 BCrypt에 고정 길이 바이너리 입력이 들어가므로 null byte 문제 등을 주의해야 합니다.
>
> **Q2.** BCrypt `encode()`는 호출마다 `SecureRandom`으로 새 salt(16바이트)를 생성하므로 동일 입력에 항상 다른 출력이 나옵니다. `matches(rawPassword, encodedPassword)`는 `encodedPassword`에서 salt를 추출하고, `rawPassword`에 동일 salt를 적용해 해시를 계산한 뒤 비교합니다. 따라서 두 `encode()` 결과를 직접 비교(`encode(A).equals(encode(A))`)하면 salt가 다르므로 항상 `false`가 됩니다. 비밀번호 동등성 검사는 반드시 `matches(rawPassword, encodedPassword)` 사용해야 합니다.
>
> **Q3.** Spring Security 차원의 방어로는 `RateLimitingFilter`를 Security Filter Chain에 추가해 IP당 로그인 시도 횟수를 제한하는 방법이 있습니다. 또한 `AuthenticationFailureHandler`에서 실패 횟수 카운터를 증가시키고 임계치 초과 시 계정 잠금(`isAccountNonLocked=false`)을 적용합니다. 애플리케이션 레벨에서는 Bucket4j, Resilience4j 등 Rate Limiter 라이브러리를 로그인 엔드포인트에 적용하고, CAPTCHA(reCAPTCHA)를 추가해 자동화 공격을 차단합니다. 인프라 레벨에서는 WAF(Web Application Firewall), Nginx의 `limit_req_zone` 설정, CloudFlare의 Bot Protection을 활용합니다.

---

<div align="center">

**[← 이전: UserDetailsService 구현과 커스터마이징](./03-user-details-service.md)** | **[홈으로 🏠](../README.md)** | **[다음: UsernamePasswordAuthenticationFilter 분석 ➡️](./05-username-password-authentication-filter.md)**

</div>
