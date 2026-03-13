# AccessDecisionManager와 Voter 체인 — 투표 기반 권한 결정 전략

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `AffirmativeBased`, `ConsensusBased`, `UnanimousBased` 세 전략의 결정 방식 차이는?
- `AccessDecisionVoter`가 반환하는 세 값(`ACCESS_GRANTED`, `ACCESS_ABSTAIN`, `ACCESS_DENIED`)의 의미는?
- `RoleVoter`, `WebExpressionVoter`, `AuthenticatedVoter`는 각각 어떤 `ConfigAttribute`를 처리하는가?
- `AccessDecisionManager`가 Spring Security 6.x에서 `AuthorizationManager`로 대체된 이유는?
- 커스텀 Voter를 작성해 기존 Voter 체인에 추가하는 방법은?
- `ACCESS_ABSTAIN`이 모든 Voter의 결과일 때 각 전략은 어떻게 동작하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 단일 규칙으로 표현하기 어려운 복잡한 권한 조건

```
복잡한 접근 제어 시나리오:

  문서 조회 권한:
  조건 A: ROLE_ADMIN이면 항상 허용
  조건 B: ROLE_USER이고 문서 소유자면 허용
  조건 C: 근무 시간(9-18시)에만 허용

  단일 SpEL 표현식:
  @PreAuthorize("hasRole('ADMIN') or
                 (hasRole('USER') and @docSecurity.isOwner(#id)) and
                 T(java.time.LocalTime).now().hour >= 9 and ...")
  → 가능하지만 복잡하고 테스트하기 어려움

해결: AccessDecisionVoter 분리
  RoleVoter: 역할 검사
  OwnershipVoter: 소유권 검사
  BusinessHoursVoter: 시간 제한 검사
  → 각 Voter가 독립적으로 의견 제출
  → AccessDecisionManager가 투표 결과 집계해 최종 결정

설계 원칙:
  각 Voter = 단일 책임 (SRP)
  Voter 추가만으로 새 규칙 도입 (OCP)
  독립적인 단위 테스트 가능
```

---

## 😱 흔한 보안 실수

### Before: UnanimousBased에서 모든 Voter가 ABSTAIN하는 상황 처리 누락

```java
// ❌ 문제: allowIfAllAbstainDecisions 기본값을 모름
// UnanimousBased 기본 설정:
// allowIfAllAbstainDecisions = false
// → 모든 Voter가 ABSTAIN이면 AccessDeniedException 발생

// 시나리오: 새 ConfigAttribute를 처리하는 Voter를 추가하지 않은 경우
// 모든 기존 Voter가 ABSTAIN → 예외 발생

// ✅ 명시적으로 설정
@Bean
public AccessDecisionManager accessDecisionManager() {
    UnanimousBased manager = new UnanimousBased(
        List.of(new RoleVoter(), new AuthenticatedVoter(), new CustomVoter()));
    manager.setAllowIfAllAbstainDecisions(false); // 기본값, 명시 권장
    // true로 설정 시: 모든 ABSTAIN → 허용 (보안 위험 가능)
    return manager;
}
```

### Before: AffirmativeBased에서 하나의 Voter 허용이 다른 Voter의 거부를 무력화

```java
// ❌ 예상과 다른 동작:
// AffirmativeBased: 하나라도 GRANTED이면 허용

// Voter 체인:
// RoleVoter: ROLE_ADMIN → GRANTED
// BusinessHoursVoter: 새벽 3시 → DENIED

// 결과: AffirmativeBased → GRANTED!
// (BusinessHoursVoter의 DENIED 무시됨)

// ✅ "모든 조건을 만족해야" 할 때는 UnanimousBased
@Bean
public AccessDecisionManager accessDecisionManager() {
    return new UnanimousBased(
        List.of(new RoleVoter(), new BusinessHoursVoter()));
    // 모든 Voter가 GRANTED여야만 허용
    // RoleVoter: GRANTED + BusinessHoursVoter: DENIED → 거부
}
```

---

## ✨ 올바른 보안 구현

### 커스텀 Voter 구현과 등록

```java
// IP 대역 기반 Voter 예시
@Component
public class IpRangeVoter implements AccessDecisionVoter<FilterInvocation> {

    private static final String IP_ATTRIBUTE_PREFIX = "IP_RANGE_";

    @Override
    public int vote(Authentication authentication,
                    FilterInvocation filterInvocation,
                    Collection<ConfigAttribute> attributes) {

        // 처리할 ConfigAttribute인지 확인
        boolean applicable = attributes.stream()
            .anyMatch(attr -> attr.getAttribute() != null
                && attr.getAttribute().startsWith(IP_ATTRIBUTE_PREFIX));

        if (!applicable) {
            return ACCESS_ABSTAIN; // 관련 없는 속성 → 기권
        }

        String remoteIp = filterInvocation.getRequest().getRemoteAddr();

        boolean allowed = attributes.stream()
            .filter(attr -> attr.getAttribute().startsWith(IP_ATTRIBUTE_PREFIX))
            .map(attr -> attr.getAttribute().substring(IP_ATTRIBUTE_PREFIX.length()))
            .anyMatch(cidr -> isInRange(remoteIp, cidr));

        return allowed ? ACCESS_GRANTED : ACCESS_DENIED;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute.getAttribute() != null
            && attribute.getAttribute().startsWith(IP_ATTRIBUTE_PREFIX);
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    private boolean isInRange(String ip, String cidr) {
        // CIDR 범위 검사 로직
        return InetAddressRange.of(cidr).contains(InetAddress.getByName(ip));
    }
}
```

---

## 🔬 내부 동작 원리

### 1. AccessDecisionVoter 인터페이스

```java
// AccessDecisionVoter.java
public interface AccessDecisionVoter<S> {

    int ACCESS_GRANTED = 1;   // 허용 의견
    int ACCESS_ABSTAIN = 0;   // 기권 (이 Voter는 판단하지 않음)
    int ACCESS_DENIED = -1;   // 거부 의견

    /**
     * @param authentication 현재 사용자
     * @param object 보호되는 대상 (FilterInvocation, MethodInvocation 등)
     * @param attributes 접근 제어 속성 목록 (ConfigAttribute)
     * @return ACCESS_GRANTED / ACCESS_ABSTAIN / ACCESS_DENIED
     */
    int vote(Authentication authentication, S object,
             Collection<ConfigAttribute> attributes);

    boolean supports(ConfigAttribute attribute); // 처리할 ConfigAttribute 선언
    boolean supports(Class<?> clazz);            // 처리할 보호 대상 타입 선언
}
```

### 2. 세 가지 AccessDecisionManager 전략

```java
// ── AffirmativeBased (기본값) ────────────────────────────────────────
// 하나라도 GRANTED이면 허용
// (OR 조건: "어떤 조건이든 하나만 만족하면")
public class AffirmativeBased extends AbstractAccessDecisionManager {

    @Override
    public void decide(Authentication authentication, Object object,
                        Collection<ConfigAttribute> configAttributes) {
        int deny = 0;

        for (AccessDecisionVoter voter : getDecisionVoters()) {
            int result = voter.vote(authentication, object, configAttributes);

            if (result == ACCESS_GRANTED) {
                return; // 하나라도 GRANTED → 즉시 허용
            }
            if (result == ACCESS_DENIED) {
                deny++;
            }
        }

        // GRANTED 없음
        if (deny > 0) {
            throw new AccessDeniedException("Access is denied");
        }
        // 모두 ABSTAIN인 경우 allowIfAllAbstainDecisions 설정에 따름
        checkAllowIfAllAbstainDecisions(); // false이면 예외
    }
}

// ── ConsensusBased ───────────────────────────────────────────────────
// GRANTED 수 > DENIED 수이면 허용
// (다수결: "투표 결과의 과반수")
public class ConsensusBased extends AbstractAccessDecisionManager {

    @Override
    public void decide(Authentication authentication, Object object,
                        Collection<ConfigAttribute> configAttributes) {
        int grant = 0, deny = 0;

        for (AccessDecisionVoter voter : getDecisionVoters()) {
            int result = voter.vote(authentication, object, configAttributes);
            if (result == ACCESS_GRANTED) grant++;
            else if (result == ACCESS_DENIED) deny++;
        }

        if (grant > deny) return; // GRANTED 과반수 → 허용
        if (deny > grant) throw new AccessDeniedException("...");
        // 동수: allowIfEqualGrantedDeniedDecisions (기본 true → 허용)
        if (grant == deny && grant > 0) {
            if (!this.allowIfEqualGrantedDeniedDecisions) {
                throw new AccessDeniedException("...");
            }
            return;
        }
        checkAllowIfAllAbstainDecisions(); // 모두 ABSTAIN
    }
}

// ── UnanimousBased ────────────────────────────────────────────────────
// 하나라도 DENIED이면 거부 (모두 GRANTED여야 허용)
// (AND 조건: "모든 조건을 동시에 만족해야")
public class UnanimousBased extends AbstractAccessDecisionManager {

    @Override
    public void decide(Authentication authentication, Object object,
                        Collection<ConfigAttribute> configAttributes) {

        int grant = 0;

        for (AccessDecisionVoter voter : getDecisionVoters()) {
            // ConfigAttribute 하나씩 개별 투표
            for (ConfigAttribute attribute : configAttributes) {
                int result = voter.vote(authentication, object,
                    Collections.singletonList(attribute));

                if (result == ACCESS_DENIED) {
                    throw new AccessDeniedException("..."); // 즉시 거부
                }
                if (result == ACCESS_GRANTED) {
                    grant++;
                }
            }
        }

        if (grant > 0) return; // 거부 없이 하나라도 GRANTED → 허용
        checkAllowIfAllAbstainDecisions();
    }
}
```

### 3. 기본 제공 Voter 상세

```java
// ── RoleVoter ────────────────────────────────────────────────────────
// ROLE_ 접두사로 시작하는 ConfigAttribute 처리
public class RoleVoter implements AccessDecisionVoter<Object> {

    private String rolePrefix = "ROLE_";

    @Override
    public int vote(Authentication authentication, Object object,
                    Collection<ConfigAttribute> attributes) {
        int result = ACCESS_ABSTAIN;

        Collection<? extends GrantedAuthority> authorities =
            authentication.getAuthorities();

        for (ConfigAttribute attribute : attributes) {
            if (!attribute.getAttribute().startsWith(rolePrefix)) {
                continue; // ROLE_ 아닌 속성은 ABSTAIN
            }
            result = ACCESS_DENIED; // 관련 속성 발견 → 일단 DENIED

            for (GrantedAuthority authority : authorities) {
                if (attribute.getAttribute().equals(authority.getAuthority())) {
                    return ACCESS_GRANTED; // 권한 일치 → GRANTED
                }
            }
        }
        return result; // ABSTAIN (관련 속성 없음) or DENIED
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute.getAttribute() != null
            && attribute.getAttribute().startsWith(rolePrefix);
    }
}

// ── AuthenticatedVoter ────────────────────────────────────────────────
// IS_AUTHENTICATED_FULLY, IS_AUTHENTICATED_REMEMBERED,
// IS_AUTHENTICATED_ANONYMOUSLY 처리
public class AuthenticatedVoter implements AccessDecisionVoter<Object> {

    @Override
    public int vote(Authentication authentication, Object object,
                    Collection<ConfigAttribute> attributes) {
        for (ConfigAttribute attribute : attributes) {
            switch (attribute.getAttribute()) {
                case "IS_AUTHENTICATED_FULLY":
                    return trustResolver.isFullyAuthenticated(authentication)
                        ? ACCESS_GRANTED : ACCESS_DENIED;
                case "IS_AUTHENTICATED_REMEMBERED":
                    return (!trustResolver.isAnonymous(authentication))
                        ? ACCESS_GRANTED : ACCESS_DENIED;
                case "IS_AUTHENTICATED_ANONYMOUSLY":
                    return ACCESS_GRANTED; // 항상 허용
                default:
                    return ACCESS_ABSTAIN; // 관련 없는 속성
            }
        }
        return ACCESS_ABSTAIN;
    }
}

// ── WebExpressionVoter ────────────────────────────────────────────────
// authorizeRequests()에서 access("SpEL") 처리
// SpEL 표현식을 평가해서 GRANTED/DENIED 반환
public class WebExpressionVoter implements AccessDecisionVoter<FilterInvocation> {

    private SecurityExpressionHandler<FilterInvocation> expressionHandler;

    @Override
    public int vote(Authentication authentication, FilterInvocation filterInvocation,
                    Collection<ConfigAttribute> attributes) {
        WebExpressionConfigAttribute webConfig = findWebExpressionConfig(attributes);
        if (webConfig == null) return ACCESS_ABSTAIN;

        EvaluationContext ctx = expressionHandler
            .createEvaluationContext(authentication, filterInvocation);
        boolean granted = (boolean) webConfig.getAuthorizeExpression().getValue(ctx);
        return granted ? ACCESS_GRANTED : ACCESS_DENIED;
    }
}
```

### 4. AccessDecisionManager → AuthorizationManager 전환 (6.x)

```java
// Spring Security 6.x AuthorizationManager와의 매핑:
// AffirmativeBased + RoleVoter + WebExpressionVoter
// ≈ AuthorityAuthorizationManager + WebExpressionAuthorizationManager

// AccessDecisionManager (5.x, deprecated) → 사용 방식:
// http.authorizeRequests().accessDecisionManager(customAdm)

// AuthorizationManager (6.x) 커스텀 → 사용 방식:
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/office/**")
            .access(new BusinessHoursAuthorizationManager()) // 커스텀 AM
        .anyRequest().authenticated()
    );
    return http.build();
}

// 커스텀 AuthorizationManager (6.x 방식)
public class BusinessHoursAuthorizationManager
        implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authentication,
            RequestAuthorizationContext context) {

        int hour = LocalTime.now().getHour();
        boolean inBusinessHours = hour >= 9 && hour < 18;
        return new AuthorizationDecision(inBusinessHours);
    }
}
```

### 5. 세 전략 비교 시각화

```
Voter 결과:
  V1(RoleVoter): GRANTED
  V2(BusinessHoursVoter): DENIED
  V3(IpVoter): ABSTAIN

AffirmativeBased (OR): V1=GRANTED → 즉시 허용 ✓
  → DENIED와 ABSTAIN은 무시됨

ConsensusBased (다수결): GRANTED(1) vs DENIED(1) 동수
  → allowIfEqualGrantedDeniedDecisions (기본 true) → 허용 ✓

UnanimousBased (AND): V2=DENIED → 즉시 거부 ✗
  → 하나라도 DENIED이면 차단

모두 ABSTAIN일 때:
  allowIfAllAbstainDecisions = false (기본)
  → 세 전략 모두 AccessDeniedException
```

---

## 💻 실험으로 확인하기

### 실험 1: 세 전략별 동작 차이 단위 테스트

```java
class AccessDecisionManagerStrategyTest {

    AccessDecisionVoter<Object> grantVoter =
        (auth, obj, attrs) -> AccessDecisionVoter.ACCESS_GRANTED;
    AccessDecisionVoter<Object> denyVoter =
        (auth, obj, attrs) -> AccessDecisionVoter.ACCESS_DENIED;
    AccessDecisionVoter<Object> abstainVoter =
        (auth, obj, attrs) -> AccessDecisionVoter.ACCESS_ABSTAIN;

    Authentication auth = new AnonymousAuthenticationToken(
        "key", "anon", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));

    @Test
    void affirmativeBased_oneGranted_allows() {
        AffirmativeBased adm = new AffirmativeBased(List.of(grantVoter, denyVoter));
        assertDoesNotThrow(() -> adm.decide(auth, new Object(), List.of()));
    }

    @Test
    void unanimousBased_oneDenied_denies() {
        UnanimousBased adm = new UnanimousBased(List.of(grantVoter, denyVoter));
        assertThatThrownBy(() -> adm.decide(auth, new Object(), List.of()))
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void allAbstain_defaultDenies() {
        AffirmativeBased adm = new AffirmativeBased(List.of(abstainVoter));
        adm.setAllowIfAllAbstainDecisions(false);
        assertThatThrownBy(() -> adm.decide(auth, new Object(), List.of()))
            .isInstanceOf(AccessDeniedException.class);
    }
}
```

### 실험 2: 커스텀 Voter TRACE 로그

```yaml
logging:
  level:
    org.springframework.security.access.vote: TRACE
```

```
# authorizeRequests() 사용 시 (구버전):
TRACE AffirmativeBased - Voter: org.springframework.security.access.vote.RoleVoter,
      returned: 1 (GRANTED)
TRACE AffirmativeBased - Authorization successful
```

---

## 🔒 보안 체크리스트

```
전략 선택
  ☐ 여러 조건 중 하나라도 충족: AffirmativeBased
  ☐ 모든 조건을 동시에 충족: UnanimousBased
  ☐ 다수결 방식: ConsensusBased (주로 관리 시스템)

Voter 구현
  ☐ supports() 메서드가 정확한 ConfigAttribute 접두사/패턴 처리
  ☐ 관련 없는 속성에는 반드시 ACCESS_ABSTAIN 반환
  ☐ ACCESS_ABSTAIN vs ACCESS_DENIED 의미 명확히 구분

allowIfAllAbstainDecisions
  ☐ false (기본값) 유지 권장
  ☐ true로 설정 시: 모든 Voter가 판단 안 하면 허용 → 보안 위험
```

---

## 🤔 트레이드오프

```
AccessDecisionManager(Voter) vs AuthorizationManager (신버전):
  Voter 방식:
    장점  여러 독립적인 관심사(역할, 시간, IP 등)를 별도 Voter로 분리
          기존 코드(5.x)와 호환
    단점  deprecated, 세 가지 전략 선택 복잡
          ABSTAIN 개념이 혼란스러울 수 있음

  AuthorizationManager (6.x):
    장점  타입 안전, 함수형, 컴포지션 쉬움
          지연 Authentication 로드 지원
    단점  기존 Voter 재사용 불가 (래핑 필요)

전략 선택의 보안 함의:
  AffirmativeBased: ROLE_ADMIN이면 다른 제약(시간, IP) 무력화 가능
  UnanimousBased: 가장 엄격하지만 새 Voter 추가 시 기존 흐름 영향
```

---

## 📌 핵심 정리

```
세 전략 결정 방식
  AffirmativeBased: 하나라도 GRANTED → 허용 (기본값, OR 조건)
  ConsensusBased:  GRANTED > DENIED → 허용 (다수결)
  UnanimousBased:  하나라도 DENIED → 거부 (AND 조건)

Voter 결과 의미
  ACCESS_GRANTED (1):  허용 의견
  ACCESS_ABSTAIN (0):  기권 (이 Voter는 판단 안 함)
  ACCESS_DENIED (-1):  거부 의견

기본 Voter 목록
  RoleVoter:           ROLE_ 접두사 ConfigAttribute 처리
  AuthenticatedVoter:  IS_AUTHENTICATED_* 처리
  WebExpressionVoter:  access() SpEL 처리 (authorizeRequests()에서)

6.x 대안
  AuthorizationManager 인터페이스로 대체
  authorizeHttpRequests().access(customAuthorizationManager)
```

---

## 🤔 생각해볼 문제

**Q1.** `RoleHierarchy`를 설정했을 때 `RoleVoter`가 계층적 역할을 처리하지 못하는 이유는 무엇이며, `RoleHierarchyVoter`를 사용해야 하는 이유는?

**Q2.** `ConsensusBased`에서 `allowIfEqualGrantedDeniedDecisions = true`(기본)로 설정되어 있을 때, GRANTED와 DENIED가 동수인 경우 허용되는 것이 보안 관점에서 적절한가? 어떤 상황에 `false`로 설정해야 하는가?

**Q3.** Spring Security 6.x의 `AuthorizationManager`가 Voter 방식을 대체하면서 `ACCESS_ABSTAIN` 개념이 없어졌습니다. 여러 조건을 독립적으로 검사하되 기권 개념이 필요한 경우 `AuthorizationManager`로 어떻게 구현하는가?

> 💡 **해설**
>
> **Q1.** `RoleVoter`는 `authentication.getAuthorities()`를 직접 순회해 `ConfigAttribute`와 문자열 비교를 합니다. 역할 계층이 `ROLE_ADMIN > ROLE_USER`로 설정되어 있어도, `RoleVoter`는 `ROLE_ADMIN` 사용자가 `ROLE_USER`가 필요한 리소스를 요청할 때 `authentication.getAuthorities()`에 `ROLE_USER`가 없으므로 `ACCESS_DENIED`를 반환합니다. `RoleHierarchyVoter`는 `RoleHierarchy.getReachableGrantedAuthorities()`를 호출해 계층적으로 도달 가능한 모든 권한을 포함해 비교합니다. 6.x의 `AuthorityAuthorizationManager`는 기본적으로 `RoleHierarchy`를 지원하므로 별도 설정 없이 계층적 역할이 동작합니다.
>
> **Q2.** `allowIfEqualGrantedDeniedDecisions = true`는 동수일 때 접근을 허용하므로 "의심스러우면 허용(fail-open)" 원칙을 따릅니다. 금융 거래, 개인정보 접근, 관리자 기능처럼 "의심스러우면 차단(fail-secure)"이 필요한 시스템에서는 `false`로 설정해야 합니다. 예를 들어 근무 시간 Voter(GRANTED)와 내부망 Voter(DENIED: 외부망 접근 시)가 동수가 되면, `true`이면 외부망에서 근무 시간에 허용됩니다. 이를 방지하려면 `false`로 설정해 동수는 거부하도록 해야 합니다.
>
> **Q3.** `AuthorizationManager` 컴포지션으로 기권 개념을 구현할 수 있습니다. `null`을 반환하는 `AuthorizationManager`를 "기권"으로 간주하고, 여러 매니저를 체인으로 연결하는 `CompositeAuthorizationManager`를 구현합니다. 각 매니저가 `null`을 반환하면 다음 매니저로 위임하고, `AuthorizationDecision`을 반환하면 해당 결정을 사용합니다. 모든 매니저가 `null`을 반환하면 기본 정책(거부 또는 허용)을 적용합니다. 또는 `RequestMatcherDelegatingAuthorizationManager`가 이미 이 패턴을 구현하고 있어, RequestMatcher가 매칭되지 않으면(`null` 반환) 다음 규칙으로 위임합니다.

---

<div align="center">

**[← 이전: FilterSecurityInterceptor 내부 구조](./03-filter-security-interceptor.md)** | **[홈으로 🏠](../README.md)** | **[다음: SpEL을 활용한 복잡한 권한 검사 ➡️](./05-spel-authorization.md)**

</div>
