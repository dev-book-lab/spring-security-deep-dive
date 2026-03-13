# GrantedAuthority vs Role 차이 — ROLE_ 접두사 규칙과 RoleHierarchy

---

## 🎯 핵심 질문

이 문서를 읽고 나면 다음 질문에 답할 수 있습니다.

- `hasRole("ADMIN")`과 `hasAuthority("ADMIN")`의 차이는 정확히 무엇인가?
- `ROLE_` 접두사 규칙은 어디서 왔으며 왜 존재하는가?
- `RoleVoter`는 어떤 기준으로 `ROLE_` 접두사가 없는 권한을 무시하는가?
- `RoleHierarchy`를 설정하면 권한 검사 흐름이 어떻게 달라지는가?
- DB에 권한을 "ROLE_ADMIN"으로 저장해야 하는가, "ADMIN"으로 저장해야 하는가?
- `@Secured("ADMIN")`과 `@Secured("ROLE_ADMIN")`은 다르게 동작하는가?

---

## 🔍 왜 이 보안 메커니즘이 필요한가

### 문제: Role과 Permission(Authority)는 개념이 다르다

```
현실 세계의 권한 모델:

  Role (역할):
    ADMIN     → 관리자 역할 (광범위한 권한의 묶음)
    USER      → 일반 사용자 역할
    MODERATOR → 중재자 역할

  Permission/Authority (세부 권한):
    READ_USERS     → 사용자 목록 조회
    WRITE_USERS    → 사용자 정보 수정
    DELETE_ORDERS  → 주문 삭제
    PUBLISH_POST   → 게시글 발행

이 두 개념을 구분 없이 같은 목록에 넣으면:
  getAuthorities() → ["ADMIN", "READ_USERS", "WRITE_USERS"]
  → "ADMIN"이 역할인지 권한인지 구분 불가
  → hasRole("ADMIN") vs hasAuthority("ADMIN") 혼용 시 혼란

Spring Security의 해결책:
  역할(Role)은 ROLE_ 접두사로 구별
  getAuthorities() → ["ROLE_ADMIN", "READ_USERS", "WRITE_USERS"]
  → hasRole("ADMIN")    내부적으로 "ROLE_ADMIN" 검색
  → hasAuthority("READ_USERS") 정확히 "READ_USERS" 검색
```

---

## 😱 흔한 보안 실수

### Before: hasRole()과 hasAuthority()를 혼용해서 항상 false 반환

```java
// ❌ 흔한 실수: UserDetails에서 "ADMIN"으로 저장하고 hasRole("ADMIN") 사용

@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority("ADMIN")); // ROLE_ 없음
}

// Security 설정:
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN") // 내부: "ROLE_ADMIN" 검색
);

// → getAuthorities()에 "ADMIN"만 있고 "ROLE_ADMIN"이 없으므로
//   /admin/** 접근 시 항상 403
// → 개발자는 "설정이 왜 안 먹히지?" 라며 혼란

// ✅ 올바른 방법들:
// 방법 1: ROLE_ 접두사 포함해서 저장
return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
// → hasRole("ADMIN")으로 검사 가능

// 방법 2: ROLE_ 없이 저장하고 hasAuthority()로 검사
return List.of(new SimpleGrantedAuthority("ADMIN"));
// → hasAuthority("ADMIN")으로 검사

// 방법 3: 팀 내 일관된 규칙 수립 (권장)
// DB 저장: "ROLE_ADMIN", "ROLE_USER" (ROLE_ 접두사 포함)
// 코드: hasRole("ADMIN") 사용 (ROLE_ 자동 추가)
```

### Before: @Secured에 ROLE_ 접두사를 빠뜨림

```java
// ❌ @Secured는 ROLE_ 접두사를 자동으로 추가하지 않는다
@Secured("ADMIN")         // "ADMIN" 그대로 검색 → ROLE_ADMIN이 있어도 매칭 안 됨
public void adminMethod() { ... }

// @PreAuthorize와 다르게 @Secured는 hasRole()이 아닌 hasAuthority()처럼 동작
// → getAuthorities()에 정확히 "ADMIN"이 있어야 통과

// ✅ @Secured 사용 시 ROLE_ 접두사 명시
@Secured("ROLE_ADMIN")    // getAuthorities()에 "ROLE_ADMIN" 있으면 통과
public void adminMethod() { ... }

// 또는 @PreAuthorize 사용 (더 명확)
@PreAuthorize("hasRole('ADMIN')")  // 내부: "ROLE_ADMIN" 검색 (자동 접두사)
public void adminMethod() { ... }
```

---

## ✨ 올바른 보안 구현

### hasRole() vs hasAuthority() 선택 기준

```java
http.authorizeHttpRequests(auth -> auth
    // hasRole: ROLE_ 접두사 자동 추가
    //   → DB에 "ROLE_ADMIN"으로 저장한 경우 사용
    .requestMatchers("/admin/**").hasRole("ADMIN")

    // hasAuthority: 문자열 그대로 비교
    //   → 세부 Permission 기반 접근 제어에 사용
    //   → DB에 "admin:read", "user:write" 형태로 저장한 경우
    .requestMatchers("/reports/**").hasAuthority("REPORT_READ")

    // hasAnyRole: 여러 Role 중 하나라도 있으면 통과
    .requestMatchers("/dashboard/**").hasAnyRole("ADMIN", "MANAGER")

    // access() + SpEL: 복합 조건
    .requestMatchers("/api/**").access(
        "hasRole('USER') and hasAuthority('API_ACCESS')")
);
```

### RoleHierarchy 설정

```java
// RoleHierarchy: ADMIN → MANAGER → USER 계층 설정
// ADMIN은 MANAGER와 USER의 권한을 자동으로 포함

@Bean
public RoleHierarchy roleHierarchy() {
    return RoleHierarchyImpl.fromHierarchy("""
        ROLE_ADMIN > ROLE_MANAGER
        ROLE_MANAGER > ROLE_USER
        """);
    // ROLE_ADMIN을 가진 사용자는 hasRole("USER")도 true
    // ROLE_MANAGER를 가진 사용자는 hasRole("USER")도 true
    // ROLE_USER를 가진 사용자는 hasRole("ADMIN") false
}

// Method Security에도 적용
@Bean
public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
        RoleHierarchy roleHierarchy) {
    DefaultMethodSecurityExpressionHandler handler =
        new DefaultMethodSecurityExpressionHandler();
    handler.setRoleHierarchy(roleHierarchy);
    return handler;
}
```

---

## 🔬 내부 동작 원리

### 1. GrantedAuthority 인터페이스와 구현체

```java
// GrantedAuthority.java
public interface GrantedAuthority extends Serializable {
    // 권한 문자열 반환
    // null이면 복잡한 권한 (AbstractSecurityInterceptor가 특별 처리)
    String getAuthority();
}

// SimpleGrantedAuthority.java — 가장 일반적인 구현체
public final class SimpleGrantedAuthority implements GrantedAuthority {
    private final String role;  // "ROLE_ADMIN", "READ_USERS" 등

    public SimpleGrantedAuthority(String role) {
        Assert.hasText(role, "A granted authority textual representation is required");
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return this.role;
    }
}
```

### 2. hasRole() vs hasAuthority() 내부 구현

```java
// SecurityExpressionRoot.java (SpEL 표현식 평가 담당)
public abstract class SecurityExpressionRoot
        implements SecurityExpressionOperations {

    // hasRole("ADMIN") → 내부적으로 "ROLE_ADMIN"으로 변환 후 hasAuthority() 호출
    @Override
    public boolean hasRole(String role) {
        return hasAnyRole(role);
    }

    @Override
    public boolean hasAnyRole(String... roles) {
        return hasAnyAuthorityName(this.defaultRolePrefix, roles);
        // defaultRolePrefix = "ROLE_" (기본값)
    }

    // hasAuthority("READ_USERS") → 정확히 "READ_USERS"로 검색
    @Override
    public boolean hasAuthority(String authority) {
        return hasAnyAuthority(authority);
    }

    @Override
    public boolean hasAnyAuthority(String... authorities) {
        return hasAnyAuthorityName(null, authorities); // 접두사 없이 그대로 검색
    }

    // 실제 비교 로직
    private boolean hasAnyAuthorityName(@Nullable String prefix, String... roles) {
        Set<String> roleSet = getAuthoritySet();  // Authentication.getAuthorities()

        for (String role : roles) {
            // prefix("ROLE_") + role("ADMIN") = "ROLE_ADMIN" 검색
            String defaultedRole = getRoleWithDefaultPrefix(prefix, role);
            if (roleSet.contains(defaultedRole)) {
                return true;
            }
        }
        return false;
    }

    private static String getRoleWithDefaultPrefix(
            @Nullable String defaultRolePrefix, String role) {
        if (defaultRolePrefix == null) return role;
        if (role.startsWith(defaultRolePrefix)) return role; // 이미 접두사 있음
        return defaultRolePrefix + role; // "ROLE_" + "ADMIN" = "ROLE_ADMIN"
    }
}
```

### 3. @Secured와 @PreAuthorize의 처리 방식 차이

```java
// @Secured 처리: Jsr250AuthorizationManager 또는 SecuredAuthorizationManager
// → getAuthority()와 정확히 일치하는지 비교 (접두사 자동 추가 없음)
// → @Secured("ROLE_ADMIN") 필요 (ROLE_ 명시)

// @PreAuthorize 처리: PreAuthorizeAuthorizationManager → SpEL 평가
// → hasRole("ADMIN") 표현식 → SecurityExpressionRoot.hasRole()
// → ROLE_ 자동 접두사 추가
// → @PreAuthorize("hasRole('ADMIN')") 사용 (ROLE_ 자동)

// @RolesAllowed (JSR-250 표준) 처리: Jsr250AuthorizationManager
// → @Secured와 동일하게 동작
// → @RolesAllowed("ROLE_ADMIN") 필요

// 정리:
//   어노테이션            인자               내부 비교
//   @PreAuthorize         hasRole('ADMIN')   "ROLE_ADMIN"
//   @PreAuthorize         hasAuthority('X')  "X"
//   @Secured              "ROLE_ADMIN"       "ROLE_ADMIN"
//   @RolesAllowed         "ROLE_ADMIN"       "ROLE_ADMIN"
```

### 4. RoleHierarchy 동작 원리

```java
// RoleHierarchyImpl.java
// 계층 구조:  ROLE_ADMIN > ROLE_MANAGER > ROLE_USER

public class RoleHierarchyImpl implements RoleHierarchy {

    // 계층 구조를 파싱해서 맵으로 저장
    // ROLE_ADMIN → [ROLE_MANAGER, ROLE_USER] (상속받는 하위 권한 전체)
    // ROLE_MANAGER → [ROLE_USER]
    // ROLE_USER → []

    @Override
    public Collection<GrantedAuthority> getReachableGrantedAuthorities(
            Collection<? extends GrantedAuthority> authorities) {
        // 입력: [ROLE_ADMIN]
        // 출력: [ROLE_ADMIN, ROLE_MANAGER, ROLE_USER]
        // → ROLE_ADMIN이 있으면 하위 권한을 모두 추가

        Set<GrantedAuthority> reachableRoles = new HashSet<>();
        Set<GrantedAuthority> processedAuthorities = new HashSet<>();
        Queue<GrantedAuthority> queue = new LinkedList<>(authorities);

        while (!queue.isEmpty()) {
            GrantedAuthority authority = queue.remove();
            if (processedAuthorities.contains(authority)) continue;
            processedAuthorities.add(authority);
            reachableRoles.add(authority);

            // 이 권한에서 도달 가능한 하위 권한들을 큐에 추가
            Collection<GrantedAuthority> lowerAuthorities =
                this.rolesReachableInOneStepMap.get(authority);
            if (lowerAuthorities != null) {
                queue.addAll(lowerAuthorities);
            }
        }
        return reachableRoles;
    }
}

// RoleHierarchyVoter 또는 DefaultMethodSecurityExpressionHandler에서 사용:
// authentication.getAuthorities()를 그대로 쓰는 대신
// roleHierarchy.getReachableGrantedAuthorities(authorities)로 확장된 목록 사용
```

### 5. ROLE_ 접두사 규칙의 기원

```
역사적 맥락:
  Spring Security 초기(Acegi Security 시절)부터 도입된 규칙
  RoleVoter가 "ROLE_"로 시작하는 권한만 처리하도록 설계됨
  → "ROLE_ADMIN"은 역할, "READ_USERS"는 권한으로 명확히 구분

현재(Spring Security 6.x):
  RoleVoter → RoleHierarchyVoter → AuthorizationFilter(SpEL) 로 발전
  하지만 hasRole() = "ROLE_" 접두사 자동 추가 규칙은 유지됨

접두사 변경도 가능:
  GrantedAuthorityDefaults.class를 Bean으로 등록
  @Bean
  static GrantedAuthorityDefaults grantedAuthorityDefaults() {
      return new GrantedAuthorityDefaults(""); // 빈 문자열 = 접두사 없음
  }
  → hasRole("ADMIN") = hasAuthority("ADMIN")와 동일하게 동작
  (단, 기존 코드와의 호환성 깨질 수 있으므로 신중하게 사용)
```

---

## 💻 실험으로 확인하기

### 실험 1: hasRole()과 hasAuthority() 동작 차이 확인

```java
// 같은 사용자에게 두 방식으로 권한 검사
@GetMapping("/test-role")
@PreAuthorize("hasRole('ADMIN')")  // "ROLE_ADMIN" 검색
public String testRole() { return "hasRole passed"; }

@GetMapping("/test-authority")
@PreAuthorize("hasAuthority('ADMIN')")  // "ADMIN" 검색
public String testAuthority() { return "hasAuthority passed"; }
```

```java
// UserDetails에서 "ROLE_ADMIN" 반환하는 경우:
@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
}
```

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/test-role
# → "hasRole passed"  ✓ (ROLE_ADMIN 검색, 매칭)

curl -H "Authorization: Bearer <token>" http://localhost:8080/test-authority
# → 403 Forbidden  ✗ (ADMIN 검색, 매칭 안 됨)
```

### 실험 2: RoleHierarchy 효과 확인

```bash
# ROLE_MANAGER를 가진 사용자로 ROLE_USER가 필요한 경로 접근

# RoleHierarchy 없는 경우:
curl -H "Authorization: Bearer <manager-token>" http://localhost:8080/user-area
# → 403 (ROLE_MANAGER는 있지만 ROLE_USER는 없음)

# RoleHierarchy 설정 후 (ROLE_MANAGER > ROLE_USER):
curl -H "Authorization: Bearer <manager-token>" http://localhost:8080/user-area
# → 200 OK (ROLE_MANAGER가 ROLE_USER를 포함)
```

### 실험 3: 현재 사용자의 확장된 권한 목록 출력

```java
@GetMapping("/my-authorities")
public Map<String, Object> myAuthorities(Authentication auth,
                                          RoleHierarchy hierarchy) {
    Collection<? extends GrantedAuthority> original = auth.getAuthorities();
    Collection<GrantedAuthority> reachable =
        hierarchy.getReachableGrantedAuthorities(original);

    return Map.of(
        "original", original.stream().map(GrantedAuthority::getAuthority).toList(),
        "reachable", reachable.stream().map(GrantedAuthority::getAuthority).toList()
    );
}
```

```bash
curl -H "Authorization: Bearer <admin-token>" http://localhost:8080/my-authorities
# → {"original":["ROLE_ADMIN"],"reachable":["ROLE_ADMIN","ROLE_MANAGER","ROLE_USER"]}
```

---

## 🔒 보안 체크리스트

```
일관된 권한 명명 규칙
  ☐ 역할(Role): ROLE_ 접두사 포함 (ROLE_ADMIN, ROLE_USER)
  ☐ 권한(Permission): 접두사 없음 (READ_USERS, WRITE_ORDERS)
  ☐ DB 저장 형식과 코드 검사 방식 통일

어노테이션별 접두사 규칙
  ☐ @PreAuthorize("hasRole('X')")    → "ROLE_X" 자동 추가 (ROLE_ 없이 사용)
  ☐ @Secured("ROLE_X")              → ROLE_ 명시 필요
  ☐ @RolesAllowed("ROLE_X")         → ROLE_ 명시 필요
  ☐ .hasRole("X")                   → "ROLE_X" 자동 추가
  ☐ .hasAuthority("ROLE_X")         → 정확히 "ROLE_X" 검색

RoleHierarchy
  ☐ Method Security에서도 RoleHierarchy가 동작하도록
     MethodSecurityExpressionHandler에 주입
  ☐ URL Security (authorizeHttpRequests)에도 RoleHierarchy 적용 확인
```

---

## 🤔 트레이드오프

```
ROLE_만 사용 vs Role + Permission 혼용:
  ROLE_만 사용:
    장점  단순함, hasRole() 일관되게 사용
    단점  세밀한 권한 제어 어려움 (ROLE_REPORT_READ_ONLY 같은 긴 이름 생김)

  Role + Permission 혼용:
    장점  역할(광범위)과 권한(세밀함)을 분리해서 관리
          "이 기능은 MANAGER 역할에게만, 이 데이터는 READ_USER 권한 있는 사람만"
    단점  hasRole()과 hasAuthority() 혼용 → 팀원 간 혼란 가능
          DB 설계와 코드 간 매핑 규칙을 문서화해야 함

RoleHierarchy:
  장점  상위 역할 부여만으로 하위 권한 자동 포함
        역할 체계 변경 시 코드 수정 최소화
  단점  계층 설정이 복잡해지면 누가 어떤 권한을 갖는지 파악 어려움
        테스트 시 RoleHierarchy가 주입됐는지 확인 필요
```

---

## 📌 핵심 정리

```
ROLE_ 접두사 규칙
  역할(Role) = ROLE_ + 역할명  (ROLE_ADMIN, ROLE_USER)
  hasRole("ADMIN") = hasAuthority("ROLE_ADMIN") 과 동일
  getAuthority() 반환값에 접두사가 포함되어 있어야 hasRole()이 매칭됨

어노테이션별 접두사 처리
  @PreAuthorize("hasRole('X')")  ROLE_ 자동 추가 ← 권장
  @Secured("ROLE_X")             접두사 명시 필요 ← 실수 잦음
  @RolesAllowed("ROLE_X")        접두사 명시 필요

RoleHierarchy
  상위 역할 → 하위 역할 권한 자동 포함
  URL Security + Method Security 모두에 명시적 주입 필요
  getReachableGrantedAuthorities()로 확장된 권한 목록 계산

DB 권장 저장 형식
  ROLE_ADMIN, ROLE_USER (ROLE_ 포함)
  hasRole("ADMIN") 방식으로 일관되게 검사
```

---

## 🤔 생각해볼 문제

**Q1.** `GrantedAuthorityDefaults`를 사용해 기본 접두사를 빈 문자열(`""`)로 변경하면 어떤 변화가 생기는가? 기존에 `ROLE_ADMIN`을 DB에 저장하고 있던 코드가 이 변경 후 어떤 영향을 받는가?

**Q2.** `RoleHierarchy`를 `@Bean`으로 등록했지만 `@PreAuthorize("hasRole('USER')")`에서 계층이 적용되지 않는다. 무엇이 누락된 것인가?

**Q3.** 권한 목록에 `GrantedAuthority.getAuthority()`가 `null`을 반환하는 객체를 포함할 수 있습니다. 이것은 어떤 용도로 사용되며 `AccessDecisionManager`는 이를 어떻게 처리하는가?

> 💡 **해설**
>
> **Q1.** `GrantedAuthorityDefaults("")` 설정 후 `hasRole("ADMIN")`은 내부적으로 `"" + "ADMIN" = "ADMIN"`으로 검색합니다. 기존에 `ROLE_ADMIN`을 DB에 저장하고 `hasRole("ADMIN")`으로 검사하던 코드는 더 이상 매칭되지 않습니다(`"ROLE_ADMIN" != "ADMIN"`). 반드시 DB의 권한 데이터도 `ADMIN`으로 변경하거나, 코드를 `hasAuthority("ROLE_ADMIN")`으로 변경해야 합니다. 이 변경은 광범위한 영향을 주므로 기존 애플리케이션에서는 신중하게 사용해야 합니다.
>
> **Q2.** `RoleHierarchy` Bean을 등록하는 것만으로는 Method Security에 자동으로 적용되지 않습니다. `MethodSecurityExpressionHandler`에 `roleHierarchy`를 주입해야 합니다. `@Bean static MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy rh) { DefaultMethodSecurityExpressionHandler h = new DefaultMethodSecurityExpressionHandler(); h.setRoleHierarchy(rh); return h; }`를 등록해야 `@PreAuthorize`에서 계층 구조가 적용됩니다. URL Security(`authorizeHttpRequests`)에도 별도의 설정이 필요합니다.
>
> **Q3.** `getAuthority()`가 `null`을 반환하는 `GrantedAuthority`는 "복합 권한(Complex Authority)"을 나타냅니다. 이는 단순한 문자열로 표현할 수 없는 도메인 객체 기반 권한(예: "ID=42인 문서에 대한 읽기 권한")을 구현할 때 사용합니다. `AccessDecisionManager`는 `getAuthority()`가 `null`인 `GrantedAuthority`를 `RoleVoter`나 일반 문자열 비교로는 처리하지 않고, 커스텀 `AccessDecisionVoter`가 이 타입을 직접 캐스팅해서 처리하도록 설계합니다. `AbstractSecurityInterceptor`는 `null` 반환 권한을 만나면 지원하는 Voter에게 위임합니다.

---

<div align="center">

**[← 이전: Authentication 객체 구조](./05-authentication-object.md)** | **[홈으로 🏠](../README.md)** | **[다음: SecurityContextPersistenceFilter 동작 ➡️](./07-security-context-persistence-filter.md)**

</div>
