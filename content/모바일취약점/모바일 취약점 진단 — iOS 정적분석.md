---
title: 모바일 취약점 진단 — iOS 정적분석
tags:
  - 모바일보안
  - 취약점진단
  - iOS
  - 정적분석
---

iOS 앱 진단의 첫 단계는 앱을 실행하기 전에 **IPA 파일 자체에서 뽑아낼 수 있는 정보**를 먼저 훑는 것입니다. 탈옥(jailbreak)된 기기가 없어도, 앱을 설치하지 않아도 할 수 있는 작업이 대부분이라 동적 분석 전에 공격 표면과 우선순위를 잡는 용도로 씁니다. 이 글은 정적분석까지만 다루고, 키체인에 실제로 뭐가 저장되는지·런타임에서 SSL 피닝이 어떻게 걸리는지 같은 동적 영역은 이후 글에서 다룹니다.

---

## 1. IPA 구조와 추출

**원리**: IPA는 확장자만 바뀐 ZIP 압축 파일입니다. 이 블로그의 웹 취약점 글에서 DOCX/XLSX가 사실 "ZIP 안에 XML"이라 XXE 공격면이 된다고 다룬 적이 있는데, IPA도 같은 발상입니다 — 다만 안에 들어있는 건 XML이 아니라 컴파일된 실행 파일과 리소스입니다.

`unzip app.ipa`로 풀면 `Payload/앱이름.app/` 디렉터리가 나오고, 그 안에 `Info.plist`의 `CFBundleExecutable` 값과 같은 이름의 **Mach-O 바이너리**(실행 파일 본체, `.app` 디렉터리 이름과 실제 실행 파일명이 다를 수 있어 `CFBundleExecutable`로 확인하는 게 정확합니다), `Info.plist`(앱 설정과 메타데이터), `*.storyboardc`/`.nib`/이미지 같은 리소스, `_CodeSignature/`(서명 정보)가 들어 있고, `embedded.mobileprovision`은 Ad Hoc·엔터프라이즈·개발용 배포에서는 들어 있지만 App Store 배포본에는 빠져 있는 경우가 많아 모든 IPA에 항상 있는 파일은 아닙니다.

App Store에서 받은 IPA는 FairPlay DRM으로 바이너리 자체가 암호화돼 있는 경우가 많아, 이 경우 `otool -l`로 본 `LC_ENCRYPTION_INFO`(64비트 바이너리에서는 `LC_ENCRYPTION_INFO_64`) 로드 커맨드의 `cryptid`가 1이면 아직 암호화된 상태이고(탈옥 기기에서 `frida-ios-dump` 등으로 메모리 복호화 덤프를 떠야 분석 가능), TestFlight·Ad Hoc·엔터프라이즈 배포나 개발자가 직접 빌드한 IPA는 이 암호화가 없어 바로 분석할 수 있습니다.

- 체크 포인트: `Payload/*.app` 안에 들어있는 바이너리가 `LC_ENCRYPTION_INFO`/`LC_ENCRYPTION_INFO_64`로 암호화돼 있는지(`otool -l <바이너리> | grep -A4 LC_ENCRYPTION`), 앱 번들 안에 다른 프레임워크(`Frameworks/*.framework`)나 앱 익스텐션(`PlugIns/*.appex`)이 같이 들어있어 각각 별도 바이너리로 분석해야 하는지
- 참고: [Apple — Bundle Structure](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html), [OWASP MASTG — Automated Static Analysis](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0078/)

## 2. Info.plist 분석

**원리**: `Info.plist`는 앱의 선언적 설정 파일이라 바이너리를 디스어셈블하지 않고도 많은 걸 알 수 있습니다.

먼저 `CFBundleURLTypes`에 등록된 URL scheme(커스텀 딥링크, 예: `myapp://`)은 다른 앱이 호출할 수 있는 진입점이므로, 어떤 scheme이 있는지와 그 핸들러가 전달받은 파라미터를 검증 없이 쓰는지가 체크 대상입니다.

다음으로 중요한 게 `NSAppTransportSecurity`(ATS)입니다. iOS 9 SDK 이상으로 빌드된 앱의 기본값은 **HTTPS 강제 + TLS 1.2 이상 + 순방향 비밀성(forward secrecy) 요구**이고, 별도 설정이 전혀 없으면 이 기본 보호가 그대로 적용됩니다.

단, ATS는 `URLSession`/`NSURLConnection` 등 **URL Loading System을 거치는 요청에만 적용**되고, 앱이 `Network.framework`의 저수준 API나 BSD 소켓으로 직접 TCP 연결을 맺으면 이 보호를 그대로 우회합니다 — 그래서 ATS 설정만 보고 "이 앱은 평문 통신을 안 한다"고 단정하면 안 되고, 저수준 네트워킹 API 사용 여부도 같이 봐야 합니다. ATS를 완화하는 키는 각각 허용 범위가 다릅니다.
  - `NSAllowsArbitraryLoads: true` — 앱 전역에서 ATS를 끕니다. 다만 Apple 공식 문서에 명시된 대로, `NSAllowsArbitraryLoadsForMedia`/`NSAllowsArbitraryLoadsInWebContent`/`NSAllowsLocalNetworking` 중 **하나라도 plist에 존재하면 그 값(true/false 무관)과 상관없이 `NSAllowsArbitraryLoads` 자체가 무시되고 기본값 `NO`로 처리**됩니다. 즉 세 세분화 키가 하나도 없을 때만 전역 해제가 실제로 먹힙니다.
  - `NSAllowsArbitraryLoadsInWebContent: true` — `WKWebView`로 불러오는 웹 콘텐츠에만 평문 HTTP를 허용하고, 앱이 직접 만드는 `URLSession` 요청에는 영향이 없습니다.
  - `NSExceptionDomains`에 등록한 도메인은 서브도메인까지 포함하려면 `example.com` 항목 아래 `NSIncludesSubdomains: true`를 따로 지정해야 하고(`*.example.com` 같은 와일드카드 표기는 지원되지 않습니다), 그 도메인에 `NSExceptionAllowsInsecureHTTPLoads: true`를 걸면 전역 ATS 설정과 무관하게 **그 도메인만의 독립적인 예외**가 적용됩니다(전역이 아니라 범위가 좁은 예외라 실무에서 더 흔하게 씀).
  - `NSExceptionMinimumTLSVersion`으로 도메인별 최소 TLS 버전을 낮추는 예외도 Apple 문서에 여전히 나와 있지만, Apple이 구형 TLS에 대한 플랫폼 차원의 지원을 점차 좁혀 온 추세를 감안하면 "이 예외 키가 plist에 있다"는 사실만으로 대상 기기에서 실제로 낮은 버전 협상이 성립한다고 단정하지 말고, 진단 대상 iOS 버전에서 실제 연결로 핸드셰이크가 성사되는지를 직접 확인해야 합니다.

  `NSAllowsArbitraryLoads`의 우선순위 규칙만 따로 그리면 다음과 같습니다.

  ```mermaid
  flowchart TD
      A["plist에 NSAllowsArbitraryLoads 존재"] --> B{"ForMedia/InWebContent/LocalNetworking 중 하나라도 존재?"}
      B -->|예| C["NSAllowsArbitraryLoads 무시, 기본값 NO로 강제"]
      B -->|아니오| D{"NSAllowsArbitraryLoads = true?"}
      D -->|예| E["전역 ATS 해제"]
      D -->|아니오| F["기본 ATS 보호 유지"]
  ```

  App Store 심사에서는 `NSAllowsArbitraryLoads`를 쓰면 App Store Connect 제출 시 사유 소명을 요구하므로, 전역 예외가 걸린 앱은 심사를 통과한 "정당한 사유"가 실제로 존재하는지(서드파티 SDK 호환용인지, 내부망 전용 앱인지)까지 같이 봐야 과장 없는 평가가 됩니다.

  마지막으로 `NSxxxUsageDescription`(`NSCameraUsageDescription`, `NSLocationWhenInUseUsageDescription`, `NSContactsUsageDescription` 등) 키의 존재 여부로 이 앱이 요청**할 수 있는** 민감 권한 후보 목록을 추정할 수 있습니다 — 다만 이 문자열이 있다는 게 해당 권한을 실제 코드 경로가 호출한다는 확정 증거는 아니고, 쓰지 않는 서드파티 SDK가 끼워 넣었거나 이후 기능용으로 남겨둔 경우도 있어 실제 호출 여부는 바이너리·코드 분석으로 별도 확인해야 합니다. 반대로 이 문자열이 없는 상태에서 해당 보호 자원에 접근하면 iOS는 그 접근을 거부하고 앱을 종료시키는 식으로 반응합니다.

  참고로 암호화 수출 신고 관련 `ITSAppUsesNonExemptEncryption` 키도 같은 파일에 있는데, 이건 보안 취약점이 아니라 규제 준수 메타데이터이고 값만으로 앱이 커스텀 암호화를 자체 구현했는지까지 단정하기는 어려워 진단 범위에서는 참고 수준으로만 다룹니다.

- 체크 포인트:
  - `NSAllowsArbitraryLoads`가 켜져 있을 때 `NSAllowsArbitraryLoadsForMedia`/`NSAllowsArbitraryLoadsInWebContent`/`NSAllowsLocalNetworking` 키가 같이 존재해서 실제로는 무시되고 있는 건 아닌지
  - `NSExceptionDomains`에 `NSIncludesSubdomains`로 서브도메인까지 넓힌 예외나 사설 네트워크용 예외가 과도하게 걸려 있는지
  - `CFBundleURLTypes`에 등록된 scheme이 입력값 검증 없이 딥링크 파라미터를 처리하는지(코드 분석으로 확인할 가설)
  - `NSxxxUsageDescription` 목록으로 추정한 권한 후보가 앱의 실제 기능 범위를 벗어나는지
  - 앱이 URL Loading System을 우회하는 저수준 네트워킹 API를 쓰는지
- 참고: [Apple — NSAllowsArbitraryLoads](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads), [Apple — Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections), [Apple — Requesting Access to Protected Resources](https://developer.apple.com/documentation/uikit/requesting-access-to-protected-resources), [OWASP MASTG — ATS Configurations Allowing Cleartext Traffic](https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0322/)

## 3. 바이너리 정보 추출

**원리**: Objective-C는 런타임에 클래스·메서드 정보를 그대로 들고 있어야 메시지 디스패치(`objc_msgSend`)가 동작하기 때문에, 컴파일된 바이너리의 `__DATA.__objc_classlist`, `__TEXT.__objc_methname` 같은 섹션에 **클래스 이름, 메서드 시그니처, 프로퍼티 이름이 평문 문자열로 그대로 남습니다**. `class-dump`나 `class-dump-z`는 이 메타데이터를 읽어 헤더 파일 형태로 복원해 주므로, 소스 없이도 앱의 클래스 구조와 API 설계를 상당 부분 추정할 수 있습니다(다만 접근 제어자, 컴파일러 최적화, 배포 전 심볼 스트리핑 여부에 따라 복원되는 범위는 달라지고, 소스 코드 자체를 그대로 복원해 주는 건 아닙니다). `otool -L`은 링크된 동적 라이브러리/프레임워크 목록(어떤 SDK를 쓰는지 추정), `nm`은 심볼 테이블(공개 함수/클래스 이름)을 보여줍니다.

문제는 **Swift 전용으로 작성된 바이너리**입니다. Swift는 동적 메시지 디스패치 대신 대부분 정적 호출이나 vtable을 쓰고, 메서드 이름도 사람이 읽기 어려운 형태로 네임 맹글링(name mangling)되어 있어 class-dump가 기대하는 Objective-C 런타임 메타데이터 형식과 다릅니다.

Objective-C 런타임에 노출되려면 `NSObject`를 상속하는 것만으로는 부족하고 해당 클래스·메서드가 `@objc`로 선언되어(또는 Objective-C와 상호운용되도록) 있어야 하며, 그렇게 노출된 멤버만 class-dump에 일부 보입니다. 순수 Swift 타입(구조체, enum, `@objc` 노출이 없는 클래스/메서드)은 `swift-demangle`로 맹글링된 이름만 풀어낼 수 있을 뿐 class-dump류 도구로는 시그니처 복원이 거의 안 됩니다.

이 때문에 Swift 비중이 큰 앱일수록 정적분석 난이도가 올라가고, Hopper/Ghidra/IDA 같은 디스어셈블러로 넘어가야 하는 경우가 많습니다.

- 체크 포인트:
  - `otool -L <바이너리>`로 링크된 프레임워크 목록에 디버그용 로깅 라이브러리가 남아있는지
  - 이름만으로 추정되는 SDK 버전은 실제 바이너리 버전 분석으로 추가 확인할 가설로 다루기
  - `class-dump -H <바이너리> -o 출력폴더`로 뽑은 헤더에 민감한 클래스명(`APIKeyManager`, `DebugLogin` 등)이 있는지
  - 바이너리가 순수 Swift라 `@objc` 노출 심볼 외에는 class-dump 결과가 비어 있는지
- 참고: [OWASP MASTG — class-dump](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0043), [OWASP MASTG — Reviewing Disassembled Objective-C and Swift Code](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0076), [class-dump (GitHub)](https://github.com/nygard/class-dump)

## 4. 바이너리 보호 기법 확인

**원리**: PIE(Position Independent Executable)는 바이너리가 매 실행마다 다른 메모리 주소에 로드되게 해 ASLR이 성립하기 위한 전제조건입니다. Apple은 iOS App Store 제출 시 메인 실행 파일의 PIE를 요구한 지 오래되어, Xcode로 빌드한 최신 iOS 앱은 사실상 전부 PIE가 켜진 상태로 나옵니다 — 그래서 PIE 확인 자체보다는 "혹시 꺼진 레거시/사이드로드 바이너리가 있는지"를 걸러내는 용도에 더 가깝습니다. 확인 대상은 **앱의 메인 실행 파일**이고, 번들에 같이 들어있는 `.framework`/`.dylib`는 애초에 위치 독립 코드(PIC)로 빌드되는 공유 라이브러리라 `MH_PIE` 플래그 자체가 의미가 없으니 거기서 플래그가 안 보인다고 문제 삼을 필요는 없습니다. `otool -hv <메인 실행 파일>`로 Mach-O 헤더 플래그를 보면 `PIE` 플래그 유무를 바로 확인할 수 있습니다.

스택 카나리(stack canary, Apple 구현은 `___stack_chk_guard`/`___stack_chk_fail`)는 함수 리턴 전에 스택에 심어둔 값이 변조됐는지 검사해 스택 버퍼 오버플로우로 리턴 주소를 직접 덮어쓰는 공격의 난이도를 올려주는 컴파일러 보호 기법으로, Xcode의 clang은 Objective-C/C/C++ 코드 중 **컴파일러가 취약하다고 판단한, 지역 버퍼가 있는 함수**에 한해 이 코드를 삽입합니다(빌드 설정이나 함수 형태에 따라 삽입 여부가 갈리므로 "전부 자동으로 들어간다"고 단정할 건 아닙니다). `nm <바이너리> | grep stack_chk`나 `otool -Iv <바이너리> | grep stack_chk`로 해당 심볼이 임포트돼 있는지 보면 전반적인 경향은 파악할 수 있지만, 심볼이 안 보인다고 해당 바이너리의 모든 함수가 무방비 상태라고 단정할 수는 없습니다. 다만 **순수 Swift 코드**라면 이 항목은 우선순위를 낮춰도 됩니다 — Swift는 배열 경계 검사, 타입 안전성 등을 언어 차원에서 강제하도록 설계되어 있어 C 스타일 스택 버퍼 오버플로우 자체가 성립하는 경로가 훨씬 좁기 때문에, 스택 카나리 유무보다는 Swift 코드가 `UnsafePointer`/`UnsafeMutableRawPointer` 같은 안전하지 않은 API나 C 라이브러리 브릿징을 쓰는 지점이 있는지를 보는 게 더 의미 있습니다.

ARC(Automatic Reference Counting)는 메모리 손상 전반이 아니라 **Objective-C 객체의 참조 카운트 수명 관리**를 컴파일 타임에 자동 retain/release 코드 삽입으로 대신해 주는 기법으로, C/C++이 직접 관리하는 메모리나 Swift 쪽 참조 카운팅까지 보장해 주는 건 아닙니다(Swift는 `objc_retain`/`objc_release`가 아니라 자체 `swift_retain`/`swift_release` 계열을 쓰므로, ObjC용 심볼이 안 보인다고 Swift 코드에 참조 카운팅이 없다는 뜻은 아닙니다). `nm`/`otool -Iv` 출력에서 `_objc_retain`, `_objc_release`, `_objc_autorelease`, `_objc_retainAutorelease` 같은 심볼이 보이면 그 바이너리의 **Objective-C 코드 부분**이 ARC로 빌드됐다는 정황 증거 정도로 참고할 수 있지만, 이 심볼 유무만으로 바이너리 전체 혹은 각 컴파일 단위의 ARC 설정을 확정 판정할 수는 없습니다.

세 가지 모두 "있다/없다"가 취약점 유무를 가르는 게 아니라, **빠져 있을 경우 다른 메모리 손상 취약점(버퍼 오버플로우, UAF 등)이 발견됐을 때 익스플로잇 난이도가 얼마나 낮아지는지**를 가늠하는 보조 지표로 씁니다.

- 체크 포인트:
  - 메인 실행 파일의 `otool -hv` 출력에 `PIE` 플래그가 있는지(프레임워크/dylib는 제외)
  - Objective-C/C/C++ 코드 비중이 큰 바이너리라면 `nm`/`otool -Iv` 출력에 `_stack_chk_fail`/`_stack_chk_guard` 심볼이 있는지
  - `_objc_retain`/`_objc_autorelease` 계열 심볼 유무로 ARC 적용 여부를 추정할 수 있는지
  - C/C++로 작성된 서드파티 네이티브 라이브러리가 끼어 있어 위 보호 기법이 빠진 채 빌드됐는지
- 참고: [OWASP MASTG — Binary Protection Mechanisms](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0061/), [OWASP MASTG — Obtaining Compiler-Provided Security Features](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0118/), [Apple — Transitioning to ARC](https://developer.apple.com/library/archive/releasenotes/ObjectiveC/RN-TransitioningToARC/Introduction/Introduction.html)

## 5. 키체인/엔타이틀먼트 미리보기

**원리**: `codesign -d --entitlements :- <앱 경로>`를 실행하면 앱에 서명된 entitlement plist가 그대로 출력됩니다. 여기서 정적으로 볼 수 있는 건 앱이 **"무엇을 요청하는지"** 선언뿐이고, 실제로 키체인에 뭘 저장하는지·공유 범위가 코드상 어떻게 쓰이는지는 런타임/파일시스템 분석 영역이라 이 글에서는 다루지 않습니다(로컬 저장소 포렌식 글에서 이어서 다룰 예정).

주로 보는 키는 `keychain-access-groups`(이 그룹에 속한 다른 앱이 **접근 가능한 자격**을 선언한 것일 뿐, 그 자체로 실제 공유 항목이 존재함을 뜻하지는 않습니다 — 같은 접근 그룹을 선언하고 서명·프로비저닝 조건까지 맞는 다른 앱이 실제로 설치돼 있어야 공유가 성립합니다), `com.apple.security.application-groups`(앱 익스텐션·메인 앱 간 공유 컨테이너), `aps-environment`(푸시 알림 사용 여부와 development/production 환경), `com.apple.developer.associated-domains`(Universal Links로 연결을 위임받을 도메인 목록)입니다.

다만 associated domains는 URL scheme처럼 앱 쪽 선언만으로 하이재킹이 성립하는 구조가 아니라, 그 도메인의 `.well-known/apple-app-site-association` 파일이 이 앱의 번들 ID를 실제로 허용하고 있는지와 상호 검증되는 구조라, 점검 시에는 등록된 도메인을 앱이 실제로 통제하는지와 더불어 그 도메인의 AASA 파일 내용까지 같이 봐야 합니다.

참고로 `UIBackgroundModes`(백그라운드 실행 방식)는 entitlement가 아니라 `Info.plist`의 일반 키이므로 `codesign`이 아니라 Info.plist 쪽에서 확인합니다.

- 체크 포인트:
  - `keychain-access-groups`에 선언된 그룹이 다른(특히 서드파티 벤더) 앱과 겹치는지
  - 실제로 그 앱이 기기에 설치되어 공유가 성립하는 조합인지
  - `com.apple.security.application-groups`로 공유 컨테이너를 쓰는 익스텐션이 있는지
  - `associated-domains`에 등록된 도메인이 실제로 그 앱이 통제하는 도메인이고 해당 도메인의 AASA 파일이 이 앱의 번들 ID를 포함하는지
- 참고: [Apple — Entitlements Reference](https://developer.apple.com/documentation/bundleresources/entitlements), [Apple — Supporting Associated Domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains), [Apple — UIBackgroundModes](https://developer.apple.com/documentation/bundleresources/information-property-list/uibackgroundmodes)

## 6. 하드코딩 시크릿

**원리**: `strings <바이너리>`는 바이너리 파일 전체를 훑어 사람이 읽을 수 있는 연속된 문자 시퀀스를 모두 뽑아내는 범용 도구라, Mach-O의 문자열 섹션(`__TEXT.__cstring` 등)뿐 아니라 Swift 메타데이터 섹션(`__TEXT.__swift5_*`)을 포함한 바이너리 전체에서 매치되는 문자열을 찾아줍니다. Objective-C든 Swift든 소스 코드에 박아 넣은 문자열 리터럴이 **별도의 암호화·난독화 처리를 추가하지 않는 한 평문 그대로 바이너리에 남는 경우가 많아서**, API 키, 내부 엔드포인트 URL, 하드코딩된 OAuth client secret, 디버그용 백도어 계정 같은 게 종종 발견됩니다(컴파일러가 문자열을 항상 똑같은 형태로 유지해 준다는 보장은 아니고, 상수 폴딩·중복 제거 등으로 위치나 형태가 달라질 수 있습니다).

`Info.plist`도 같은 관점에서 봐야 하는데, 커스텀 키 값에 API 키나 서명용 시크릿을 그대로 넣어둔 사례가 흔합니다.

다만 짧은 영숫자 문자열이 전부 시크릿은 아니므로, 문자열 주변 컨텍스트(변수명·클래스명과 함께 쓰였는지, Base64/hex로 보이는 고엔트로피 문자열인지)를 같이 봐야 오탐을 줄일 수 있습니다.

- 체크 포인트: `strings <바이너리> | grep -iE "key|secret|token|api|password"`로 1차 스크리닝 후 실제 유효한 자격증명인지 확인, `Info.plist`의 커스텀 키 값, 고엔트로피 문자열(Base64/hex 패턴)이 하드코딩돼 있는지
- 참고: [OWASP MASTG — Retrieving Strings](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0071), [OWASP MASTG — Testing Local Data Storage](https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0052)

## 7. 탈옥(jailbreak) 탐지 로직 확인

**원리**: `strings`와 class-dump 결과에서 흔히 보이는 탈옥 탐지 패턴은 ① `/Applications/Cydia.app`, `/Library/MobileSubstrate/MobileSubstrate.dylib`, `/bin/bash`, `/usr/sbin/sshd`, `/etc/apt` 같은 전통적인 탈옥 환경 특유의 파일/디렉터리 경로를 `stat`/`fopen`으로 존재 확인, ② 샌드박스 밖 쓰기 시도(`/private/` 아래에 테스트 파일을 써보고 성공 여부 확인), ③ `fork()` 호출 성공 여부(정상 iOS 앱 샌드박스는 `fork()`를 허용하지 않아 실패하는데, 일부 탈옥 환경에서는 샌드박스 제약이 풀려 성공합니다), ④ 의심스러운 동적 라이브러리가 프로세스에 로드돼 있는지(`dyld` 이미지 목록 순회), ⑤ 커스텀 URL scheme `cydia://`가 열리는지 확인하는 패턴입니다.

다만 이 경로 목록은 고전적인(루트 파일시스템이 쓰기 가능한) 탈옥 기준이고, 최근 주류인 루트리스(rootless) 탈옥은 `/var/jb/` 하위에 격리된 경로를 쓰고 Cydia 대신 Sileo 같은 패키지 매니저를 쓰는 경우가 많아, 탐지 로직이 이런 최신 경로까지 반영하고 있는지도 같이 봐야 합니다.

정적분석에서 탐지 로직의 **존재와 위치**를 찾아냈다고 우회가 자동으로 되는 건 아닙니다. 앱 구현에 따라 이 검사들이 공통된 판정 함수 하나로 모여 있을 수도, 여러 지점에 흩어져 있을 수도 있어서, Frida 같은 동적 계측 도구로 실제 우회 지점(들)을 찾아 후킹해야 하고(경로 확인 함수가 항상 "없음"을 리턴하게, `fork()` 결과를 조작하는 식), 로직이 난독화돼 있으면 정적분석만으로 전체 목록을 찾기 어려워 동적 분석과 병행해야 합니다.

- 체크 포인트: `strings` 결과에 `Cydia`, `MobileSubstrate`, `/var/jb` 같은 고전·루트리스 탈옥 관련 문자열이 모두 있는지, class-dump 결과에 `isJailbroken`, `JailbreakDetector` 류의 클래스/메서드 이름이 있는지, 탐지 로직이 한 곳에 모여 있는지 아니면 여러 지점에 분산돼 있는지(후킹 난이도에 영향)
- 참고: [OWASP MASTG — Jailbreak Detection](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084/), [OWASP MASTG — Bypassing Jailbreak Detection](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0152/), [OWASP MASVS](https://mas.owasp.org/MASVS/)

---

정적분석은 "코드를 실행하지 않고 얼마나 알아낼 수 있는가"의 영역이라, 여기서 잡은 ATS 예외·과도한 entitlement·하드코딩 시크릿·탈옥 탐지 지점은 다음 단계인 동적 분석(Frida 후킹, SSL 피닝 우회, 런타임 키체인/파일시스템 검사)에서 검증할 가설 목록이 됩니다.
