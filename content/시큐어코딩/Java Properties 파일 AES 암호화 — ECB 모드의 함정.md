---
title: Java Properties 파일 AES 암호화 — ECB 모드의 함정
draft: true
tags:
  - AES
  - 암호화
  - 시큐어코딩
  - Java
  - 취약점
---

설정파일(`properties`)에 DB 접속 정보나 API 키를 평문으로 두는 대신 AES로 암호화해서 저장하는 패턴을 진단에서 자주 봅니다. 그런데 그중 상당수가 `AES/ECB/PKCS5Padding`을 그대로 씁니다. 동작은 하지만, 진단원 입장에서는 "암호화했다"는 착각만 주는 구현이에요. 실전에서는 ECB 모드 하나만 단독으로 문제인 경우는 거의 없고, 키를 소스에 박아 넣는 습관이 항상 같이 따라붙습니다. 이 글에서는 흔히 쓰이는 구현을 그대로 보고, ECB 모드와 하드코딩 키가 왜 위험한지, 어떻게 뚫리는지, 어떻게 고쳐야 하는지를 순서대로 짚습니다.

## 1. 흔히 보는 구현

### 1.1 암호화 코드

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESEncryption {

    public static String encrypt(String plainText, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        String key = "1234567890123456"; // 16-byte secret key
        String plainText = "database.ip=192.168.1.100\napi.url=http://example.com/api";

        String encryptedText = encrypt(plainText, key);
        System.out.println("Encrypted Text: " + encryptedText);
    }
}
```

암호화된 문자열은 `encrypted.properties` 파일에 저장합니다.

### 1.2 복호화 코드

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.io.InputStream;
import java.util.Properties;

public class SecureProperties {

    private static final String KEY = "1234567890123456"; // 16-byte secret key

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        InputStream input = SecureProperties.class.getClassLoader()
                .getResourceAsStream("encrypted.properties");

        if (input == null) {
            System.out.println("Sorry, unable to find encrypted.properties");
            return;
        }

        byte[] encryptedBytes = input.readAllBytes();
        String decryptedContent = decrypt(new String(encryptedBytes), KEY);
        properties.load(new java.io.StringReader(decryptedContent));

        System.out.println("Database IP: " + properties.getProperty("database.ip"));
        System.out.println("API URL: " + properties.getProperty("api.url"));
    }

    public static String decrypt(String encryptedText, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }
}
```

흐름을 요약하면 암호화는 평문을 AES로 암호화하고 Base64로 인코딩해 `encrypted.properties`에 저장하고, 복호화는 파일을 읽어 Base64로 디코딩한 뒤 AES로 복호화해 `Properties` 객체로 로드합니다. 여기까지는 여느 튜토리얼과 같습니다. 문제는 지금부터입니다.

## 2. 왜 이 구현이 위험한가

### 2.1 ECB 모드 — "같은 블록은 같은 암호문"

AES는 데이터를 16바이트 블록 단위로 자릅니다. ECB(Electronic Codebook) 모드는 각 블록을 서로 완전히 독립적으로 암호화해요. 이게 핵심 결함입니다. 평문 블록이 같으면 암호문 블록도 항상 같습니다.

타일 벽지를 떠올리면 이해가 쉽습니다. 벽지의 원본 무늬(평문)를 안 보이게 하려고 각 타일을 색만 바꿔 칠했는데, 같은 무늬 타일은 항상 같은 색으로 칠했다면 색을 몰라도 벽지 전체의 원본 패턴(경계선, 반복 구조)이 그대로 드러납니다. 유명한 "ECB 펭귄" 이미지 예제가 정확히 이 현상을 보여줍니다.

`database.ip=`, `api.url=` 같은 반복되는 필드명, 자주 등장하는 키워드가 있는 properties 파일이라면 암호문만 보고도 블록 경계와 반복 패턴이 그대로 보입니다. 완전한 평문 복구는 아니어도, 공격자에게 구조 정보를 그대로 흘려주는 셈이에요.

### 2.2 하드코딩된 16바이트 키

`"1234567890123456"`처럼 소스코드에 키를 박아 넣으면, 컴파일된 `.class`/`.jar`를 디컴파일하는 순간 키가 그대로 노출됩니다. jadx나 Ghidra로 몇 초면 나오는 문자열이에요. 암호화 알고리즘 자체가 아무리 강력해도 키가 공개되면 그 즉시 무의미합니다. AES-256을 써도 마찬가지입니다.

### 2.3 IV(초기화 벡터)가 아예 없다

ECB는 구조상 IV를 쓰지 않는 모드입니다. 그래서 같은 평문을 암호화할 때마다 항상 같은 암호문이 나옵니다. 즉 이 시스템은 결정론적(deterministic)입니다. 공격자가 "이 값이 A인지 B인지"를 이미 알고 있는 후보군과 암호문을 단순 비교하는 것만으로 원문을 추측할 수 있습니다(사전 공격, dictionary attack).

## 3. 공격 시나리오로 이어지는 흐름

```
①  jadx/Ghidra로 .class·.jar 디컴파일
       ↓
②  소스코드에서 하드코딩된 AES 키 확보
       ↓
③  encrypted.properties 탈취 (배포 파일·백업·Git 히스토리 등)
       ↓
④  키로 직접 복호화 → DB IP·API 엔드포인트·자격증명 평문 획득
       ↓
⑤  노출된 DB/API로 직접 접근 → 내부망 피벗(Lateral Movement)
```

키가 하드코딩돼 있다면 ECB냐 GCM이냐는 사실 부차적인 문제입니다. ①→②가 뚫리는 순간 암호화 자체가 무력화되니까요. 실전 진단에서는 이 둘(약한 모드 + 하드코딩 키)이 항상 세트로 발견됩니다. 키 관리가 안 되니 검증도 안 하고 ECB를 그대로 쓰는 식이죠.

APK나 데스크톱 배포 바이너리에 이런 패턴이 있다면, "AES를 쓴다"는 사실 자체는 리스크를 낮추지 않습니다. 키가 클라이언트 사이드에 존재하는 이상 이건 난독화(obfuscation)일 뿐, 암호화가 아닙니다.

## 4. 이렇게 고칩니다

핵심은 AEAD 모드로 전환하고, 매 암호화마다 랜덤 IV/nonce를 쓰고, 키를 소스 밖으로 빼는 것입니다.

```java
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESGcmEncryption {

    private static final int IV_LENGTH_BYTES = 12;   // GCM 권장 nonce 길이
    private static final int TAG_LENGTH_BITS = 128;  // 인증 태그 길이

    public static String encrypt(String plainText, SecretKeySpec key) throws Exception {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv); // 매번 새로 생성 — 절대 재사용 금지

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        byte[] encrypted = cipher.doFinal(plainText.getBytes());

        // IV를 암호문 앞에 붙여서 함께 저장 (복호화 시 다시 꺼내 씀)
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(result);
    }
}
```

왜 이렇게 바뀌어야 안전한지 하나씩 보면, `AES/GCM/NoPadding`은 AEAD(Authenticated Encryption with Associated Data) 방식이라 암호화와 동시에 무결성 검증(변조 탐지)까지 해줍니다. ECB/CBC는 데이터가 위변조돼도 복호화 시점엔 알 수 없지만, GCM은 태그 검증에 실패하면 예외를 던져요. 블록별 독립 암호화가 아니라 스트림처럼 동작해서 ECB의 패턴 노출 문제도 사라집니다.

매 호출마다 랜덤 IV(nonce)를 쓰면 같은 평문이라도 매번 다른 암호문이 나오게 됩니다. 결정론적 암호화 문제가 해결되는 셈이에요. 단, 같은 키로 같은 IV를 두 번 쓰면 GCM의 안전성이 완전히 깨지므로 `SecureRandom`으로 매번 새로 뽑는 게 필수입니다.

키는 환경변수, OS 키스토어, 또는 AWS KMS/HashiCorp Vault 같은 키 관리 시스템에서 런타임에 가져오도록 코드 밖으로 빼야 합니다. 최소한 `.class` 디컴파일 한 번으로 키가 뽑히는 구조는 피해야 해요. 키 자체가 노출되면 그 뒤의 모든 암호화 설계는 의미가 없어집니다.

가능하다면 민감정보를 애초에 애플리케이션 배포물에 담지 말고, 실행 환경(컨테이너 시크릿, 클라우드 시크릿 매니저)에서 주입하는 구조가 가장 안전합니다. 클라이언트 사이드 암호화는 키를 어딘가엔 둬야 한다는 근본적인 한계를 안고 갑니다.

## 마무리

`AES/ECB/PKCS5Padding` + 하드코딩 키는 암호화한 것처럼 보이는 평문일 뿐입니다. AES/GCM에 매번 랜덤 IV를 쓰고 키를 코드 밖으로 빼는 것이 최소 기준이고, 가능하면 키 관리 자체를 KMS/Vault 같은 외부 시스템에 맡기세요.
