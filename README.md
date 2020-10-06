# Saml Servlet


콘솔에서 아래와 같이 실행한다.

```
mvn jetty:run
```

빌드 시  
아래와 같이 war로 빌드한다

```
mvn package
```


간단 사용법
  
```java 
  SAMLUtil samlUtil = new SAMLUtil(<Issuer ID>, <Identity Provider Url>, <ACS Url>);    
```

JKS파일 사용하여 SamlRequest를 Signing 할 경우
- Keystore 생성
```
keytool -genkey -alias samlkey \
-keyalg RSA \
-keysize 2048  \
-sigalg SHA256withRSA \
-validity 735 \
-keypass secret \
-storepass secret \
-keystore keystore.jks

```
- Java Source  
키알고리즘이 다를경우 소스를 수정해야 함

```java
 SAMLUtil samlUtil = new SAMLUtil("com:koreanair:crewnet:sp",
                        "https://accounts.google.com/o/saml2/idp?idpid=C04cdbghf",
                         "http://127.0.0.1:8080/saml/SSO",
                         false,
                         false,
                         "classpath:/keystore.jks",
                         "secret",
                          "samlkey");
```
Google Test

- [x] Redirect Login Page (2FA 인증 후 ACS Url로 이동됨)  
- [ ] Read IDP Meta  
- [x] Singing AuthnRequest   
- [x] SAML Response parsing    
- [ ] SAML Response validate
