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
Google Test

-[x] Redirect Login Page (2FA 인증 후 ACS Url로 이동됨)  
-[ ] Read IDP Meta  
-[ ] Singing AuthnRequest   
-[ ] SAML Response parsing  
