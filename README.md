# Saml Servlet

## SAMUtil initialize

초기화 하는 방법은 두가지가 있다  
(There are two methods to initialize)

```java
  SAMLUtil samlUtil = new SAMLUtil(
     "classpath:/metadata/GoogleIDPMetadata-koreanair.com.xml",  //IDP Metafile
      "com:koreanair:xxsx:xxxx"                                 //Issuer Id
  );


  String request = samlUtil.createSAMLRequest();
    //or
  request = samlUtil.toSAMLRequestHtml();
  ```

또는 property 파일을 통해서 초기화 한다
(or using property file)

```java
SAMLUtil samlUtil = SAMLUtil.create("classpath:/sso.properity")
```

sso.properties 파일의 내용은 아래와 같이 작성  
```
sso.issuerId = com:koreanair:xxx:sp
sso.assertionConsumerServiceUrl = https://localhost:8443/saml/SSO
sso.idpmetadata = classpath:/metadata/GoogleIDPMetadata-koreanair.com.xml
sso.keystore.file = classpath:/keystore.jks
sso.keystore.alias = samlkey
sso.keystore.password = secret
```

SAML Request를 signing 처리 할 경우 jks 파일을 작성할것 (Keystroe 작성 참조)   
```java
 samlUtil.setSigner(
  "classpath:/keystore.jks", //JKS 파일 위치
   "secret",                 //패스워드
   "samlkey"                 //alias
 );

String request = samlUtil.toSAMLRequestHtml(true); //true 는 signig 할지 여부
```

###  Keystore 작성  
 JKS파일 사용하여 SamlRequest를 Signing 할 경우

```
keytool -genkey -alias samlkey 
-keyalg RSA 
-keysize 2048  
-sigalg SHA256withRSA 
-validity 735 
-keypass secret 
-storepass secret 
-keystore keystore.jks
```

# How to run

콘솔에서 아래와 같이 실행한다.

```
mvn jetty:run
```
