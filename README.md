# Two Simple Examples of PKCS11 Smart Card Access

Recently I had to read the certificates from a PKCS11 enabled smart card. After some research and some problems, I ended with two solutions:

## Sun's PKCS11 Implementation (sun.security.pkcs11.SunPKCS11)
This is an old implemention that has been included into JRE since Java 5. But, on Windows and prior to Java 8, only in the 32 bits versions of JRE [[JEP 131](http://openjdk.java.net/jeps/131)].
It is easy to use, especially if you have experience with Keystores and Certificates.

#### Caracteristics
- Uses a native JNI PKCS11 wrapper (j2pkcs11)

#### On the bright side
- easy to use
- included with JRE 5+

#### On the dark side
- doesn't work on JRE Windows 64 bits if Java 7 or prior
- to load the keystore the pin code is required, even to read public certificates

## Own PKCS11 Implementation 
Since I needed to access some public certificates information without the pin code and SunPKCS11 wouldn't help me, I searched a bit by Wrappers in Java that wouldn't need a custom native part.
I found the [IAIK PKCS11 Wrapper](https://github.com/mikma/pkcs11wrapper), but it has some native C codes that need compiling and the newer version is commercial and paid.
Luckly there is this [JNA PKCS11 Wrapper](https://github.com/joelhockey/jacknji11) that is pretty complete and gave me the understanding to overcome some memory allocation problems when using structres.

#### Caracteristics
- based on the [PKCS11 specification version 2.4](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- tested with libaetpkss.so and aetpkss1.dll

#### On the bright side
- Uses [JNA](https://github.com/java-native-access/jna), not JNI
- Works with Java < 8 on JRE 64 bits on Windows
- The pin code is only needed to access private certificates for signing or for writing operations

#### On the dark side
- Harder to use
- Needs deep control over memory allocation when calling native methods and using structures

## Example of Use
```
# mvn "-Dexec.args=-classpath %classpath com.jesjobom.pkcs11.Main PinCode123" -Dexec.executable=$JAVA_HOME/bin/java org.codehaus.mojo:exec-maven-plugin:1.2.1:exec
...                                                                        
14:56:05.883 [main] INFO  com.jesjobom.pkcs11.Main -  === BEGIN SMART CARD ACCESS ===
14:56:05.885 [main] INFO  com.jesjobom.pkcs11.Main -  === USING SUN'S IMPLEMENTATION ===
14:56:08.709 [main] INFO  com.jesjobom.pkcs11.Main - CN=JONH SNOW PARKER:123456789,OU=AR SERASA,OU=(EM BRANCO),OU=RFB e-CPF A3,OU=Secretaria da Receita Federal do Brasil - RFB,O=ICP-Brasil,C=BR
14:56:08.709 [main] INFO  com.jesjobom.pkcs11.Main - 
14:56:08.710 [main] INFO  com.jesjobom.pkcs11.Main -  === USING JNA ===
14:56:09.163 [main] INFO  com.jesjobom.pkcs11.Main - JONH SNOW PARKER:123456789
14:56:09.163 [main] INFO  com.jesjobom.pkcs11.Main -  === END OF SMART CARD ACCESS ===
...
```
