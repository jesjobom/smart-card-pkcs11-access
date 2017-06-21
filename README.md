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
Since I needed to access some public certificates information and SunPKCS11 wouldn't help me, I searched a bit by Wrappers in Java that wouldn't need a custom native part.
I found the [IAIK PKCS11 Wrapper](https://github.com/mikma/pkcs11wrapper), but it has some native C codes that need compiling and the newer version is commercial and paid.
Luckly there is this [JNA PKCS11 Wrapper](https://github.com/joelhockey/jacknji11) that is pretty complete and gave me the understanding to code something simpler.

#### Caracteristics
- based on the [PKCS11 specification version 2.4](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- tested with libaetpkss.so and aetpkss1.dll

#### On the bright side
- Uses [JNA](https://github.com/java-native-access/jna), not JNI
- Works with Java < 8 on JRE 64 bits on Windows

#### On the dark side
- Harder to use
- Needs deep control over memory allocation when calling native methods
