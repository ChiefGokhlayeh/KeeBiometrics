# KeeBiometrics

KeePass 2.x plug-in and Android-app to allow for two-factor-authentication using biometrical data such as fingerprint or face-recognition.

As stated _KeeBiometrics_ consists of two main components. One being the [KeePass 2.x](https://keepass.info/) plug-in for _Windows_, registering as a [Key Provider](https://keepass.info/help/v2_dev/plg_keyprov.html) which handles the remote authentication and unlocking of the KeePass database. The authentication is done via the _KeeBimoetrics_ Android-app, which uses the fingerprint or face-recognition APIs of your smartphone or tablet to send a secret key over a secured connection to the KeePass plug-in running on your Windows-host.

This allows you to simply use your fingerprint or other biometrical authentication methods made available by the Android API to unlock your KeePass database on your PC.

## How it Works

After installing the `.apk`  on your phone/tablet and dropping the plug-in in your `<KeePass-install-dir>/Plugins` folder, you will need to register your Android device as a __Trusted-Device__. The following diagram illustrates the registration-procedure:
![PlantUML Registration](http://www.plantuml.com/plantuml/png/1S513i9020NGg-W5XhrB5xhm52FzQKawq7mWNj_txkPwzeRcUJkghdo8SFx6RdNqjnFKy8BNq5Zo8l06mss5V82dnKBHD6NDB52sK25so-8i2nzN_m40)

After you have a __Trusted-Device__ registered, you can unlock your database via fingerprint, face-recognition or any other biometric authentication method provided by your Android OS. The following diagram shows the unlock-procedure:
![PlantUML Unlock](http://www.plantuml.com/plantuml/png/1S6z3G8n30RG_gQ01UAUwaG11LC4vnCN4Tid_uZrUM-Fx9ubQxjEvLK3vUjoP9vn8_B-Qv-PHxqhu6oQq6niGWy7dd3JAKOlu3vDa3uvI7ead8OnbIxZRpjhsw6ZPFq1)