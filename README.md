# php-blowfish-pkcs5
Blowfish encrypt and decrypt PKCS5Padding, base64

##Usage

```php
$secretKey = 'xxxxxx';
$str = 'qwerty';

$secret = BlowfishCrypt::encrypt($str,$secretKey);

$str =  BlowfishCrypt::decrypt($secret,$secretKey);

```
