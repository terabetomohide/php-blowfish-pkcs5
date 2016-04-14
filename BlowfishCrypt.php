<?php

/**
 * Class BlowfishCrypt
 */
class BlowfishCrypt
{
    private $str;
    private $key;
    private $input;
    private $data;

    public function __construct($str, $key)
    {
        $this->key = $key;
        $this->str = $str;
    }

    public static function encrypt($str, $key)
    {
        $encrypter = new self($str, $key);
        $encrypter->input = $encrypter->pkcs5_pad();
        $encrypter->browFishEncrypt();
        return base64_encode($encrypter->data);
    }

    public static function decrypt($str, $key)
    {
        $decrypter = new self($str, $key);
        $decrypter->input = base64_decode($str);
        $decrypter->browFishDecrypt();
        $result = $decrypter->pkcs5_unpad();
        if (!$result) {
            return false;
        }
        return $decrypter->pkcs5_unpad();
    }

    private function browFishEncrypt()
    {
        $td = mcrypt_module_open('blowfish', '', 'ecb', '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $this->key, $iv);
        $this->data = mcrypt_generic($td, $this->input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
    }

    private function browFishDecrypt()
    {
        $td = mcrypt_module_open('blowfish', '', 'ecb', '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $this->key, $iv);
        $this->data = mdecrypt_generic($td, $this->input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
    }

    private function pkcs5_pad()
    {
        $str = $this->str;
        $blocksize = mcrypt_get_block_size('blowfish', 'ecb');
        $pad = $blocksize - (strlen($str) % $blocksize);
        return $str . str_repeat(chr($pad), $pad);
    }

    private function pkcs5_unpad()
    {
        $str = $this->data;
        $pad = ord($str{strlen($str) - 1});
        if ($pad > strlen($str)) return false;
        if (strspn($str, chr($pad), strlen($str) - $pad) != $pad) return false;
        return substr($str, 0, -1 * $pad);
    }
}
