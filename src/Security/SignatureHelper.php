<?php

namespace Jazor\Security;

use Jazor\Console;

class SignatureHelper
{

    public static function verify(string $data, string $signature, AsymmetricKey $publicKey, HashIdentifier $hashIdentifier){

        $name = HashIdentifier::getHashAlgorithmNameForOpenSSL($hashIdentifier->getAlgorithm());

        $publicKey = sprintf("-----BEGIN PUBLIC KEY-----\r\n%s\r\n-----END PUBLIC KEY-----\r\n", base64_encode($publicKey->getEncoded()));

        return openssl_verify($data, $signature, $publicKey, $name);
    }
}
