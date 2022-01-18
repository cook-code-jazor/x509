<?php

namespace Jazor\X509;

use Jazor\ASN1\ASN1Encodable;
use Jazor\Console;
use Jazor\NotSupportedException;
use Jazor\Security\AsymmetricKeyFactory;
use Jazor\ASN1\ASN1Reader;
use Jazor\Security\AsymmetricKeyPair;
use Jazor\Security\EC\ECPrivateKey;
use Jazor\Security\EC\ECPublicKey;
use Jazor\Security\RSA\RSAPrivateKey;
use Jazor\Security\RSA\RSAPublicKey;
use Jazor\UnexpectedException;

class PemReader
{
    /**
     * @param string $data
     * @param null $typeName
     * @param bool $throwWhenError
     * @return bool|false|string
     * @throws \Exception
     */
    public static function getPemContents(string $data, &$typeName, bool $throwWhenError = true){
        $typeName = '';
        $success = preg_match('/-----BEGIN (.+?)-----([\s\S]+?)-----END \1-----/', $data, $match );
        if(!$success) {
            if($throwWhenError) throw new \Exception('unknown pem file type');
            return $data;
        }
        $typeName = $match[1];
        return base64_decode($match[2]);
    }

    /**
     * @param string $file
     * @param null $typeName
     * @return mixed
     * @throws \Exception
     */
    public static function import(string $file, &$typeName = null){
        return self::importFromContents(file_get_contents($file), $typeName);
    }

    /**
     * @param string $contents
     * @param null $typeName
     * @return mixed
     * @throws \Exception
     */
    public static function importFromContents(string $contents, &$typeName = null){
        $contents = self::getPemContents($contents, $typeName);
        $sequence = ASN1Reader::read($contents);

        switch ($typeName){
            case 'PRIVATE KEY':
            case 'PUBLIC KEY':
            case 'RSA PRIVATE KEY':
            case 'EC PRIVATE KEY':
                return AsymmetricKeyFactory::getInstance($sequence, $typeName);
            case 'CERTIFICATE REQUEST':
                return CertificateRequest::getInstance($sequence);
            case 'CERTIFICATE':
                return X509CertificateV3::getInstance($sequence);
        }

        throw new \Exception('not support('. $typeName .')');
    }

    /**
     * @param ASN1Encodable $object
     * @param bool $exportPKCS8
     * @return string|void
     * @throws NotSupportedException
     */
    public static function export(ASN1Encodable $object, $exportPKCS8 = false){
        if($object instanceof AsymmetricKeyPair){
            if($exportPKCS8 === true){
                return sprintf("-----BEGIN PRIVATE KEY-----\r\n%s\r\n-----END PRIVATE KEY-----\r\n", base64_encode_chunked($object->getPKCS8Encoded()));
            }
            $object = $object->getPrivateKey();
        }
        if($object instanceof ECPrivateKey || $object instanceof RSAPrivateKey){
            $name = ($object instanceof ECPrivateKey) ? 'EC' : 'RSA';
            return sprintf("-----BEGIN %s PRIVATE KEY-----\r\n%s\r\n-----END %s PRIVATE KEY-----\r\n", $name, base64_encode_chunked($object->getEncoded()), $name);
        }
        if($object instanceof RSAPublicKey || $object instanceof ECPublicKey){
            return sprintf("-----BEGIN PUBLIC KEY-----\r\n%s\r\n-----END PUBLIC KEY-----\r\n", base64_encode_chunked($object->getEncoded()));
        }
        if($object instanceof CertificateRequest){
            return sprintf("-----BEGIN CERTIFICATE REQUEST-----\r\n%s\r\n-----END CERTIFICATE REQUEST-----\r\n", base64_encode_chunked($object->getEncoded()));
        }
        if($object instanceof X509CertificateV3){
            return sprintf("-----BEGIN CERTIFICATE-----\r\n%s\r\n-----END CERTIFICATE-----\r\n", base64_encode_chunked($object->getEncoded()));
        }

        throw new NotSupportedException('not supported(' . get_class($object) . ')');
    }

}
