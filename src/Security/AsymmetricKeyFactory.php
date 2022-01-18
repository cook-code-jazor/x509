<?php


namespace Jazor\Security;


use Jazor\Console;
use Jazor\NotImplementedException;
use Jazor\NotSupportedException;
use Jazor\Security\EC\ECKeyIdentifier;
use Jazor\Security\EC\ECPrivateKey;
use Jazor\Security\EC\ECPublicKey;
use Jazor\Security\RSA\RSAKeyIdentifier;
use Jazor\Security\RSA\RSAPrivateKey;
use Jazor\Security\RSA\RSAPublicKey;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\Objects\ASN1Sequence;

class AsymmetricKeyFactory
{
    /**
     * @param ASN1Sequence $sequence
     * @param string $typeName
     * @return AsymmetricKey|AsymmetricKeyPair|ECPublicKey|RSAPublicKey
     * @throws \Exception
     */
    public static function getInstance(ASN1Sequence $sequence, string $typeName ){
        switch ($typeName){
            case 'PRIVATE KEY':
                return self::getPrivateKeyInPKcs8($sequence);
            case 'PUBLIC KEY':
                return self::getPublicKey($sequence);
            case 'RSA PRIVATE KEY':
                $algorithm = new RSAKeyIdentifier(AsymmetricKeyIdentifier::RsaEncryption);
                return self::getPrivateKey($algorithm, $sequence);
            case 'EC PRIVATE KEY':
                $algorithm = new ECKeyIdentifier(AsymmetricKeyIdentifier::IdECPublicKey, $sequence[2][0]->getValue());

                return self::getPrivateKey($algorithm, $sequence);
        }

        throw new \Exception('not support('. $typeName .')');
    }

    /**
     * @param ASN1Sequence $sequence
     * @return AsymmetricKey
     * @throws \Exception
     */
    public static function getPublicKey(ASN1Sequence $sequence){
        $algorithm  = AsymmetricKeyIdentifier::getInstance($sequence[0]);

        if($algorithm instanceof RSAKeyIdentifier){
            $keyDataSequence = ASN1Reader::read($sequence[1]->getContents());
            return new RSAPublicKey($algorithm,
                $keyDataSequence[1]->getInteger() ?? null,
                $keyDataSequence[0]->getContents() ?? null
            );
        }
        if($algorithm instanceof  ECKeyIdentifier) {
            return new ECPublicKey($algorithm, $sequence[1]->getContents());
        }
        throw new NotSupportedException('unknown algorithm: ' . $algorithm->getAlgorithm());

    }

    /**
     * @param ASN1Sequence $sequence
     * @return AsymmetricKeyPair
     * @throws \Exception
     */
    public static function getPrivateKeyInPKcs8(ASN1Sequence $sequence){
        $algorithm  = AsymmetricKeyIdentifier::getInstance($sequence[1]);

        $keyDataSequence = ASN1Reader::read($sequence[2]->getContents());

        return self::getPrivateKey($algorithm, $keyDataSequence);
    }

    /**
     * @param AsymmetricKeyIdentifier $algorithm
     * @param ASN1Sequence $sequence
     * @return AsymmetricKeyPair
     * @throws \Exception
     */
    private static function getPrivateKey(AsymmetricKeyIdentifier $algorithm, ASN1Sequence $sequence){
        if($algorithm instanceof RSAKeyIdentifier){

            $publicKey = new RSAPublicKey($algorithm,
                $sequence[2]->getInteger() ?? null,
                $sequence[1]->getContents() ?? null
            );

            $privateKey= new RSAPrivateKey($algorithm, $publicKey,
                $sequence[3]->getContents() ?? null,
                $sequence[4]->getContents() ?? null,
                $sequence[5]->getContents() ?? null,
                $sequence[6]->getContents() ?? null,
                $sequence[7]->getContents() ?? null,
                $sequence[8]->getContents() ?? null,
            );
            return new AsymmetricKeyPair($privateKey, $publicKey);
        }
        if($algorithm instanceof ECKeyIdentifier){
            $publicKey = new ECPublicKey($algorithm, $sequence[3][0]->getContents());
            $privateKey = new ECPrivateKey($publicKey, $sequence[1]->getContents());
            return new AsymmetricKeyPair($privateKey, $publicKey);
        }
        throw new NotImplementedException('unknown algorithm: ' . $algorithm->getAlgorithm());
    }
}
