<?php

namespace Jazor\Security;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\Objects\ASN1Null;
use Jazor\ASN1\Objects\ASN1ObjectIdentifier;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\NotImplementedException;
use Jazor\Security\DH\DHDomainParameters;
use Jazor\Security\DH\DHKeyIdentifier;
use Jazor\Security\DSA\DSADomainParameters;
use Jazor\Security\DSA\DSAKeyIdentifier;
use Jazor\Security\EC\ECKeyIdentifier;
use Jazor\Security\EC\ECParameters;
use Jazor\Security\RSA\RSAKeyIdentifier;

/**
 * @link https://www.ietf.org/rfc/rfc2459.txt
 * @link https://www.rfc-editor.org/rfc/rfc3279#page-7
 * @link https://www.rfc-editor.org/rfc/inline-errata/rfc5280.html
 */
abstract class AsymmetricKeyIdentifier implements ASN1Encodable
{

    /*ECDSA/ECDH*/
    const IdECPublicKey             = '1.2.840.10045.2.1';
    /*RSA*/
    const RsaEncryption             = '1.2.840.113549.1.1.1';
    const md5WithRSAEncryption      = '1.2.840.113549.1.1.4';
    const sha1WithRSAEncryption     = '1.2.840.113549.1.1.5';
    const IdRsaesOaep               = '1.2.840.113549.1.1.7';
    const IdRsassaPss               = '1.2.840.113549.1.1.10';
    const sha256WithRSAEncryption   = '1.2.840.113549.1.1.11';

    /*DSA*/
    const IdDSA                     = '1.2.840.10040.4.1';
    /*DH*/
    const DH                     = '1.2.840.10046.2.1';
    /*KEA*/
    const KEA                     = '2.16.840.1.101.2.1.1.22';

    private string $algorithm;

    /**
     * @param string $algorithm
     */
    public function __construct(string $algorithm)
    {
        $this->algorithm = $algorithm;
    }

    public static function getInstance(ASN1Sequence $seq){
        $oid = $seq[0]->getValue();

        $parameters = isset($seq[1]) ? $seq[1] : null;

        if(strpos($oid, '1.2.840.113549.1.1.') !== false) return new RSAKeyIdentifier($oid);

        if($oid == self::IdECPublicKey){

            if($parameters instanceof ASN1Null) return new ECKeyIdentifier($oid, null);
            if($parameters instanceof ASN1ObjectIdentifier) return new ECKeyIdentifier($oid, $parameters->getValue());
            if($parameters instanceof ASN1Sequence) return new ECKeyIdentifier($oid, ECParameters::getInstance($parameters));
        }

        if($oid == self::IdDSA){
            return new DSAKeyIdentifier($oid, DSADomainParameters::getInstance($parameters));
        }
        if($oid == self::DH){
            return new DHKeyIdentifier($oid, DHDomainParameters::getInstance($seq[1]));
        }
        throw new NotImplementedException('OID('. $oid .')');
    }

    /**
     * @return mixed
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }
}
