<?php


namespace Jazor\Security;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\UnexpectedException;

class HashIdentifier implements ASN1Encodable
{
    private static $algs = [
        '1.2.840.113549.2.2' => 'MD2', /*X509*/
        '1.2.840.113549.2.3' => 'MD4',
        '1.2.840.113549.2.5' => 'MD5', /*X509*/
        '1.3.14.3.2.26' => 'SHA1', /*X509*/

        '1.2.840.113549.1.1.11' => 'sha256WithRSAEncryption',  /*X509*/
        '1.2.840.113549.1.1.5' => 'sha1WithRSAEncryption',  /*X509*/
        '1.2.840.113549.1.1.4' => 'md5WithRSAEncryption',  /*X509*/
        '1.2.840.113549.1.1.2' => 'md2WithRSAEncryption',  /*X509*/

        '2.16.840.1.101.3.4.2.4' => 'SHA224',
        '2.16.840.1.101.3.4.2.3' => 'SHA512',
        '2.16.840.1.101.3.4.2.2' => 'SHA384',
        '2.16.840.1.101.3.4.2.1' => 'SHA256',
        '1.3.36.3.2.1' => 'RIPEMD160',
        '1.3.36.3.2.2' => 'RIPEMD128',
        '1.3.36.3.2.3' => 'RIPEMD256',
        '1.2.643.2.2.9' => 'GOST3411',
        '1.2.840.10045.4.1' => 'Sha1WithECDsa',
        '1.2.840.10045.4.3.1' => 'Sha224WithECDsa',
        '1.2.840.10045.4.3.2' => 'Sha256WithECDsa',
        '1.2.840.10045.4.3.3' => 'Sha384WithECDsa',
        '1.2.840.10045.4.3.4' => 'Sha512WithECDsa',

        '1.2.840.10040.4.3' => 'id-dsa-with-sha1',
    ];

    public static function getHashAlgorithmName($oid){
        return self::$algs[$oid] ?? $oid;
    }
    public static function getHashAlgorithmNameForOpenSSL($oid){

        if(!isset(self::$algs[$oid])) return $oid;

        $name = self::$algs[$oid];
        $idx = strpos(strtolower($name), 'withecdsa');
        if($idx !== false) return substr($name, 0, $idx);

        return $name;
    }

    private $algorithm;
    private $params = null;
    public function __construct($algorithm, $params = null){
        $this->algorithm = $algorithm;
        $this->params = $params;
    }

    public function __toString()
    {
        return sprintf("Algorithm=%s\r\nParameters\r\n%s", $this->algorithm, $this->params == null ? 'null' : indent($this->params, 2));
    }

    /**
     * @return mixed
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    public static function getInstance(ASN1Sequence $seq){

        return new HashIdentifier($seq[0]->getValue(), isset($seq[1]) ? $seq[1] : null);
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        $gen->ObjectIdentifier($this->algorithm);

        if($this->params !== null){
            $gen->Object($this->params);
        }

        return $gen->generate();
    }

    /**
     * @return mixed|null
     */
    public function getParams()
    {
        return $this->params;
    }
}
