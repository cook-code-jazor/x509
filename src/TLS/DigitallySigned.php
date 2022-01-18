<?php


namespace Jazor\TLS;


class DigitallySigned
{

    const HASH_NONE = 0;
    const HASH_MD5 = 1;
    const HASH_SHA1 = 2;
    const HASH_SHA224 = 3;
    const HASH_SHA256 = 4;
    const HASH_SHA384 = 5;
    const HASH_SHA512 = 6;
    const HASH_UNKNOWN = 255;

    const SIGNATURE_ANONYMOUS = 0;
    const SIGNATURE_RSA = 1;
    const SIGNATURE_DSA = 2;
    const SIGNATURE_ECDSA = 3;
    const SIGNATURE_UNKNOWN = 255;

    private int $hashAlgorithm;
    private int $signatureAlgorithm;
    private string $signature;

    private static array $NamedHashAlgorithm = [
        self::HASH_NONE => 'None',
        self::HASH_MD5 => 'MD5',
        self::HASH_SHA1 => 'SHA1',
        self::HASH_SHA224 => 'SHA224',
        self::HASH_SHA256 => 'SHA256',
        self::HASH_SHA384 => 'SHA384',
        self::HASH_SHA512 => 'SHA512',
        self::HASH_UNKNOWN => 'UNKNOWN',
    ];
    private static array $NamedSignatureAlgorithm = [
        self::SIGNATURE_ANONYMOUS => 'ANONYMOUS',
        self::SIGNATURE_RSA => 'RSA',
        self::SIGNATURE_DSA => 'DSA',
        self::SIGNATURE_ECDSA => 'ECDSA',
        self::SIGNATURE_UNKNOWN => 'UNKNOWN',
    ];

    public function __toString()
    {
        return sprintf("HashAlgorithm = %s\r\nSignatureAlgorithm = %s\r\nSignature = %s",
            self::$NamedHashAlgorithm[$this->hashAlgorithm],
            self::$NamedSignatureAlgorithm[$this->signatureAlgorithm],
            bin2hex($this->signature),
        );
    }


    public function getEncoded(){
        $result = chr($this->hashAlgorithm);
        $result .= chr($this->signatureAlgorithm);


        $len = strlen($this->signature);

        $lenBytes = chr($len >> 8) . chr($len & 0xff);

        $result .= $lenBytes;
        $result .= $this->signature;

        return $result;
    }
    /**
     * @return mixed
     */
    public function getHashAlgorithm()
    {
        return $this->hashAlgorithm;
    }

    /**
     * @param mixed $hashAlgorithm
     */
    public function setHashAlgorithm($hashAlgorithm): void
    {
        $this->hashAlgorithm = $hashAlgorithm;
    }

    /**
     * @return mixed
     */
    public function getSignatureAlgorithm()
    {
        return $this->signatureAlgorithm;
    }

    /**
     * @param mixed $signatureAlgorithm
     */
    public function setSignatureAlgorithm($signatureAlgorithm): void
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
    }

    /**
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @param string $signature
     */
    public function setSignature(string $signature): void
    {
        $this->signature = $signature;
    }
}
