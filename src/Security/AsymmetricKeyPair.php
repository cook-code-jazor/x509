<?php


namespace Jazor\Security;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;

class AsymmetricKeyPair implements ASN1Encodable
{
    private AsymmetricKey $privateKey;
    private AsymmetricKey $publicKey;

    /**
     * AsymmetricKey constructor.
     * @param AsymmetricKey $privateKey
     * @param AsymmetricKey $publicKey
     */
    public function __construct(AsymmetricKey $privateKey, AsymmetricKey $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * @return AsymmetricKey
     */
    public function getPrivateKey(): AsymmetricKey
    {
        return $this->privateKey;
    }

    public function getEncoded()
    {
        return $this->privateKey->getEncoded();
    }

    public function getPKCS8Encoded(){

        $gen = ASN1SequenceGenerator::create();
        $gen->Integer("\x00");
        $gen->Raw($this->publicKey->getAlgorithm()->getEncoded());
        $gen->OctetString($this->privateKey->getEncoded());
        return $gen->generate();

    }

    /**
     * @return AsymmetricKey
     */
    public function getPublicKey(): AsymmetricKey
    {
        return $this->publicKey;
    }

    public function __toString()
    {
        return sprintf(
            "(AsymmetricKeyPair)\r\n%s\r\n%s",
            preg_replace('/^/m', '  ', $this->privateKey),
            preg_replace('/^/m', '  ', $this->publicKey));
    }

}
