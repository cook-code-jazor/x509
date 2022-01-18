<?php


namespace Jazor\Security;

use Jazor\ASN1\ASN1Encodable;

abstract class AsymmetricKey implements ASN1Encodable
{
    private AsymmetricKeyIdentifier $algorithm;
    private $value;

    /**
     * AsymmetricKey constructor.
     * @param AsymmetricKeyIdentifier $algorithm
     * @param $value
     */
    public function __construct(AsymmetricKeyIdentifier $algorithm, $value)
    {
        $this->algorithm = $algorithm;
        $this->value = $value;
    }

    public function getValue(){
        return $this->value;
    }
    /**
     * @return AsymmetricKeyIdentifier
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * @param mixed $value
     */
    public function setValue($value)
    {
        $this->value = $value;
    }

    public abstract function __toString();
    /**
     * @return string
     */
    public abstract function getEncoded();
}
