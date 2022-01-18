<?php


namespace Jazor\Security\EC;


use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Security\AlgorithmIdentifier;
use Jazor\Security\AsymmetricKey;

class ECPrivateKey extends AsymmetricKey
{

    private $q;

    private $curve;

    private $publicKey = null;

    /**
     * ECPublicKey constructor.
     * @param ECPublicKey $publicKey
     * @param $value
     * @throws \Exception
     */
    public function __construct($publicKey, $value)
    {
        $this->publicKey = $publicKey;
        $alg = $publicKey->getAlgorithm();
        parent::__construct($alg, $value);
        $this->curve = $publicKey->getCurve();
        $this->q = $value;
    }
    /**
     * @param mixed $value
     * @throws \Exception
     */
    public function setValue($value)
    {
        parent::setValue($value);
        $this->q = $value;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer("\x01");
        $gen->OctetString($this->q);
        $gen->ConstructedContext(0, function (ASN1SequenceGenerator $gen){
            $gen->ObjectIdentifier($this->curve);
        });
        $gen->ConstructedContext(1, function (ASN1SequenceGenerator $gen){
            $gen->BitString($this->publicKey->getValue());
        });
        return $gen->generate();
    }

    /**
     * @return mixed
     */
    public function getCurve()
    {
        return $this->curve;
    }

    public function __toString()
    {
        return sprintf("Curve = %s\r\nQ = 0x%s", $this->curve, bin2hex($this->q));
    }

    /**
     * @return mixed
     */
    public function getQ()
    {
        return $this->q;
    }
}
