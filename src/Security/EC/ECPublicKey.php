<?php


namespace Jazor\Security\EC;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Security\AlgorithmIdentifier;
use Jazor\Security\AsymmetricKey;
use Jazor\Security\AsymmetricKeyIdentifier;

class ECPublicKey extends AsymmetricKey
{

    private $x;
    private $y;

    private $curve;

    /**
     * ECPublicKey constructor.
     * @param ECKeyIdentifier $algorithm
     * @param $value
     * @throws \Exception
     */
    public function __construct(ECKeyIdentifier $algorithm, $value)
    {
        parent::__construct($algorithm, $value);
        $this->curve = $algorithm->getCurve();
        $this->parsePublicKey();
    }

    /**
     * @return mixed
     */
    public function getX()
    {
        return $this->x;
    }

    /**
     * @return mixed
     */
    public function getY()
    {
        return $this->y;
    }

    /**
     * @throws \Exception
     */
    private function parsePublicKey(){
        $value = $this->getValue();
        if($value == null) return;
        $isCompressed = ord($value[0]) !== 0x04;
        if(!$isCompressed) {
            $length = (strlen($value) - 1) / 2;
            $this->x = substr($value, 1, $length);
            $this->y = substr($value, $length + 1, $length);
        }
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $alg = $this->getAlgorithm();
        $gen = ASN1SequenceGenerator::create();
        $gen->Sequence(function (ASN1SequenceGenerator $seq) use ($alg){
            $seq->ObjectIdentifier($alg->getAlgorithm());
            $seq->ObjectIdentifier($this->curve);
        });
        $gen->BitString($this->getValue());
        return $gen->generate();
    }

    /**
     * @param mixed $value
     * @throws \Exception
     */
    public function setValue($value)
    {
        parent::setValue($value);
        $this->parsePublicKey();
    }

    public function getPublicKeyValue(){
        return $this->getValue();
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
        return sprintf("Curve = %s\r\nX = 0x%s\r\nY = 0x%s", $this->curve, bin2hex($this->x), bin2hex($this->y));
    }
}
