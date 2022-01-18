<?php


namespace Jazor\Security\EC;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class ECCurve implements ASN1Encodable
{
    private $a;
    private $b;
    private $seed;
    public function __construct($a, $b, $seed)
    {
        $this->a = $a;
        $this->b = $b;
        $this->seed = $seed;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        $gen->OctetString($this->a);
        $gen->OctetString($this->b);
        if($this->seed != null) $gen->BitString($this->seed);

        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $sequence){
        return new ECCurve(
            $sequence[0]->getContents(),
            $sequence[1]->getContents(),
            isset($sequence[2]) ? $sequence[2]->getContents() : null
        );
    }

    /**
     * @return mixed
     */
    public function getA()
    {
        return $this->a;
    }

    /**
     * @return mixed
     */
    public function getB()
    {
        return $this->b;
    }

    /**
     * @return mixed
     */
    public function getSeed()
    {
        return $this->seed;
    }
}
