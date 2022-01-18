<?php


namespace Jazor\Security\DH;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;

class DHValidationParameters implements ASN1Encodable
{

    private $seed;
    private $pgenCounter;
    public function __construct($seed, $pgenCounter)
    {
        $this->seed = $seed;
        $this->pgenCounter = $pgenCounter;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->BitString($this->seed);
        $gen->Integer($this->pgenCounter);

        return $gen->generate();
    }

    /**
     * @return mixed
     */
    public function getSeed()
    {
        return $this->seed;
    }

    /**
     * @return mixed
     */
    public function getPgenCounter()
    {
        return $this->pgenCounter;
    }
}
