<?php


namespace Jazor\Security\EC;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class Pentanomial implements ASN1Encodable
{

    private $k1;
    private $k2;
    private $k3;
    public function __construct($k1, $k2, $k3)
    {
        $this->k1 = $k1;
        $this->k2 = $k2;
        $this->k3 = $k3;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer($this->k1);
        $gen->Integer($this->k2);
        $gen->Integer($this->k3);
        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $sequence){
        return new static($sequence[0]->getContents(), $sequence[1]->getContents(), $sequence[2]->getContents());
    }
}
