<?php


namespace Jazor\Security\DSA;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class DSADomainParameters implements ASN1Encodable
{

    private $p;
    private $q;
    private $g;

    public function __construct($p, $q, $g)
    {
        $this->p = $p;
        $this->q = $q;
        $this->g = $g;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer($this->p);
        $gen->Integer($this->q);
        $gen->Integer($this->g);
        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){
        return new static($seq[0]->getContents(), $seq[1]->getContents(), $seq[2]->getContents());
    }

    /**
     * @return mixed
     */
    public function getP()
    {
        return $this->p;
    }

    /**
     * @return mixed
     */
    public function getQ()
    {
        return $this->q;
    }

    /**
     * @return mixed
     */
    public function getG()
    {
        return $this->g;
    }
}
