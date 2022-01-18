<?php


namespace Jazor\Security\DH;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class DHDomainParameters implements ASN1Encodable
{
    private $p;
    private $q;
    private $g;
    private $j;
    private ?DHValidationParameters $validationParameters;

    public function __construct($p, $g, $q, $j, ?DHValidationParameters $validationParameters = null)
    {
        $this->p = $p;
        $this->q = $q;
        $this->g = $g;
        $this->j = $j;
        $this->validationParameters = $validationParameters;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer($this->p);
        $gen->Integer($this->g);
        $gen->Integer($this->q);
        if($this->j != null){
            $gen->Integer($this->j);
        }
        if($this->validationParameters != null){
            $gen->Object($this->validationParameters);
        }

        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){
        return new DHDomainParameters(
            $seq[0]->getContents(),
            $seq[1]->getContents(),
            $seq[2]->getContents(),
            isset($seq[3]) ? $seq[3]->getContents() : null,
            isset($seq[4]) ? new DHValidationParameters($seq[4][0]->getContents(), $seq[4][1]->getContents()) : null
        );
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

    /**
     * @return mixed
     */
    public function getJ()
    {
        return $this->j;
    }

    /**
     * @return DHValidationParameters|null
     */
    public function getValidationParameters(): ?DHValidationParameters
    {
        return $this->validationParameters;
    }
}
