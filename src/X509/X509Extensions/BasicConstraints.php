<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Console;

class BasicConstraints implements ASN1Encodable
{
    private bool $ca;
    private ?int $pathLenConstraint = null;
    public function __construct(bool $ca, ?int $pathLenConstraint)
    {
        $this->ca = $ca;
        $this->pathLenConstraint = $pathLenConstraint;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        if($this->ca){
            $gen->Boolean(true);
            if($this->pathLenConstraint !== null){
                $gen->Integer($this->pathLenConstraint);
            }
        }
        return $gen->generate();
    }

    public function __toString()
    {
        return sprintf("Subject Type=%s\r\nPath Length Constraint=%s", $this->ca ? 'CA' : 'End Entity', $this->pathLenConstraint === null ? 'None' : $this->pathLenConstraint);
    }

    public static function getInstance($binary){
        $seq = ASN1Reader::read($binary);

        return new static(isset($seq[0]) ? $seq[0]->getValue() : false, isset($seq[1]) ? $seq[1]->getInteger() : null);
    }

    /**
     * @return string|null
     */
    public function getPathLenConstraint(): ?string
    {
        return $this->pathLenConstraint;
    }

    /**
     * @return bool
     */
    public function isCa(): bool
    {
        return $this->ca;
    }
}
