<?php

namespace Jazor\X509\X509Extensions\SubClasses;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class SMIMECapability implements \Jazor\ASN1\ASN1Encodable
{

    private string $capabilityID;
    private ?ASN1Encodable $parameters = null;

    public function __construct($capabilityID, ?ASN1Encodable $parameters)
    {
        $this->capabilityID = $capabilityID;
        $this->parameters = $parameters;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->ObjectIdentifier($this->capabilityID);
        if($this->parameters != null){
            $gen->Object($this->parameters);
        }
        return $gen->generate();
    }

    public function __toString()
    {
        $result = sprintf('CapabilityID = %s', $this->capabilityID);

        if($this->parameters != null) {
            $result .= sprintf("\r\nParameters\r\n%s", indent($this->parameters, 2));
        }
        return sprintf("SMIMECapability\r\n%s", indent($result, 2)) ;
    }

    /**
     * @return string
     */
    public function getCapabilityID(): string
    {
        return $this->capabilityID;
    }

    /**
     * @return ASN1Encodable|null
     */
    public function getParameters(): ?ASN1Encodable
    {
        return $this->parameters;
    }

    public static function getInstance(ASN1Sequence $seq){
        return new static($seq[0]->getValue(), isset($seq[1]) ? $seq[1] : null);
    }
}