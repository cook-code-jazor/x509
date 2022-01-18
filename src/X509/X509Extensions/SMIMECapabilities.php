<?php

namespace Jazor\X509\X509Extensions;

use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1OctetString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\UnexpectedException;
use Jazor\X509\X509Extensions\SubClasses\SMIMECapability;

class SMIMECapabilities implements \Jazor\ASN1\ASN1Encodable
{

    private array $sMIMECapabilities = [];

    public function __construct($sMIMECapabilities)
    {
        $this->sMIMECapabilities = $sMIMECapabilities;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        foreach ($this->sMIMECapabilities as $capability){
            $gen->Object($capability);
        }
        return $gen->generate();
    }

    public function __toString()
    {
        $result = '';

        $idx = 0;
        foreach ($this->sMIMECapabilities as $capability){
            $result .= '[' . $idx++ . ']' . $capability . "\r\n";
        }
        return rtrim($result);
    }

    public static function getInstance($binary){
        $asn1 = ASN1Reader::read($binary);
        if(!($asn1 instanceof ASN1Sequence)) throw new UnexpectedException('expect \'ASN1Sequence\'');

        return new static($asn1->getChildren(SMIMECapability::class));
    }

    /**
     * @return array
     */
    public function getSMIMECapabilities(): array
    {
        return $this->sMIMECapabilities;
    }
}
