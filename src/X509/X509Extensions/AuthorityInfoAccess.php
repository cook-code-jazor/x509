<?php

namespace Jazor\X509\X509Extensions;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class AuthorityInfoAccess implements ASN1Encodable
{

    private array $authorityInfoAccessSyntax;
    public function __construct(array $authorityInfoAccessSyntax){
        $this->authorityInfoAccessSyntax = $authorityInfoAccessSyntax;
    }

    /**
     * @return array
     */
    public function getAuthorityInfoAccessSyntax(): array
    {
        return $this->authorityInfoAccessSyntax;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        foreach ($this->authorityInfoAccessSyntax as $accessSyntax){
            $gen->Object($accessSyntax);
        }

        return $gen->generate();
    }

    public function __toString()
    {
        $result = '';
        $idx = 0;
        foreach ($this->authorityInfoAccessSyntax as $accessSyntax){
            $result .= sprintf("AccessDescription[%s]\r\n", $idx++);
            $result .= indent($accessSyntax, 2) . "\r\n";
        }
        return rtrim($result);
    }

    public static function getInstance($binary){
        $asn1 = ASN1Reader::read($binary);
        if(!($asn1 instanceof ASN1Sequence)) throw new \Exception('expect \'ASN1Sequence\'');
        $authorityInfoAccessSyntax = [];

        foreach ($asn1->getElements() as $element){
            $authorityInfoAccessSyntax[] = AccessDescription::getInstance($element);
        }

        return new static($authorityInfoAccessSyntax);
    }


}
