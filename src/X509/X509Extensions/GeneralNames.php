<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\DerTag;
use Jazor\ASN1\Objects\ASN1Context;
use Jazor\ASN1\Objects\ASN1IA5String;
use Jazor\ASN1\Objects\ASN1ObjectIdentifier;
use Jazor\ASN1\Objects\ASN1OctetString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\NotImplementedException;
use Jazor\NotSupportedException;
use Jazor\X509\X509Name;

class GeneralNames implements ASN1Encodable
{
    private array $names = [];
    public function __construct(?array $names = null)
    {
        if($names != null) $this->names = $names;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        /**
         * @var GeneralName $name
         */
        foreach ($this->names as $name){
            $gen->Object($name);
        }
        return $gen->generate();
    }

    public function __toString()
    {
        $result = '';
        /**
         * @var GeneralName $name
         */
        $index = 0;
        foreach ($this->names as $name){
            $result .= (string)$name . "\r\n";
        }
        return rtrim($result);
    }

    public static function getInstance(ASN1Sequence $seq){
        $names = [];

        $elements = $seq->getElements();

        foreach ($elements as $element){
            $names[] = GeneralName::getInstance($element);
        }

        return new static($names);
    }

}
