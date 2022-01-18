<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\DerTag;
use Jazor\ASN1\Objects\ASN1Context;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\X509\X509Name;

class SubjectAlternativeName implements ASN1Encodable
{
    private array $names = [];

    public function __construct()
    {
    }

    public function addName(GeneralName $name)
    {
        $this->names[] = $name;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        /**
         * @var GeneralName $name
         */
        foreach ($this->names as $name) {
            $value = $name->getEncoded();
            $gen->Raw($value);
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
        foreach ($this->names as $name) {
            $result .= '[' . $index++ . ']'. $name . "\r\n";
        }
        return rtrim($result);
    }

    public static function getInstance($binary)
    {
        $seq = ASN1Reader::read($binary);
        if (!($seq instanceof ASN1Sequence)) throw new \Exception('expect \'ASN1Sequence\'');

        $ins = new static();
        $elements = $seq->getElements();

        foreach ($elements as $element) {
            $ins->names[] = GeneralName::getInstance($element);
        }
        return $ins;
    }
}
