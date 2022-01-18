<?php

namespace Jazor\X509\X501Attributes;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1ConstructedContext;
use Jazor\ASN1\Objects\ASN1Sequence;

class X501Attributes implements ASN1Encodable
{
    private array $attributes;

    public function __construct(array $attributes)
    {
        $this->attributes = $attributes;
    }

    public function __toString()
    {
        $result = '';
        $idx = 0;
        foreach ($this->attributes as $attribute){
            $result .= '[' . $idx++ . "]Attribute\r\n" . indent($attribute, 2) . "\r\n";
        }
        return rtrim($result);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create(new ASN1ConstructedContext(0));
        foreach ($this->attributes as $attr){
            $gen->Object($attr);
        }
        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){

        $attributes = [];
        /**
         * @var ASN1Sequence $element
         */
        foreach ($seq->getElements() as $element){

            $attributeType = $element[0]->getValue();

            $attribute = null;
            switch ($attributeType){
                case '1.2.840.113549.1.9.14':
                    $attribute = Pkcs9ExtensionRequest::getInstance($element);
                    break;
                default:
                    $attribute = $element;
            }
            if($attribute !=null) $attributes[] = $attribute;
        }
        return new static($attributes);
    }
}
