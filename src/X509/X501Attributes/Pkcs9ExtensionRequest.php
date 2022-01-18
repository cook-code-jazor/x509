<?php

namespace Jazor\X509\X501Attributes;

use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\X509\ExtensionReqs\SubjectAltName;
use Jazor\X509\X509Extension;
use Jazor\X509\X509Extensions;

class Pkcs9ExtensionRequest extends X501Attribute
{
    const OID = '1.2.840.113549.1.9.14';

    /**
     * @param string $type
     * @throws \Exception
     */
    public function __construct(string $type)
    {
        if($type != self::OID) throw new \Exception('oid not match, expect: ' . self::OID);
        parent::__construct($type);
    }

    public function __toString()
    {
        $values = $this->getValues();
        $result = sprintf("Type = %s(Pkcs9ExtensionRequest)\r\nValues\r\n", $this->getType());
        $idx = 0;
        foreach ($values as $value){
            $result .= "  [" . ($idx++) . "]Value\r\n";
            $result .= indent($value, 4);
        }
        return rtrim($result);
    }

    public static function getInstance(ASN1Sequence $seq){
        $attributeType = $seq[0]->getValue();
        $elements = $seq->getElements();

        $instance = new static($attributeType);
        /**
         * @var ASN1Sequence $element
         */

        for($i = 1; $i < count($elements); $i++){

            /**
             * SET
             */
            $element = $elements[$i];

            $instance->addValue(X509Extensions::getInstance($element[0]));
        }
        return $instance;
    }
}
