<?php

namespace Jazor\X509\X501Attributes;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;

abstract class X501Attribute implements ASN1Encodable
{

    private string $type;

    private array $values;

    public function __construct(string $type)
    {
        $this->type = $type;
        $this->values = [];
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return array
     */
    public function getValues(): array
    {
        return $this->values;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->ObjectIdentifier($this->type);

        foreach ($this->values as $value) {
            $gen->Set()->Object($value);
        }
        return $gen->generate();
    }


    public function addValue($value){
        array_push($this->values, $value);
    }
    public abstract function __toString();
}
