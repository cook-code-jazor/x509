<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1NumericString extends ASN1String
{
    /**
     * ASN1NumericString constructor.
     * @param string $contents
     */
    public function __construct(string $contents = '')
    {
        parent::__construct(DerTag::NumericString, $contents);
    }

    public function __toString(){
        return '(NumericString)' . $this->getContents();
    }
}
