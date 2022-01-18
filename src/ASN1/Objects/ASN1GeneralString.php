<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1GeneralString extends ASN1String
{
    /**
     * ASN1GeneralString constructor.
     * @param string $contents
     */
    public function __construct($contents = '')
    {
        parent::__construct(DerTag::GeneralString, $contents);
    }

    public function __toString(){
        return '(GeneralString)' . $this->getContents();
    }
}
