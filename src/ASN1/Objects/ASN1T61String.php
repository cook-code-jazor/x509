<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1T61String extends ASN1String
{
    /**
     * ASN1T61String constructor.
     * @param string $contents
     */
    public function __construct($contents = '')
    {
        parent::__construct(DerTag::T61String, $contents);
    }

    public function __toString(){
        return '(T61String)' . $this->getContents();
    }
}
