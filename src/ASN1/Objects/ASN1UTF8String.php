<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1UTF8String extends ASN1String
{
    /**
     * ASN1UTF8String constructor.
     * @param string $contents
     */
    public function __construct($contents = '')
    {
        parent::__construct(DerTag::UTF8String, $contents);
    }

    public function __toString(){
        return '(UTF8String)' . $this->getContents();
    }
}
