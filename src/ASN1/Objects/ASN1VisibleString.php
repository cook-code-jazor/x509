<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1VisibleString extends ASN1String
{
    /**
     * ASN1VisibleString constructor.
     * @param string $contents
     */
    public function __construct($contents = '')
    {
        parent::__construct(DerTag::VisibleString, $contents);
    }

    public function __toString(){
        return '(VisibleString)' . $this->getContents();
    }
}
