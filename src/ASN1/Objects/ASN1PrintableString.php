<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1PrintableString extends ASN1String
{
    /**
     * ASN1PrintableString constructor.
     * @param string $contents
     */
    public function __construct($contents = '')
    {
        parent::__construct(DerTag::PrintableString, $contents);
    }

    public function __toString(){
        return '(PrintableString)' . $this->getContents();
    }
}
