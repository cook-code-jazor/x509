<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1IA5String extends ASN1String
{
    /**
     * ASN1IA5String constructor.
     * @param string $contents
     */
    public function __construct($contents = '')
    {
        parent::__construct(DerTag::IA5String, $contents);
    }

    public function __toString(){
        return '(IA5String)' . $this->getContents();
    }
}
