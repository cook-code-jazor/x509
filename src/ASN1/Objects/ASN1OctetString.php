<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1OctetString extends ASN1String
{
    /**
     * ASN1OctetString constructor.
     * @param string $contents
     */
    public function __construct($contents = '')
    {
        parent::__construct(DerTag::OctetString, $contents);
    }
}
