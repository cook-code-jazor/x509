<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1Set extends ASN1Sequence
{

    public function __construct(array $elements = null)
    {
        parent::__construct(DerTag::ConstructedSet);
        if ($elements != null) {
            $this->addElements($elements);
        }
    }
}