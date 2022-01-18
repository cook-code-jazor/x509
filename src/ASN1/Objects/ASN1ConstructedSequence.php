<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1ConstructedSequence extends ASN1Sequence
{

    public function __construct()
    {
        parent::__construct(DerTag::Sequence | DerTag::ConstructedFlag);
    }
}