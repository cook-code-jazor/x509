<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1ConstructedContext extends ASN1Sequence
{

    public function __construct($flag = 0)
    {
        parent::__construct(DerTag::ContextSpecificTagFlag | DerTag::ConstructedFlag | $flag);
    }
}