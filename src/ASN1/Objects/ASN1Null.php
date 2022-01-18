<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1Null extends ASN1Object
{
    /**
     * ASN1Null constructor.
     */
    public function __construct()
    {
        parent::__construct(DerTag::Null);
    }
    public function getContents(){
        return null;
    }

    public function getValue(){
        return null;
    }

    public function getEncoded()
    {
        return "\5\0";
    }

    public function __toString(){
        return '(Null)';
    }
}
