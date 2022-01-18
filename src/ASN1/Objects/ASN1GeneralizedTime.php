<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1GeneralizedTime extends ASN1DateTime
{
    /**
     * ASN1GeneralizedTime constructor.
     * @param \DateTime|integer|string $contents
     */
    public function __construct($contents = null)
    {
        parent::__construct(DerTag::GeneralizedTime, $contents, 'YmdHis');
    }

    public function __toString()
    {
        return '(GeneralizedTime)'
            . $this->getDateTime()->format('Y-m-d H:i:s')
            . '(' . $this->getContents() . ')';
    }
}
