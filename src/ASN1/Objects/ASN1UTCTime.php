<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1UTCTime extends ASN1DateTime
{
    /**
     * ASN1UTCTime constructor.
     * @param \DateTime|integer|string $contents
     */
    public function __construct($contents = null)
    {
        parent::__construct(DerTag::UTCTime, $contents);
    }

    public function __toString()
    {
        return '(UTCTime)'
            . $this->getDateTime()->format('Y-m-d H:i:s')
            . '(' . $this->getContents() . ')';
    }
}
