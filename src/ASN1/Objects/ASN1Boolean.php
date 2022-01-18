<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1Boolean extends ASN1Object
{
    private bool $value;
    public function __construct(bool $value)
    {
        parent::__construct(DerTag::Boolean);
        $this->value = $value;
    }

    /**
     * @return bool
     */
    public function getValue()
    {
        return $this->value;
    }
    public function getEncoded()
    {
        return parent::encodeHeader(1) . chr($this->value ? 255 : 0);
    }

    public function __toString()
    {
        return '(Boolean)' . ($this->value ? 'true' : 'false');
    }
}
