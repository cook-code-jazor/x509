<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;
use Jazor\Console;

class ASN1BitString extends ASN1String
{
    private int $padding = 0;
    public function __construct(string $contents = '', int $padding = 0)
    {
        $this->padding = $padding;
        parent::__construct(DerTag::BitString, $contents);
    }

    public function getEncoded()
    {
        return parent::encodeContents(chr($this->padding) . $this->getContents());
    }

    /**
     * @return int
     */
    public function getPadding(): int
    {
        return $this->padding;
    }
}
