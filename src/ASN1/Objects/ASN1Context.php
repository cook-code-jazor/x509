<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1Context extends ASN1String
{
    private int $flag;

    /**
     * @param int $flag
     * @param string $contents
     */
    public function __construct(int $flag = 0, $contents = '')
    {
        $this->flag = $flag;
        parent::__construct(DerTag::ContextSpecificTagFlag | $flag, $contents);
    }

    public function __toString()
    {
        return '(Context[' . $this->flag . '])0x' . bin2hex($this->getContents());
    }
}
