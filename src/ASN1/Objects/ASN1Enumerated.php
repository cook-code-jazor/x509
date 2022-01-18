<?php


namespace Jazor\ASN1\Objects;


class ASN1Enumerated extends ASN1Integer
{

    public function __construct($value)
    {
        parent::__construct($value);
    }
    public function getTag()
    {
        return 0x0a;
    }
    public function getEncoded()
    {
        $data = parent::getEncoded();
        $data[0] = chr($this->getTag());
        return $data;
    }
    public function __toString()
    {
        return sprintf('(Enumerated)%s', $this->getInteger());
    }
}
