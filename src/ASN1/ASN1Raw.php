<?php


namespace Jazor\ASN1;


class ASN1Raw implements ASN1Encodable
{

    private string $contents;

    public function __construct(string $contents)
    {
        $this->contents = $contents;
    }

    public function getEncoded()
    {
        return $this->contents;
    }
}
