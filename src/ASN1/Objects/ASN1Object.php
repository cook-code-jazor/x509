<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\ASN1Encodable;

abstract class ASN1Object implements ASN1Encodable
{
    private int $tag = 0;
    public function __construct($tag)
    {
        $this->tag = $tag;
    }
    /**
     * @return int
     */
    public function getTag()
    {
        return $this->tag;
    }

    /**
     * 编码长度值，标志位81，82，83，84,大端编码
     * @param int $length 长度值
     * @return string
     */
    protected final function encodeLength(int $length){
        if($length < 0x80){
            return chr($length);
        }
        $idx = 0;
        $result = '';
        while ($length > 0){
            $result = chr($length & 0xff) . $result;
            $length >>= 8;
            $idx++;
        }
        return chr(0x80 | $idx) . $result;
    }

    public function encodeHeader(int $length){
        return chr($this->tag) . self::encodeLength($length);
    }

    public function encodeContents(string $contents){
        return $this->encodeHeader(strlen($contents)) . $contents;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded(){
        throw new \Exception('method \'getEncoded\' not implemented');
    }
}
