<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;
use Jazor\Console;

class ASN1Integer extends ASN1String
{
    /**
     * ASN1Integer constructor.
     * @param string|int $value
     */
    public function __construct($value)
    {
        if(is_int($value)){
            $newValue = '';
            while ($value > 0xff){
                $newValue = chr($value & 0xff) . $newValue;
                $value >>= 8;
            }
            if(($value & 0x80) > 0){
                $value = "\x00" . chr($value) . $newValue;
            }else{
                $value = chr($value) . $newValue;
            }
        }
        parent::__construct(DerTag::Integer, $value);
    }
    /**
     * @return int
     */
    public function getInteger()
    {
        $data = $this->getContents();
        $length = strlen($data);
        if($length === 0) return 0;

        $maxNum = 4;
        if ($length < $maxNum) $maxNum = $length;

        $num = 0;
        for ($i = $length - $maxNum; $i < $length; $i++) {
            $num = $num << 8;
            $num |= ord($data[$i]);
        }
        return $num;
    }

    public function __toString()
    {
        $hex = bin2hex($this->getContents());
        if(strlen($hex) <= 8){
            return sprintf('(Integer)0x%s(%s)', $hex, $this->getInteger());
        }
        if (strlen($hex) > 64) {
            $hex = substr($hex, 0, 64) . ' ...more data(' . (strlen($hex) - 64) . ') skipped';
        }
        return sprintf('(Integer)0x%s', $hex);
    }
}
