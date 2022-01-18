<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1ObjectIdentifier extends ASN1Object
{
    private string $value;

    /**
     * ASN1ObjectIdentifier constructor.
     * @param string $oidString
     */
    public function __construct(string $oidString = '')
    {
        parent::__construct(DerTag::ObjectIdentifier);
        $this->value = $oidString;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    public function getEncoded(){
        $contents = self::encode($this->value);
        return $this->encodeContents($contents);
    }

    /**
     * OID字符串编码为二进制数据
     * @param string $oid 字符串形式的OID
     * @return string
     */
    public static function encode($oid){
        $parts = explode('.', $oid);
        $parts = array_map(function ($t) { return intval($t); }, $parts);
        $result = chr($parts[0] * 40 + $parts[1]);

        for ($i = 2; $i < count($parts); $i++){
            $value = $parts[$i];
            if($value <= 127){
                $result .= chr($value);
                continue;
            }
            $substr = '';
            $flag = false;
            while ($value > 0){
                $num7 = ($value & 0x7f);
                if($flag){
                    $num7 = 0x80 | $num7;
                }
                $substr = chr($num7) . $substr;
                $value >>= 7;
                if(!$flag) $flag = true;
            }
            $result .= $substr;
        }

        return $result;
    }
    /**
     * 二进制数据解码为OID字符串
     * @param string $data 二进制数据
     * @param int $position 数据偏移位置
     * @param int $count OID所占字节大小
     * @return string
     */
    public static function decode($data, $position, $count){

        $builder = '';
        $num2 = ord($data[$position]);
        $num3 = floor($num2 / 40);
        $num4 = $num2 % 40;
        $builder .= $num3;
        $builder .= '.';
        $builder .= $num4;

        $flag = true;
        $integer = 0;
        for ($i = 1; $i < $count; $i++)
        {
            $num6 = ord($data[$position + $i]);
            $num7 = $num6 & 0x7f;
            if ($flag)
            {
                $builder .= '.';
                $flag = false;
            }
            $integer = $integer << 7;
            $integer += $num7;
            if ($num6 == $num7)
            {
                $builder .= $integer;
                $integer = 0;
                $flag = true;
            }
        }
        return $builder;
    }

    public function __toString(){
        return '(ObjectIdentifier)'.$this->value;
    }
}
