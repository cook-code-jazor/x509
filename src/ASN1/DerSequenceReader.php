<?php
namespace Jazor\ASN1;

use Jazor\ASN1\Objects\ASN1Context;
use Jazor\ASN1\Objects\ASN1ObjectIdentifier;
use Jazor\Console;

/**
 * code from .net
 */
class DerSequenceReader
{
    private static string $encoding_invalid = "Der_Invalid_Encoding";
    // Fields
    private string $data;
    private int $end;
    private int $position;
    private int $origin_position;
    private int $origin_length;

    /**
     * @return int
     */
    public function getOriginPosition(): int
    {
        return $this->origin_position;
    }

    /**
     * @return int
     */
    public function getOriginLength(): int
    {
        return $this->origin_length;
    }

    /**
     * 获取原始数据
     * @return false|string
     */
    public function getOriginContent()
    {
        return substr($this->data, $this->origin_position, $this->origin_length);
    }

    /**
     * 构造函数
     * @param string $data 数据
     * @param int $offset 偏移
     * @param int $length 长度
     * @param int $tagToEat 标签，可选择不预读标签
     * @throws \Exception
     */
    public function __construct(string $data, int $offset, int $length, int $tagToEat = Dertag::Sequence)
    {
      $this->init($tagToEat, $data, $offset, $length);
    }

    /**
     * 初始化
     * @param int $tagToEat 标签
     * @param string $data 数据
     * @param int $offset 偏移
     * @param int $length 长度
     * @throws \Exception
     */
    private function init(int $tagToEat, string $data, int $offset, int $length)
    {
        if ((($offset < 0) || ($length < 2)) || ($length > (strlen($data) - $offset))) throw new \Exception('Argument_Out_Of_Range');

        //记录下原始的偏移信息
        $this->origin_position = $offset;
        $this->origin_length = $length;

        $this->data = $data;
        $this->end = $offset + $length;
        $this->position = $offset;
        if($tagToEat === 0) return;

        $this->eatTag($tagToEat);
        $num = $this->eatLength();
        $this->end = $this->position + $num;
    }

    /**
     * @param int $expectedTag 标签
     * @param string $data 数据
     * @param int $position 位置
     * @throws \Exception
     */
    private static function checkTag(int $expectedTag, string $data, int $position)
    {
        if ($position >= strlen($data)) throw new \Exception('Argument_Out_Of_Range');

        $num = ord($data[$position]);
        $num2 = $num & 0x1f;
        if ($num2 == 0x1f) throw new DerEncodingInvalidException('Tag_Error');

        if (($num & 0x80) == 0)
        {
            $num3 = $expectedTag & (DerTag::BitString | DerTag::GeneralizedTime | DerTag::OctetString);
            if ($num3 != $num2) throw new DerEncodingInvalidException('Tag_Mismatch');
        }
    }

    /**
     * 获取长度数据，并移动偏移
     * @return int
     * @throws \Exception
     */
    private function eatLength()
    {
        $num2 = self::scanContentLength($this->data, $this->position, $this->end, $num);
        $this->position += $num;
        return $num2;
    }

    /**
     * @param string $data 数据
     * @param int $offset 偏移
     * @param int $end 长度
     * @param int $bytesConsumed 长度消费的字节数（实际尚未消费）
     * @return int
     * @throws \Exception
     */
    private static function scanContentLength(string $data, int $offset, int $end, &$bytesConsumed)
    {
        if ($offset >= $end) throw new \Exception('Argument_Out_Of_Range');

        $num = ord($data[$offset]);
        if ($num < 0x80)
        {
            $bytesConsumed = 1;
            if ($num > (($end - $offset) - $bytesConsumed)) throw new DerEncodingInvalidException('Content_Length_Out_Of_Range');

            return $num;
        }
        $num2 = $num & 0x7f;
        if ($num2 > 4 || $num2 == 0) throw new DerEncodingInvalidException('Content_Length_Mask_Error');

        $bytesConsumed = 1 + $num2;
        if ($bytesConsumed > ($end - $offset)) throw new DerEncodingInvalidException('Content_Length_Out_Of_Range');

        $num3 = $offset + $bytesConsumed;
        $num4 = 0;
        for ($i = $offset + 1; $i < $num3; $i++)
        {
            $num4 = $num4 << 8;
            $num4 |= ord($data[$i]);
        }
        if ($num4 < 0 || $num4 > (($end - $offset) - $bytesConsumed)) throw new DerEncodingInvalidException('Content_Length_Out_Of_Range');

        return $num4;
    }

    /**
     * @param int $expected 标签
     * @throws \Exception
     */
    private function eatTag(int $expected)
    {
        if (!$this->hasData()) throw new \Exception(self::$encoding_invalid);

        self::checkTag($expected, $this->data, $this->position);
        $this->position++;
    }

    /**
     * @param int $expectedTag 标签
     * @return bool
     */
    public function hasTag(int $expectedTag) {
        return ($this->hasData() && (ord($this->data[$this->position]) == $expectedTag));
    }

    /**
     * @return int
     * @throws \Exception
     */
    public function peekTag()
    {
        if (!$this->hasData()) throw new DerEncodingInvalidException('At_End_Of_Data');

        $num = ord($this->data[$this->position]);
        if (($num & 0x1f) == 0x1f) throw new DerEncodingInvalidException('Tag_Error');

        return $num;
    }

    /**
     * 消费指定数量的数据并返回
     * @param int $count
     * @return false|string
     */
    private function eatContent(int $count){
        $data = substr($this->data, $this->position, $count);
        $this->position += $count;
        return $data;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readBitString(int &$padding)
    {
        $this->eatTag(DerTag::BitString);
        $count = $this->eatLength();
        if ($count < 1) throw new DerEncodingInvalidException(self::$encoding_invalid);

        $num2 = ord($this->data[$this->position]);
        if ($num2 > 7) throw new \Exception(self::$encoding_invalid);

        $padding = $num2;
        $count--;
        $this->position++;
        return $this->eatContent($count);
    }

    /**
     * @return bool
     * @throws \Exception
     */
    public function readBoolean()
    {
        $this->eatTag(DerTag::Boolean);
        $num = $this->eatLength();
        if ($num != 1) throw new \Exception(self::$encoding_invalid);

        $flag = ord($this->data[$this->position]) > 0;
        $this->position++;
        return $flag;
    }

    /**
     * @param int $tag
     * @return DerSequenceReader mixed
     * @throws \Exception
     */
    public function readCollectionWithTag(int $tag)
    {
        self::checkTag($tag, $this->data, $this->position);
        $num2 = self::scanContentLength($this->data, $this->position + 1, $this->end, $num);
        $length = (1 + $num) + $num2;
        $reader = new DerSequenceReader($this->data, $this->position, $length, $tag);
        $this->position += $length;
        return $reader;
    }

    /**
     * @return false|string
     * @throws \Exception
     */
    private function readContentAsBytes()
    {
        $count = $this->eatLength();
        return $this->eatContent($count);
    }

    /**
     * @param int $tag
     * @return string
     * @throws \Exception
     */
    public function readIntegerBytes($tag = DerTag::Integer)
    {
        $this->eatTag($tag);
        return $this->readContentAsBytes();
    }

    /**
     * 读取下一条数据，数据包含标签，长度和内容
     * @return false|string
     * @throws \Exception
     */
    public function readNextEncodedValue()
    {
        $this->peekTag();
        $num2 = self::scanContentLength($this->data, $this->position + 1, $this->end, $num);
        $count = (1 + $num) + $num2;
        return $this->eatContent($count);
    }

    /**
     * 读取小下一条数据，只包含内容
     * @return false|string
     * @throws \Exception
     */
    public function readNextContent()
    {
        $this->peekTag();
        $num2 = self::scanContentLength($this->data, $this->position + 1, $this->end, $num);
        $this->position += 1 + $num;
        return $this->eatContent($num2);
    }
    /**
     * @return string
     * @throws \Exception
     */
    public function readOctetString()
    {
        $this->eatTag(DerTag::OctetString);
        return $this->readContentAsBytes();
    }
    /**
     * @return string
     * @throws \Exception
     */
    public function readOidAsString()
    {
        $this->eatTag(DerTag::ObjectIdentifier);
        $num = $this->eatLength();
        if ($num < 1) throw new \Exception(self::$encoding_invalid);

        $oid = ASN1ObjectIdentifier::decode($this->data, $this->position, $num);

        $this->position += $num;
        return $oid;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readPrintableString()
    {
        return $this->readString(DerTag::PrintableString);
    }

    /**
     * @return DerSequenceReader
     * @throws \Exception
     */
    public function readSequence()
    {
        return $this->readCollectionWithTag(DerTag::Sequence);
    }

    /**
     * @return DerSequenceReader
     * @throws \Exception
     */
    public function readSet()
    {
        return $this->readCollectionWithTag(DerTag::Set);
    }

    /**
     * @param int $timeTag
     * @return false|string
     * @throws \Exception
     */
    private function readTime(int $timeTag)
    {
        $this->eatTag($timeTag);
        $count = $this->eatLength();
        return $this->eatContent($count);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readUtcTime()
    {
        return $this->readTime(DerTag::UTCTime);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readGeneralizedTime()
    {
        return $this->readTime(DerTag::GeneralizedTime);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readUtf8String()
    {
        return $this->readString(DerTag::UTF8String);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readT61String()
    {
        return $this->readString(DerTag::T61String);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readNumericString()
    {
        return $this->readString(DerTag::NumericString);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readBMPString()
    {
        return $this->readString(DerTag::BMPString);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readIA5String()
    {
        return $this->readString(DerTag::IA5String);
    }

    /**
     * @param int $tag
     * @return string
     * @throws \Exception
     */
    public function readString(int $tag)
    {
        $this->eatTag($tag);
        $count = $this->eatLength();
        $str = $this->eatContent($count);
        return self::trimTrailingNulls($str);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function ReadX509Date()
    {
        $tag = $this->peekTag();
        if ($tag == DerTag::UTCTime) return $this->readUtcTime();
        if ($tag == DerTag::GeneralizedTime) $this->readGeneralizedTime();

        throw new \Exception(self::$encoding_invalid);
    }


    /**
     * @param int $length
     * @return int
     */
    public function skip(int $length)
    {
        $position = $this->position;
        $this->position += $length;
        return $position;
    }


    /**
     * @throws \Exception
     */
    public function skipValue()
    {
        $this->eatTag($this->peekTag());
        $num = $this->eatLength();
        $this->position += $num;
    }

    /**
     * @param string $value
     * @return string
     */
    private static function trimTrailingNulls(string $value)
    {
        if($value == null || strlen($value) == 0) return $value;

        $length = strlen($value);
        while (($length > 0) && ($value[$length - 1] == '\0'))
        {
            $length--;
        }
        if ($length != strlen($value)) return substr($value, 0, $length);

        return $value;
    }

    /**
     * @return bool
     */
    public function hasData() {
        return $this->position < $this->end;
    }

    /**
     * @return array
     * @throws \Exception
     */
    public function toArray(){
        $dest = [];
        while($this->hasData()){

            $position = $this->position;
            $tag = $this->peekTag();
            $this->eatTag($tag);
            $length = $this->eatLength();
            $construct = ($tag & DerTag::ConstructedFlag) == DerTag::ConstructedFlag;
            $context = ($tag & DerTag::ContextSpecificTagFlag) == DerTag::ContextSpecificTagFlag;
            $item = [
                'tag' => $tag,
                'tagName' => DerTag::getName($tag),
                'position' => $position,
                'length' => $length
            ];
            $position = $this->position;
            if ($construct || $tag == DerTag::Sequence || $tag == DerTag::Set) {
                $this->skip($length);
                $item['children'] = (new DerSequenceReader($this->data, $position, $length, 0))->toArray();
                $dest[] = $item;
                continue;
            }

            $value = $this->getContentValue($tag, $length);
            if($value !== false) {
                $item['value'] = $tag === DerTag::Boolean ? $value > 0 : $value;
            }
            $dest[] = $item;
        }
        return $dest;
    }

    private function getContentValue($tag, $length){
        switch ($tag){
            case DerTag::BMPString:
                $content = $this->eatContent($length);
                return iconv('UCS-2BE', 'utf-8', $content);
            case DerTag::ObjectIdentifier:
                $content = $this->eatContent($length);
                return ASN1ObjectIdentifier::decode($content, 0, strlen($content));
            case DerTag::NumericString:
            case DerTag::PrintableString:
            case DerTag::IA5String:
            case DerTag::T61String:
            case DerTag::UTF8String:
            case DerTag::GeneralString:
            case DerTag::VisibleString:
            case DerTag::UTCTime:
            case DerTag::GeneralizedTime:
                return $this->eatContent($length);
            case DerTag::Boolean:
                $content = $this->eatContent($length);
                return ord($content[0]);
            default:
                $this->skip($length);
                return false;
        }
    }

    /**
     * @param string $payload 数据
     * @param int $tagToEat 标签
     * @return DerSequenceReader
     * @throws \Exception
     */
    public static function fromPayload(string $payload, int $tagToEat = 0){
        return new DerSequenceReader($payload, 0, strlen($payload), $tagToEat);
    }
}
