<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\DerSequenceReader;
use Jazor\ASN1\DerTag;

class ASN1Sequence extends ASN1Object implements \ArrayAccess
{
    private array $elements = [];
    private $innerSequenceReader;

    /**
     * @param int $tag
     * @param null $innerSequenceReader
     */
    public function __construct($tag = DerTag::ConstructedSequence, $innerSequenceReader = null)
    {
        parent::__construct($tag);
        $this->innerSequenceReader = $innerSequenceReader;
    }

    /**
     * @param ASN1Encodable $element
     */
    public function addElement(ASN1Encodable $element)
    {
        $this->elements[] = $element;
    }

    /**
     * @param array $elements
     */
    public function addElements(array $elements)
    {
        foreach ($elements as $ele)
            $this->elements[] = $ele;
    }

    /**
     * @param int $tag
     * @return string
     */
    public static function getASN1SequenceName(int $tag)
    {
        switch ($tag) {
            case DerTag::Sequence:
            case DerTag::ConstructedSequence:
                return 'Sequence';
            case DerTag::Set:
            case DerTag::ConstructedSet:
                return 'Set';

            default:
                if (($tag & DerTag::ContextSpecificTagFlag) == DerTag::ContextSpecificTagFlag) {
                    $flag = $tag & 0x1f;
                    return 'Context[' . $flag . ']';
                }
        }
        return 'UnknownSequence';
    }

    /**
     * @return array
     */
    public function getElements(): array
    {
        return $this->elements;
    }

    /**
     * @return DerSequenceReader|mixed|null
     */
    public function getInnerSequenceReader()
    {
        return $this->innerSequenceReader;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $contents = '';
        foreach ($this->elements as $value) {
            /**
             * @var ASN1Encodable $value
             */
            $contents .= $value->getEncoded();
        }

        return $this->encodeContents($contents);
    }

    public function getElementCount(){
        return count($this->elements);
    }

    /**
     * @param string|array $className
     * @return array
     */
    public function getInstance($className){
        return call_user_func($className . '::getInstance', $this);
    }

    /**
     * @param string|array $className
     * @return array
     */
    public function getChildren($className){
        $instances = [];
        if(is_array($className)){

            for ($i = 0; $i < count($className); $i++){
                if(!isset($this->elements[$i])){
                    break;
                }
                $instances[] = call_user_func($className[$i] . '::getInstance', $this->elements[$i]);
            }

            return $instances;
        }
        foreach ($this->elements as $element){
            $instances[] = call_user_func($className . '::getInstance', $element);
        }
        return $instances;
    }


    public function __toString()
    {
        $name = self::getASN1SequenceName($this->getTag());
        $result = "({$name})\r\n";
        foreach ($this->elements as $value) {
            $result .= indent($value, 2) . "\r\n";
        }
        return rtrim($result);
    }

    public function offsetExists($offset)
    {
        return isset($this->elements[$offset]);
    }

    /**
     * @param mixed $offset
     * @return ASN1Encodable|ASN1Sequence|ASN1Object
     */
    public function offsetGet($offset)
    {
        return $this->elements[$offset] ?? null;
    }

    public function offsetSet($offset, $value)
    {
        $this->elements[$offset] = $value;
    }

    public function offsetUnset($offset)
    {
        if (!isset($this->elements[$offset])) return;
        unset($this->elements[$offset]);
    }

}
