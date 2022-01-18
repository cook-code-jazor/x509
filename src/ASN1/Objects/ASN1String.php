<?php

namespace Jazor\ASN1\Objects;

/**
 *
 */
abstract class ASN1String extends ASN1Object
{
    private $contents;
    public function __construct($tag, $contents = null)
    {
        parent::__construct($tag);
        $this->contents = $contents;
    }

    /**
     * @return mixed|null|string
     */
    public function getContents()
    {
        return $this->contents;
    }
    public function getEncoded()
    {
        return parent::encodeContents($this->contents);
    }

    public function __toString(){
        $className = get_class($this);
        $idx = strrpos($className, '\\');
        if($idx >= 0){
            $className = substr($className, $idx + 1);
        }
        $hex = bin2hex($this->contents);
        if(strlen($hex) > 64){
            $hex = substr($hex, 0, 64 ) . ' ...more data(' . (strlen($hex) - 64) . ') skipped';
        }
        $className = str_replace('ASN1', '', $className);
        return "({$className})0x" . $hex;
    }
}
