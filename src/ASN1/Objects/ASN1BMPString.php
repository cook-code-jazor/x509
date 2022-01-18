<?php

namespace Jazor\ASN1\Objects;

use Jazor\ASN1\DerTag;

class ASN1BMPString extends ASN1String
{
    public static string $DefaultContentsEncoding = 'utf-8';
    private string $contentsEncoding;

    /**
     * @param string $contents
     * @param string $contentsEncoding
     */
    public function __construct($contents = '', $contentsEncoding = '')
    {
        if(!empty($contentsEncoding)){
            $contents = iconv($contentsEncoding, 'UCS-2BE', $contents);
        }
        parent::__construct(DerTag::BMPString, $contents);
        $this->contentsEncoding = $contentsEncoding;
    }

    public function getContents(){
        return iconv('UCS-2BE', (empty($this->contentsEncoding) ? self::$DefaultContentsEncoding : $this->contentsEncoding), parent::getContents());
    }

    public function __toString(){
        return '(BMPString)' . $this->getContents();
    }
}
