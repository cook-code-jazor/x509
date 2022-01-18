<?php

namespace Jazor\ASN1\Objects;

use DateTime;
use Jazor\ASN1\DerTag;

abstract class ASN1DateTime extends ASN1String
{
    private DateTime $dateTime;

    /**
     * @param int $tag
     * @param DateTime|integer|string $contents
     * @param string $format
     */
    public function __construct(int $tag, $contents = '', string $format = 'ymdHis')
    {
        if($contents instanceof DateTime){
            $this->dateTime = $contents;
            $contents = $this->dateTime->format($format) . 'Z';
        }else if(is_string($contents)){
            $this->dateTime = DateTime::createFromFormat($format . 'Z', $contents);
        }
        else if(is_numeric($contents)){
            $this->dateTime = (new DateTime())->setTimestamp($contents);
            $contents = $this->dateTime->format($format) . 'Z';
        }
        parent::__construct($tag, $contents);
    }

    /**
     * @return DateTime|false
     */
    public function getDateTime()
    {
        return $this->dateTime;
    }
}
