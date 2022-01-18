<?php

namespace Jazor\X509;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

/**
 * Class X509Extensions
 * @link https://www.rfc-editor.org/rfc/inline-errata/rfc5280.html
 * @package Jazor\X509
 */
class X509Extensions implements ASN1Encodable
{
    private array $extensions;

    public function __construct(array $extensions)
    {
        $this->extensions = $extensions;
    }

    public function __toString()
    {
        $result = '';
        $idx = 0;
        foreach ($this->extensions as $extension){
            $result .= '[' . $idx++ . ']' . $extension . "\r\n";
        }
        return rtrim($result);
    }

    /**
     * @param $oid
     * @return X509Extension|null
     */
    public function getExtension($oid){

        /**
         * @var X509Extension $extension
         */
        foreach ($this->extensions as $extension){
            if($extension->getOid() == $oid) return $extension;
        }
        return null;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        foreach ($this->extensions as $extension){
            $gen->Object($extension);
        }
        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){

        $extensions = [];
        foreach ($seq->getElements() as $element){
            $extensions[] = X509Extension::getInstance($element);
        }
        return new static($extensions);
    }
}
