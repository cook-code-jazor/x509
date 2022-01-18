<?php


namespace Jazor\X509\X509Extensions\CrlDistributionPoints;


use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\DerTag;
use Jazor\ASN1\Objects\ASN1ConstructedContext;
use Jazor\ASN1\Objects\ASN1Context;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\X509\X509Extensions\GeneralNames;

class DistributionPointName implements \Jazor\ASN1\ASN1Encodable
{

    private ?GeneralNames $fullName = null;
    private ?GeneralNames $nameRelativeToCRLIssuer = null;


    public function __toString()
    {
        $result = '';

        if($this->fullName != null){
            $result .= "FullName\r\n";
            $result .= indent($this->fullName, 2) . "\r\n";
        }
        if($this->nameRelativeToCRLIssuer != null){
            $result .= "NameRelativeToCRLIssuer\r\n";
            $result .= indent($this->nameRelativeToCRLIssuer, 2) . "\r\n";
        }

        return rtrim($result);
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        $flag = 0;
        if($this->fullName != null){
            $data = $this->fullName->getEncoded();
            $data[0] = chr(DerTag::ContextSpecificTagFlag | DerTag::ConstructedFlag | $flag);
            $gen->Raw($data);
            $flag++;
        }
        if($this->nameRelativeToCRLIssuer != null){
            $data = $this->nameRelativeToCRLIssuer->getEncoded();
            $data[0] = chr(DerTag::ContextSpecificTagFlag | DerTag::ConstructedFlag | $flag);
            $gen->Raw($data);
            $flag++;
        }

        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $context){
        $instance = new static();
        if(isset($context[0])){
            $instance->fullName = GeneralNames::getInstance($context[0]);
        }
        if(isset($context[1])){
            $instance->nameRelativeToCRLIssuer = GeneralNames::getInstance($context[2]);
        }
        return $instance;
    }
}
