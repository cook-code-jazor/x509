<?php


namespace Jazor\X509\X509Extensions\CrlDistributionPoints;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\DerTag;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\X509\X509Extensions\GeneralNames;

class DistributionPoint implements ASN1Encodable
{

    private ?DistributionPointName $distributionPoint = null;
    private ?ASN1Encodable $reasons = null;
    private ?GeneralNames $cRLIssuer = null;


    public function __toString()
    {
        $result = '';

        if($this->distributionPoint != null) {
            $result .= "DistributionPointName\r\n";
            $result .= indent($this->distributionPoint, 2) . "\r\n";
        }
        if($this->reasons != null) {
            $result .= "Reasons\r\n";
            $result .= indent(bin2hex($this->reasons->getEncoded()), 2) . "\r\n";
        }
        if($this->cRLIssuer != null) {
            $result .= "CRLIssuer\r\n";
            $result .= indent($this->cRLIssuer, 2) . "\r\n";
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
        if($this->distributionPoint != null){
            $data = $this->distributionPoint->getEncoded();
            $data[0] = chr(DerTag::ContextSpecificTagFlag | DerTag::ConstructedFlag | $flag);
            $gen->Raw($data);
            $flag++;
        }
        if($this->reasons != null){
            $gen->ConstructedContext($flag, function (ASN1SequenceGenerator $gen){
                $gen->Object($this->reasons);
            });
            $flag++;
        }
        if($this->cRLIssuer != null){
            $data = $this->cRLIssuer->getEncoded();
            $data[0] = chr(DerTag::ContextSpecificTagFlag | DerTag::ConstructedFlag | $flag);
            $gen->Raw($data);
            $flag++;
        }

        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){
        $distributionPoint = new static();
        if(isset($seq[0])){
            $distributionPoint->distributionPoint = DistributionPointName::getInstance($seq[0]);
        }
        if(isset($seq[1])){
            $distributionPoint->reasons = $seq[1][0];
        }
        if(isset($seq[2])){
            $distributionPoint->cRLIssuer = GeneralNames::getInstance($seq[2]);
        }
        return $distributionPoint;
    }

    /**
     * @return ASN1Encodable|null
     */
    public function getReasons(): ?ASN1Encodable
    {
        return $this->reasons;
    }

    /**
     * @return DistributionPointName|null
     */
    public function getDistributionPoint(): ?DistributionPointName
    {
        return $this->distributionPoint;
    }

    /**
     * @return GeneralNames|null
     */
    public function getCRLIssuer(): ?GeneralNames
    {
        return $this->cRLIssuer;
    }
}
