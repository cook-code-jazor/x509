<?php


namespace Jazor\X509\X509Extensions\CertificatePolicies;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1BMPString;
use Jazor\ASN1\Objects\ASN1IA5String;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\ASN1\Objects\ASN1UTF8String;

class NoticeReference implements ASN1Encodable
{

    private ASN1Encodable $organization;
    private array $noticeNumbers;

    public function __construct($organization, $noticeNumbers)
    {
        if(!($organization instanceof ASN1IA5String || $organization instanceof ASN1BMPString || $organization instanceof ASN1UTF8String)){
            throw new \Exception('expect \'ASN1IA5String\',\'ASN1BMPString\',\'ASN1UTF8String\',');
        }
        $this->organization = $organization;
        $this->noticeNumbers = $noticeNumbers;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Object($this->organization);
        $gen->Sequence(function (ASN1SequenceGenerator $gen){
            foreach ($this->noticeNumbers as $noticeNumber){
                $gen->Integer($noticeNumber);
            }
        });

        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){
        $organization = $seq[0];
        $noticeNumbers = [];
        foreach ($seq[1]->getElements() as $element){
            $noticeNumbers[] = $element->getContents();
        }
        return new static($organization, $noticeNumbers);
    }
}
