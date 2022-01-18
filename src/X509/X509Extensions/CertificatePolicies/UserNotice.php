<?php


namespace Jazor\X509\X509Extensions\CertificatePolicies;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1BMPString;
use Jazor\ASN1\Objects\ASN1IA5String;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\ASN1\Objects\ASN1UTF8String;
use Jazor\ASN1\Objects\ASN1VisibleString;
use Jazor\Console;

class UserNotice implements ASN1Encodable
{

    private ?NoticeReference $noticeRef;
    private ?string $explicitText;

    public function __construct($noticeRef, $explicitText)
    {
        $this->noticeRef = $noticeRef;
        $this->explicitText = $explicitText;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        if($this->noticeRef !== null) $gen->Object($this->noticeRef);

        if($this->explicitText !== null) $gen->BMPString($this->explicitText, 'utf-8');
        return $gen->generate();
    }

    public function __toString()
    {
        $result = "NoticeReference\r\n";
        if($this->noticeRef != null){
            $result .= indent($this->noticeRef, 2) . "\r\n";
        }
        if($this->explicitText != null){
            $result .= indent('ExplicitText = ' . $this->explicitText, 2) . "\r\n";
        }

        return rtrim($result);
    }

    public static function getInstance(ASN1Sequence $seq){
        $noticeRef = null;
        $explicitText = null;

        $elements = $seq->getElements();
        foreach ($elements as $element){
            if($element instanceof ASN1Sequence){
                $noticeRef = NoticeReference::getInstance($element);
            }else{
                $explicitText = $element->getContents();
            }
        }
        return new static($noticeRef, $explicitText);
    }
}
