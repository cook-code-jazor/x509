<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\DerTag;
use Jazor\ASN1\Objects\ASN1OctetString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\X509\TBSCertificate;
use Jazor\X509\X509Name;

/**
 * Class AuthorityKeyIdentifier
 * TODO rfc details
 * @package Jazor\X509\X509Extensions
 */
class AuthorityKeyIdentifier implements ASN1Encodable
{
    private string $keyIdentifier;
    private ?GeneralNames $caSubject = null;
    private ?string $caId = null;

    public function __construct($keyIdentifier, ?GeneralNames $caSubject, ?string $caId)
    {
        $this->keyIdentifier = $keyIdentifier;
        $this->caSubject = $caSubject;
        $this->caId = $caId;
    }


    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Context(0, $this->keyIdentifier);
        if($this->caSubject != null){
            $bytes = $this->caSubject->getEncoded();
            $bytes[0] = chr(DerTag::ContextSpecificTagFlag | DerTag::ConstructedFlag | 0x01);
            $gen->Raw($bytes);
            if($this->caId != null){
                $gen->Context(2, $this->caId);
            }
        }

        return $gen->generate();
    }

    public function __toString()
    {
        $result = sprintf("KeyId = 0x%s", bin2hex($this->keyIdentifier));
        if($this->caSubject!=null){
            $result = $result . "\r\nCaSubject\r\n" . indent($this->caSubject, 2);
        }
        if($this->caId!=null){
            $result = $result . "\r\nCaId = 0x" . bin2hex($this->caId);
        }
        return $result;
    }

    public static function getInstance($binary){
        $asn1 = ASN1Reader::read($binary);
        if(!($asn1 instanceof ASN1Sequence)) throw new \Exception('expect \'ASN1Sequence\'');

        return new static(
            $asn1[0]->getContents(),
            isset($asn1[1]) ? GeneralNames::getInstance($asn1[1]) : null,
            isset($asn1[2]) ? $asn1[2]->getContents() : null
        );
    }

    /**
     * @return string
     */
    public function getKeyIdentifier(): string
    {
        return $this->keyIdentifier;
    }
}
