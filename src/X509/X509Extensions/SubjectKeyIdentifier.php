<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\Objects\ASN1OctetString;

class SubjectKeyIdentifier implements ASN1Encodable
{

    public string $keyIdentifier;

    public function __construct($keyIdentifier)
    {
        $this->keyIdentifier = $keyIdentifier;
    }


    public function getEncoded()
    {
        return (new ASN1OctetString($this->keyIdentifier))->getEncoded();
    }

    public function __toString()
    {
        return '0x' . bin2hex($this->keyIdentifier);
    }

    public static function getInstance($binary){
        $asn1 = ASN1Reader::read($binary);
        if(!($asn1 instanceof ASN1OctetString)) throw new \Exception('expect \'ASN1OctetString\'');

        return new static($asn1->getContents());
    }
}
