<?php

namespace Jazor\X509\X509Extensions;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class AccessDescription implements ASN1Encodable
{

    const ID_AD_CA_ISSUERS = '1.3.6.1.5.5.7.48.2';
    const ID_AD_OCSP = '1.3.6.1.5.5.7.48.1';
    private string $accessMethod;
    private GeneralName $accessLocation;

    public function __construct($accessMethod, $accessLocation)
    {
        $this->accessMethod = $accessMethod;
        $this->accessLocation = $accessLocation;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->ObjectIdentifier($this->accessMethod);
        $gen->Object($this->accessLocation);
        return $gen->generate();
    }

    public function __toString()
    {
        return sprintf("AccessMethod=%s\r\nAccessLocation\r\n%s",
            ($this->accessMethod == self::ID_AD_OCSP ? 'OCSPClient' : 'CA_ISSUERS') . '(' . $this->accessMethod . ')',
            indent($this->accessLocation, 2));
    }

    public static function getInstance(ASN1Sequence $seq){
        $accessMethod = $seq[0]->getValue();
        $accessLocation = GeneralName::getInstance($seq[1]);
        return new static($accessMethod, $accessLocation);
    }


    /**
     * @return string
     */
    public function getAccessMethod(): string
    {
        return $this->accessMethod;
    }

    /**
     * @return GeneralName
     */
    public function getAccessLocation(): GeneralName
    {
        return $this->accessLocation;
    }
}
