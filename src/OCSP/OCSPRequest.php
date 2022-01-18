<?php


namespace Jazor\OCSP;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Null;
use Jazor\Console;
use Jazor\Security\AsymmetricKey;
use Jazor\Security\HashIdentifier;
use Jazor\X509\X509Name;

class OCSPRequest implements ASN1Encodable
{

    private string $serialNumber;
    /**
     * @var X509Name
     */
    private X509Name $issuer;
    private string $issuerKeyIdentifier;

    public function __construct(string $serialNumber, X509Name $issuer, string $issuerKeyIdentifier)
    {

        $this->serialNumber = $serialNumber;
        $this->issuer = $issuer;
        $this->issuerKeyIdentifier = $issuerKeyIdentifier;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Sequence()->Sequence()->Sequence()->Sequence(function (ASN1SequenceGenerator $gen){

            $gen->Object(new HashIdentifier('1.3.14.3.2.26', new ASN1Null()));
            $gen->OctetString(hash('SHA1', $this->issuer->getEncoded(), true));
            $gen->OctetString($this->issuerKeyIdentifier);
            $gen->Integer($this->serialNumber);
        });

        return $gen->generate();
    }
}
