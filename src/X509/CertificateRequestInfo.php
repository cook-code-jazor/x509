<?php

namespace Jazor\X509;
use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Integer;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Security\AsymmetricKey;
use Jazor\Security\AsymmetricKeyFactory;
use Jazor\X509\X501Attributes\X501Attributes;


class CertificateRequestInfo implements ASN1Encodable
{

    private int $version = 0;

    private X509Name $subject;

    private AsymmetricKey $publicKey;
    private ?X501Attributes $attributes = null;

    public function getVersion()
    {
        return $this->version;
    }

    public function getSubject()
    {
        return $this->subject;
    }

    /**
     * @return X501Attributes
     */
    public function getAttributes()
    {
        return $this->attributes;
    }

    /**
     * @return AsymmetricKey
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * CertificateRequest constructor.
     * @param string|ASN1Sequence|null $contents
     * @throws \Exception
     */
    public function __construct($sequence)
    {
        if($sequence instanceof ASN1Sequence){
            $this->parse($sequence);
        }
    }
    /**
     * @param ASN1Sequence $sequence
     * @throws \Exception
     */
    private function parse(ASN1Sequence $sequence)
    {
        /**
         * @var ASN1Integer $sequence[0]
         */
        $this->version = $sequence[0]->getInteger();

        $this->subject = X509Name::getInstance($sequence[1]);


        $this->publicKey = AsymmetricKeyFactory::getPublicKey($sequence[2]);

        if(!isset($sequence[3])) return;

        $this->attributes = X501Attributes::getInstance($sequence[3]);

    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer($this->version);
        $gen->Object($this->subject);
        $gen->Object($this->publicKey);

        if(!empty($this->attributes)){
            $gen->Object($this->attributes);
        }


        return $gen->generate();
    }

    public function __toString(){
        return sprintf("Version = %s\r\nSubject = %s\r\nPublicKey\r\n%s\r\nAttributes\r\n%s",
            $this->version,
            $this->subject,
            indent($this->publicKey, 2),
            indent($this->attributes, 2),
        );
    }

    /**
     * @param ASN1Sequence $sequence
     * @return CertificateRequestInfo
     * @throws \Exception
     */
    public static function getInstance(ASN1Sequence $sequence){

        return new CertificateRequestInfo($sequence);
    }
}
