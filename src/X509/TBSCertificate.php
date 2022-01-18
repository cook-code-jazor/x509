<?php

namespace Jazor\X509;
use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\DerTag;
use Jazor\ASN1\Objects\ASN1DateTime;
use Jazor\ASN1\Objects\ASN1Integer;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\NotImplementedException;
use Jazor\NotSupportedException;
use Jazor\Security\AsymmetricKey;
use Jazor\Security\AsymmetricKeyFactory;
use Jazor\Security\HashIdentifier;


class TBSCertificate implements ASN1Encodable
{

    private int $version = 0;
    private ?string $id = null;

    private HashIdentifier $alg;
    private X509Name $issuer;
    private ASN1DateTime $notBefore;
    private ASN1DateTime $notAfter;
    private X509Name $subject;
    private AsymmetricKey $publicKey;
    private ?X509Extensions $extensions = null;
    private ?ASN1Encodable $issuerUniqueID = null;
    private ?ASN1Encodable $subjectUniqueID = null;

    public function getVersion()
    {
        return $this->version;
    }

    public function getSubject()
    {
        return $this->subject;
    }

    /**
     * @return AsymmetricKey
     */
    public function getPublicKey() : AsymmetricKey
    {
        return $this->publicKey;
    }

    /**
     * CertificateRequest constructor.
     * @param $sequence
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

        /**
         * V1
         */
        $index = 0;
        if($sequence[0] instanceof ASN1Integer){
            $this->version = 0;
        }else{
            $this->version = $sequence[$index++][0]->getInteger();
        }
        $this->id = $sequence[$index++]->getContents();
        $this->alg = HashIdentifier::getInstance($sequence[$index++]);

        $this->issuer = X509Name::getInstance($sequence[$index++]);

        $this->notBefore = $sequence[$index][0];
        $this->notAfter = $sequence[$index][1];
        $index++;
        $this->subject = X509Name::getInstance($sequence[$index++]);



        $this->publicKey = AsymmetricKeyFactory::getPublicKey($sequence[$index++]);

        while (isset($sequence[$index])){
            $seq = $sequence[$index];

            $tag = $seq->getTag();
            switch ($tag){
                case DerTag::ContextSpecificConstructedTag1:
                    $this->issuerUniqueID = $seq[0];
                    break;
                case DerTag::ContextSpecificConstructedTag2:
                    $this->subjectUniqueID = $seq[0];
                    break;
                case DerTag::ContextSpecificConstructedTag3:
                    $this->extensions = X509Extensions::getInstance($seq[0]);
                    break;
            }
            $index++;
        }

    }

    public function getEncoded()
    {
        if($this->version == 0 && $this->extensions != null){
            throw new NotSupportedException('extensions are not supported in v1');
        }
        $gen = ASN1SequenceGenerator::create();
        if($this->version > 0) {
            $gen->ConstructedContext(0)->Integer($this->version);
        }
        $gen->Integer($this->id);
        $gen->Object($this->alg);
        $gen->Object($this->issuer);
        $gen->Sequence(function (ASN1SequenceGenerator $gen){
            $gen->Object($this->notBefore);
            $gen->Object($this->notAfter);
        });
        $gen->Object($this->subject);
        $gen->Object($this->publicKey);
        if($this->issuerUniqueID!= null){
            $gen->ConstructedContext(1)->Object($this->issuerUniqueID);
        }
        if($this->subjectUniqueID!= null){
            $gen->ConstructedContext(2)->Object($this->subjectUniqueID);
        }
        if($this->extensions != null) {
            $gen->ConstructedContext(3)->Object($this->extensions);
        }

        return $gen->generate();
    }

    public function __toString(){
        return sprintf("TBSCertificate\r\n  Version = %s\r\n  Id = %s\r\n  HashAlgorithm\r\n%s\r\n  Issuer\r\n%s\r\n  NotBefore = %s\r\n  NotAfter = %s\r\n  Subject\r\n%s\r\n  PublicKey\r\n%s\r\n  Extensions\r\n%s",
            $this->version,
            '0x' . limit_bin2hex($this->id),
            indent($this->alg, 4),
            indent($this->issuer, 4),
            $this->notBefore->getDateTime()->format('Y-m-d H:i:s'),
            $this->notAfter->getDateTime()->format('Y-m-d H:i:s'),
            indent($this->subject, 4),
            indent($this->publicKey, 4),
            $this->extensions ? indent($this->extensions, 4) : '',
        );
    }

    /**
     * @param ASN1Sequence $sequence
     * @return TBSCertificate
     * @throws \Exception
     */
    public static function getInstance(ASN1Sequence $sequence){

        return new TBSCertificate($sequence);
    }

    /**
     * @return X509Extensions|null
     */
    public function getExtensions(): ?X509Extensions
    {
        return $this->extensions;
    }

    /**
     * @return ASN1Encodable|null
     */
    public function getIssuerUniqueID(): ?ASN1Encodable
    {
        return $this->issuerUniqueID;
    }

    /**
     * @return ASN1Encodable|null
     */
    public function getSubjectUniqueID(): ?ASN1Encodable
    {
        return $this->subjectUniqueID;
    }

    /**
     * @return string|null
     */
    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * @return X509Name
     */
    public function getIssuer(): X509Name
    {
        return $this->issuer;
    }

    /**
     * @return ASN1DateTime
     */
    public function getNotBefore(): ASN1DateTime
    {
        return $this->notBefore;
    }

    /**
     * @return ASN1DateTime
     */
    public function getNotAfter(): ASN1DateTime
    {
        return $this->notAfter;
    }

    /**
     * @return HashIdentifier
     */
    public function getAlg(): HashIdentifier
    {
        return $this->alg;
    }
}
