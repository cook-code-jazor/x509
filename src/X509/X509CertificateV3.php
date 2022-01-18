<?php

namespace Jazor\X509;
use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1BitString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Security\HashIdentifier;

/**
 * Class X509CertificateV3
 * @link https://www.rfc-editor.org/rfc/inline-errata/rfc5280.html
 * @link https://www.rfc-editor.org/rfc/inline-errata/rfc6960.html#OCSP
 * @link https://www.rfc-editor.org/rfc/rfc2560.html#OCSP
 * @package Jazor\X509
 */
class X509CertificateV3 implements ASN1Encodable
{

    private TBSCertificate $certificateInfo;
    private HashIdentifier $signAlgorithm;
    private ?string $signature = '';

    /**
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return HashIdentifier
     */
    public function getSignAlgorithm(): HashIdentifier
    {
        return $this->signAlgorithm;
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
         * @var ASN1Sequence $cerInfo
         * @var ASN1Sequence $signAlgorithm
         * @var ASN1BitString $signature
         */
        $cerInfo = $sequence[0];
        $signAlgorithm = $sequence[1];
        $signature = $sequence[2];
        $data = $cerInfo->getInnerSequenceReader()->getOriginContent();

        $this->certificateInfo = TBSCertificate::getInstance($cerInfo);

        $this->signAlgorithm = HashIdentifier::getInstance($signAlgorithm);
        $this->signature = $signature->getContents();

        $publicKey = $this->certificateInfo->getPublicKey();

        //TODO
        //$result = SignatureHelper::verify($data, $this->signature, $publicKey, $this->signAlgorithm);
        //if(!$result){
        //    throw new \Exception('CER verify error');
        //}
    }

    public function __toString()
    {
        return sprintf("X509Certificate\r\n  %s\r\n  SignAlgorithm = %s\r\n  Signature = %s",
            ltrim(indent($this->certificateInfo, 2)),
            $this->signAlgorithm->getAlgorithm(),
            limit_bin2hex($this->signature)
        );
    }

    /**
     * @param ASN1Sequence $sequence
     * @return X509CertificateV3
     * @throws \Exception
     */
    public static function getInstance(ASN1Sequence $sequence){

        return new X509CertificateV3($sequence);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Object($this->certificateInfo);
        $gen->Object($this->signAlgorithm);
        $gen->BitString($this->signature);

        return $gen->generate();
    }

    /**
     * @return TBSCertificate
     */
    public function getCertificateInfo(): TBSCertificate
    {
        return $this->certificateInfo;
    }
}
