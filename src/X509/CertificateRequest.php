<?php

namespace Jazor\X509;
use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1BitString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Security\HashIdentifier;
use Jazor\Security\SignatureHelper;

/**
 * Class CertificateRequest
 * <p>PKCS10</p>
 * @link https://datatracker.ietf.org/doc/html/rfc2986#page-5
 * @package Jazor\X509
 */
class CertificateRequest implements ASN1Encodable
{

    private CertificateRequestInfo $certificateRequestInfo;
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
         * @var ASN1Sequence $csrInfo
         * @var ASN1Sequence $signAlgorithm
         * @var ASN1BitString $signature
         */
        $csrInfo = $sequence[0];
        $signAlgorithm = $sequence[1];
        $signature = $sequence[2];
        $data = $csrInfo->getInnerSequenceReader()->getOriginContent();

        $this->certificateRequestInfo = CertificateRequestInfo::getInstance($csrInfo);

        $this->signAlgorithm = HashIdentifier::getInstance($signAlgorithm);
        $this->signature = $signature->getContents();

        $publicKey = $this->certificateRequestInfo->getPublicKey();

        $result = SignatureHelper::verify($data, $this->signature, $publicKey, $this->signAlgorithm);

        if(!$result){
            throw new \Exception('CSR verify error');
        }
    }

    public function __toString()
    {
        return sprintf("CertificateRequest\r\n  CertificateRequestInfo\r\n%s\r\n  SignAlgorithm = %s\r\n  Signature = %s",
            indent($this->certificateRequestInfo, 4),
            $this->signAlgorithm->getAlgorithm(),
            limit_bin2hex($this->signature)
        );
    }

    /**
     * @param ASN1Sequence $sequence
     * @return CertificateRequest
     * @throws \Exception
     */
    public static function getInstance(ASN1Sequence $sequence){

        return new CertificateRequest($sequence);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Object($this->certificateRequestInfo);
        $gen->Object($this->signAlgorithm);
        $gen->BitString($this->signature);

        return $gen->generate();
    }
}
