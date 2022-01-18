<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\UnexpectedException;
use Jazor\X509\X509Extensions\CertificatePolicies\PolicyInformation;

class CertificatePolicies implements ASN1Encodable
{

    const DOMAIN_VALIDATED = '2.23.140.1.2.1';
    const ANY_POLICY = '2.5.29.32.0';

    private array $certificatePolicies;


    public function __construct(array $certificatePolicies)
    {
        $this->certificatePolicies = $certificatePolicies;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        foreach ($this->certificatePolicies as $certificatePolicy){
            $gen->Object($certificatePolicy);
        }
        return $gen->generate();
    }

    public function __toString()
    {
        $result = '';

        $idx = 0;
        foreach ($this->certificatePolicies as $certificatePolicy){
            $result .= 'PolicyInformation[' . $idx++ . "]\r\n";
            $result .= indent($certificatePolicy, 2) . "\r\n";
        }
        return rtrim($result);
    }

    public static function getInstance($binary){
        $seq = ASN1Reader::read($binary);
        if (!($seq instanceof ASN1Sequence)) throw new UnexpectedException('expect \'ASN1Sequence\'');

        $elements = $seq->getElements();

        $certificatePolicies = [];

        for ($i = 0; $i < count($elements); $i++) {
            $certificatePolicies[] = PolicyInformation::getInstance($elements[$i]);
        }
        return new static($certificatePolicies);
    }

    /**
     * @return string|null
     */
    public function getPolicy(): ?string
    {
        return $this->policy;
    }

    /**
     * @return array
     */
    public function getCertificatePolicies(): array
    {
        return $this->certificatePolicies;
    }
}
