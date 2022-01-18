<?php


namespace Jazor\X509\X509Extensions\CertificatePolicies;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class PolicyInformation implements ASN1Encodable
{

    private string $policyIdentifier;
    private array $policyQualifiers;

    public function __construct(string $policyIdentifier, array $policyQualifiers)
    {
        $this->policyIdentifier = $policyIdentifier;
        $this->policyQualifiers = $policyQualifiers;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {

        $gen = ASN1SequenceGenerator::create();
        $gen->ObjectIdentifier($this->policyIdentifier);

        if(count($this->policyQualifiers) == 0)
            return $gen->generate();

        $gen->Sequence(function (ASN1SequenceGenerator $gen){
            foreach ($this->policyQualifiers as $qualifier){
                $gen->Object($qualifier);
            }
        });

        return $gen->generate();
    }

    public function __toString()
    {
        $result = sprintf("PolicyIdentifier=%s\r\n", $this->policyIdentifier);

        $idx = 0;
        foreach ($this->policyQualifiers as $qualifier){
            $result .= 'PolicyQualifierInfo[' . $idx++ . "]\r\n";
            $result .= indent($qualifier, 2) . "\r\n";
        }

        return rtrim($result);
    }

    public static function getInstance(ASN1Sequence $seq){
        $policyIdentifier = $seq[0]->getValue();
        $policyQualifiers = [];

        if(isset($seq[1])) {
            $elements = $seq[1]->getElements();

            for ($i = 0; $i < count($elements); $i++) {
                $policyQualifiers[] = PolicyQualifierInfo::getInstance($elements[$i]);
            }
        }
        return new static($policyIdentifier, $policyQualifiers);
    }

    /**
     * @return mixed
     */
    public function getPolicyIdentifier()
    {
        return $this->policyIdentifier;
    }

    /**
     * @return mixed
     */
    public function getPolicyQualifiers()
    {
        return $this->policyQualifiers;
    }
}
