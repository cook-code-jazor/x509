<?php


namespace Jazor\X509\X509Extensions\CertificatePolicies;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1IA5String;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;

class PolicyQualifierInfo implements ASN1Encodable
{

    const idPkix = '1.3.6.1.5.5.7';
    const idQt = '1.3.6.1.5.5.7.2';
    const idQtCps = '1.3.6.1.5.5.7.2.1';
    const idQtUnotice = '1.3.6.1.5.5.7.2.2';

    private string $policyQualifierId;
    private ASN1Encodable $qualifier;

    public function __construct( string $policyQualifierId, $qualifier)
    {
        $this->policyQualifierId = $policyQualifierId;
        $this->qualifier = $qualifier;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        $gen->ObjectIdentifier($this->policyQualifierId);

        $gen->Object($this->qualifier);
        return $gen->generate();
    }

    private static function getIdName($oid){
        switch ($oid){
            case self::idQtCps:
                return 'CPS';
            case self::idQtUnotice:
                return 'UNOTICE';
        }
        return  '';
    }

    public function __toString()
    {
        $result = sprintf("PolicyQualifierId=%s\r\nQualifier\r\n", self::getIdName($this->policyQualifierId));
        $result .= indent($this->qualifier, 2);
        return $result;
    }

    public static function getInstance(ASN1Sequence $seq){
        $policyQualifierId = $seq[0]->getValue();
        $qualifier = null;
        $next = $seq[1];

        if($next instanceof ASN1IA5String){
            $qualifier = $next;
            return new static($policyQualifierId, $qualifier);
        }

        if(!($next instanceof ASN1Sequence)) throw new \Exception('expect \'ASN1Sequence\'');

        $qualifier = UserNotice::getInstance($next);

        return new static($policyQualifierId, $qualifier);

    }
}
