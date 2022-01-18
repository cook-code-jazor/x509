<?php


namespace Jazor\OCSP;


use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\NotImplementedException;
use Jazor\X509\X509Extensions;

class OCSPResponse implements \Jazor\ASN1\ASN1Encodable
{

    private int $responseStatus;

    /**
     * id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1
     * @var string|null
     */
    private ?string $responseType = null;
    private ?string $response = null;

    /**
     * @inheritDoc
     * @throws NotImplementedException
     */
    public function getEncoded()
    {
        throw new NotImplementedException();
    }

    public function __toString()
    {
        $result = sprintf("ResponseStatus = %s\r\n", $this->responseStatus . '(' . OCSPResponseStatus::$Status[$this->responseStatus] . ')');

        if($this->responseType != null){
            $result .= sprintf("ResponseType = %s\r\n", $this->responseType);
            $result .= sprintf("Response = 0x%s\r\n", limit_bin2hex($this->response));
        }

        return rtrim($result);
    }

    public static function getInstance(ASN1Sequence $seq){
        $instance = new static();
        $instance->responseStatus = $seq[0]->getInteger();

        if(!isset($seq[1])) return $instance;

        $seq2 = $seq[1][0];
        $instance->responseType = $seq2[0]->getValue();
        $instance->response = $seq2[1]->getContents();

        return $instance;
    }
}
