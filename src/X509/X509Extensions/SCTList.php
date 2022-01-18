<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\Objects\ASN1OctetString;
use Jazor\Console;
use Jazor\TLS\DigitallySigned;
use Jazor\TLS\SignedCertificateTimestamp;
use Jazor\TLS\TLSReader;
use Jazor\UnexpectedException;

class SCTList implements ASN1Encodable
{

    private array $signedCertificateTimestampList;

    public function __construct($signedCertificateTimestampList)
    {
        $this->signedCertificateTimestampList = $signedCertificateTimestampList;
    }

    /**
     * @inheritDoc
     */
    public function getEncoded()
    {
        $result = '';
        /**
         * @var SignedCertificateTimestamp $timestamp
         */
        foreach ($this->signedCertificateTimestampList as $timestamp){
            $result .= $timestamp->getEncoded();
        }

        $len = strlen($result);

        $lenBytes = chr($len >> 8) . chr($len & 0xff);

        return (new ASN1OctetString($lenBytes . $result))->getEncoded();
    }

    public function __toString()
    {
        $result = '';
        /**
         * @var SignedCertificateTimestamp $timestamp
         */
        $idx = 0;
        foreach ($this->signedCertificateTimestampList as $timestamp){
            $result .= 'SignedCertificateTimestamp[' . ($idx++) . "]\r\n";
            $result .= indent($timestamp, 2) . "\r\n";
        }
        return rtrim($result);
    }

    /**
     * @param $binary
     * @return static
     * @throws UnexpectedException|\Exception
     */
    public static function getInstance($binary){
        $asn1 = ASN1Reader::read($binary);
        if(!($asn1 instanceof ASN1OctetString)) throw new UnexpectedException('expect \'ASN1OctetString\'');
        $data = $asn1->getContents();

        $tls = TLSReader::fromPayload($data);
        $tls = $tls->readVariable();

        $timestamps = [];

        while ($tls->hasData()){

            $timestamp = new SignedCertificateTimestamp();
            $version = $tls->readVariable();
            $timestamp->setVersion($version->readByte());
            $timestamp->setLogID($version->readBuffer(32));
            $timestamp->setTimestamp($version->readInt64());

            //ignore extensions
            $version->readVariable();

            $digitallySigned = new DigitallySigned();

            $digitallySigned->setHashAlgorithm($version->readByte());
            $digitallySigned->setSignatureAlgorithm($version->readByte());

            $digitallySignedData = $version->readVariable();
            $digitallySigned->setSignature($digitallySignedData->readBuffer(0));
            $timestamp->setDigitallySigned($digitallySigned);
            $timestamps[] = $timestamp;

        }

        return new static($timestamps);
    }
}
