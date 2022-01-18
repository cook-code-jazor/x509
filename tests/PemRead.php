<?php


namespace Jazor\Tests;

use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\DerSequenceReader;
use Jazor\Console;
use Jazor\X509\PemReader;
use Jazor\X509\X509CertificateV3;

class PemRead
{
    /**
     * @param $file
     * @param bool $isContents
     * @throws \Exception
     */
    public static function handle($file, $isContents = false){

        $cert = $isContents ? $file : file_get_contents($file);
        /**
         * @var X509CertificateV3 $okCer
         * @var X509CertificateV3 $errorCer
         */
        $payload = PemReader::getPemContents($cert, $typeName);

        Console::WriteLine($typeName);

        Console::WriteLine(ASN1Reader::read($payload));

        $result = DerSequenceReader::fromPayload($payload);
        $result = $result->toArray();
        Console::WriteLine(json_encode($result, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    }
}
