<?php


namespace Jazor\Tests;


use Jazor\Console;
use Jazor\X509\PemReader;
use Jazor\X509\X509CertificateV3;

class PemSingle
{
    /**
     * @param $file
     * @param bool $isContents
     * @throws \Jazor\NotSupportedException
     */
    public static function handle($file, $isContents = false)
    {
        $cert = $isContents ? $file : file_get_contents($file);
        /**
         * @var X509CertificateV3 $okCer
         * @var X509CertificateV3 $errorCer
         */
        $okCer = PemReader::importFromContents($cert);

        $newCer = PemReader::export($okCer);

        if(PemReader::getPemContents($newCer, $name) != PemReader::getPemContents($cert, $name)) {
            file_put_contents('./1-OK.cer', $cert);
            file_put_contents('./1-Error.cer', $newCer);
            Console::WriteLine('编码结果不一致！');
        }
        Console::WriteLine($okCer);
    }
}
