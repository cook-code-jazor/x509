<?php


namespace Jazor\Tests;


use Jazor\Console;
use Jazor\X509\PemReader;
use Jazor\X509\X509CertificateV3;

class ScanCerts
{
    /**
     * @param $dir
     * @throws \Throwable
     */
    public static function handle($dir){

        $files = scandir($dir);
        $index = 0;
        foreach ($files as $file){
            if($file === '.' || $file === '..') continue;
            $index++;
            try {
                /**
                 * @var X509CertificateV3 $csr
                 */
                $cert = file_get_contents($dir . $file);
                $csr = PemReader::importFromContents($cert);

                $newCsr = PemReader::export($csr);

                if(PemReader::getPemContents($newCsr, $name) != PemReader::getPemContents($cert, $name)) {
                    file_put_contents('./1-OK.cer', $cert);
                    file_put_contents('./1-Error.cer', $newCsr);
                    Console::WriteLine($csr);
                    break;
                }

            }catch (\Throwable $ex){
                if(strpos($cert, '-----') !== false)$cert = substr($cert, strpos($cert, '-----'));
                file_put_contents('./1-Error.cer', $cert);
                throw $ex;
            }
        }
        Console::WriteLine("共%s条", $index);
    }
}
