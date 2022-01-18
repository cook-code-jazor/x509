<?php


namespace Jazor\Tests;


use Jazor\Console;
use Jazor\OCSP\OCSPClient;
use Jazor\X509\PemReader;

class OCSP
{

    public static function handle($file){

        $ocsp = new OCSPClient(PemReader::import($file, $name));
        $response = $ocsp->verify();

        Console::WriteLine($response);
    }
}
