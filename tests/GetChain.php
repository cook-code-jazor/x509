<?php


namespace Jazor\Tests;


use Jazor\Console;
use Jazor\Http\Request;
use Jazor\NotSupportedException;

class GetChain
{
    /**
     * @param $hostname
     * @throws NotSupportedException
     * @throws \Exception
     */
    public static function handle($hostname){
        $response = (new Request('https://acmev2.jazor.net/api/v2/ssl/chain?hostname=' . $hostname))->getResponse();
        $result = $response->getJson();
        if($result['status_code'] != 200){
            Console::WriteLine($result['message']);
            return;
        }
        $certs = $result['response'];
        if(count($certs) == 0) {
            Console::WriteLine('没有找到任何证书');
            return;
        }
        PemSingle::handle($certs[0]['Certificate'], true);
    }
}
