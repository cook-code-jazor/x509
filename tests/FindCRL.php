<?php


namespace Jazor\Tests;


use Jazor\CACerts;
use Jazor\Console;
use Jazor\X509\PemReader;
use Jazor\X509\X509CertificateV3;
use Jazor\X509\X509Extension;
use Jazor\X509\X509Extensions\CrlDistributionPoints;

class FindCRL
{
    public static function handle()
    {

        $certs = CACerts::getDefault();

        $count = 0;
        foreach ($certs as $certInfo) {
            $cert = $certInfo[1];
            try {
                /**
                 * @var X509CertificateV3 $csr
                 */
                $csr = PemReader::importFromContents($cert);

                /**
                 * @var X509Extension $extension
                 * @var CrlDistributionPoints $crlDistributionPoints
                 */
                $extension = $csr->getCertificateInfo()->getExtensions()->getExtension(X509Extension::CrlDistributionPoints);
                if ($extension != null) {
                    $crlDistributionPoints = $extension->getContents();
                    $points = $crlDistributionPoints->getDistributionPoints();
                    /**
                     * @var CrlDistributionPoints\DistributionPoint $point
                     */
                    foreach ($points as $point) {
                        $reason = $point->getReasons();
                        if ($reason != null) {
                            Console::WriteLine($reason);
                        }
                    }
                }


            } catch (\Throwable $ex) {
                file_put_contents('./1-Error.cer', $cert);
                throw $ex;
            }
            $count++;
        }
        Console::WriteLine("%s => %s", $count, count($certs));
    }
}
