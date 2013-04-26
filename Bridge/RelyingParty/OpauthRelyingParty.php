<?php
namespace Fp\OpenIdBundle\Bridge\RelyingParty;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Fp\OpenIdBundle\RelyingParty\AbstractRelyingParty;
use Fp\OpenIdBundle\RelyingParty\IdentityProviderResponse;
use Fp\OpenIdBundle\RelyingParty\Exception\OpenIdAuthenticationCanceledException;
use Fp\OpenIdBundle\RelyingParty\Exception\OpenIdAuthenticationValidationFailedException;

class OpauthRelyingParty extends AbstractRelyingParty
{
    private $strategyDir;

    /**
     * @param string $strategy_dir
     */
    protected function __construct($strategyDir)
    {
        $this->strategyDir = $strategyDir;
    }

    /**
     * {@inheritdoc}
     */
    protected function verify(Request $request)
    {
        $opauth = $this->createOpauth($request);

        $opauth->identity = $this->guessIdentifier($request);
        $opauth->returnUrl = $this->guessReturnUrl($request);
        $opauth->required = $this->guessRequiredAttributes($request);
        $opauth->optional = $this->guessOptionalAttributes($request);

        return new RedirectResponse($opauth->authUrl());
    }

    /**
     * {@inheritdoc}
     */
    protected function complete(Request $request)
    {
        $opauth = $this->createOpauth($request);

        if (false == $opauth->validate()) {
            if($opauth->mode == 'cancel') {
              throw new OpenIdAuthenticationCanceledException('Authentication was canceled by the user on a provider side');
            }

            throw new OpenIdAuthenticationValidationFailedException(sprintf(
               "Validation of response parameters failed for request: \n\n%s",
               $request
            ));
        }

        return new IdentityProviderResponse($opauth->identity, $opauth->getAttributes());
    }

    /**
     * @param string $request
     *
     * @return \Opauth
     */
    protected function createOpauth($request)
    {
        $config = array(
            'host' => $request->getScheme() . "://" . getHttpHost(),
            'request_uri' => $request->getUri()
        );

        // FIXME Merge configuration from symfony-style config files here
        // In particular

        return new \Opauth($config, false);
    }
}
