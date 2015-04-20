<?php

/*
 * This file is part of the Indigo Guardian package.
 *
 * (c) Indigo Development Team
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Indigo\Guardian\Stack;

use Indigo\Guardian\SessionAuth;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Protect pages with authentication
 *
 * @author Márk Sági-Kazár <mark.sagikazar@gmail.com>
 */
class Authentication implements HttpKernelInterface
{
    /**
     * @var HttpKernelInterface
     */
    protected $app;

    /**
     * @var SessionAuth
     */
    protected $sessionAuth;

    /**
     * @var array
     */
    protected $options = [
        'delegateCaller' => false,
    ];

    /**
     * @param HttpKernelInterface $app
     * @param SessionAuth         $sessionAuth
     * @param array               $options
     */
    public function __construct(
        HttpKernelInterface $app,
        SessionAuth $sessionAuth,
        array $options = []
    ) {
        $this->app = $app;
        $this->sessionAuth = $sessionAuth;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        $route = $request->getPathInfo();

        // We have an active login
        if ($this->sessionAuth->check()) {

            switch ($route) {
                case '/login':
                    $returnUri = $request->query->get('uri', $request->attributes->get('stack.url_map.prefix', '/'));

                    return new RedirectResponse($returnUri);
                    break;
                case '/logout':
                    $this->sessionAuth->logout();

                    return new RedirectResponse($request->attributes->get('stack.url_map.prefix', '/'));
                    break;
                default:
                    $caller = $this->sessionAuth->getCurrentCaller();

                    $request->attributes->set('stack.authn.token', $caller->getLoginToken());

                    if ($this->options['delegateCaller']) {
                        $request->attributes->set('stack.authn.caller', $caller);
                    }

                    break;
            }
        } elseif($route !== '/login') {
            $routePrefix = $request->attributes->get('stack.url_map.prefix', '');
            $fullRoute = $request->server->get('PATH_INFO', '/');

            return new RedirectResponse(sprintf('%s/login?uri=%s', $routePrefix, $fullRoute));
        }

        return $this->app->handle($request, $type, $catch);
    }
}
