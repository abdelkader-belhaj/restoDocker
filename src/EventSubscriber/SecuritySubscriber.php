<?php
// src/EventSubscriber/SecuritySubscriber.php// src/EventSubscriber/SecuritySubscriber.php
namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\HttpFoundation\RequestStack;

class SecuritySubscriber implements EventSubscriberInterface
{
    private $router;
    private $requestStack;

    public function __construct(RouterInterface $router, RequestStack $requestStack)
    {
        $this->router = $router;
        $this->requestStack = $requestStack;
    }

    public function onKernelController(ControllerEvent $event)
    {
        $request = $this->requestStack->getCurrentRequest();
        $session = $request->getSession();
        $user = $session->get('user');
        
        $route = $request->attributes->get('_route');
        
        // Routes autorisées sans authentification (pages publiques)
        $publicRoutes = [
            'app_login', 
            'app_register', 
            'app_login_submit', 
            'app_register_submit',
            'app_logout',
            'front_index' // Ajout de front_index comme route publique
        ];
        
        // Routes pour les clients connectés
        $clientRoutes = [
            'app_menus_home'
        ];
        
        // Routes réservées aux admins
        $adminOnlyRoutes = [
            'app_dashboard'
        ];
        
        // Ignore les routes sans nom
        if (!$route) {
            return;
        }
        
        // Redirection si non connecté et tentant d'accéder à une page protégée
        if (!$user && !in_array($route, $publicRoutes)) {
            $event->setController(function() {
                return new RedirectResponse($this->router->generate('app_login'));
            });
            return;
        }
        
        // Redirection si connecté et tentant d'accéder au login/register
        if ($user && in_array($route, ['app_login', 'app_register'])) {
            $event->setController(function() use ($user) {
                return new RedirectResponse($this->router->generate(
                    $user['type'] === 'admin' ? 'app_dashboard' : 'front_index'
                ));
            });
            return;
        }
        
        // Vérification des permissions pour les routes admin
        if ($user && in_array($route, $adminOnlyRoutes)) {
            if ($user['type'] !== 'admin') {
                $event->setController(function() {
                    return new RedirectResponse($this->router->generate('front_index'));
                });
            }
        }
        
        // Vérification que les routes clients nécessitent une connexion
        if (!$user && in_array($route, $clientRoutes)) {
            $event->setController(function() {
                return new RedirectResponse($this->router->generate('app_login'));
            });
            return;
        }
        
        // Vérification que seuls les clients peuvent accéder aux routes client
        if ($user && in_array($route, $clientRoutes) && $user['type'] !== 'client') {
            $event->setController(function() use ($user) {
                return new RedirectResponse($this->router->generate(
                    $user['type'] === 'admin' ? 'app_dashboard' : 'front_index'
                ));
            });
        }
    }

    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::CONTROLLER => ['onKernelController', 10],
        ];
    }
}