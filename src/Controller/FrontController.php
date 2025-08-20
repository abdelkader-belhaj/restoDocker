<?php

namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class FrontController extends AbstractController
{
    #[Route('/front', name: 'app_front')]
    public function index(FirebaseService $firebase): Response
    {
        $menus = $firebase->getAllMenus();
        $types = ['Petit déjeuner', 'Déjeuner', 'Dîner', 'Collation', 'Brunch'];
        
        // Assurez-vous que chaque menu a un type défini
        foreach ($menus as &$menu) {
            if (!isset($menu['type'])) {
                $menu['type'] = '';
            }
        }

        return $this->render('front/front.html.twig', [
            'menus' => $menus,
            'types' => $types
        ]);
    }
}
