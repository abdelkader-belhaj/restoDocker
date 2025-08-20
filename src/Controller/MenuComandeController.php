<?php

namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

final class MenuComandeController extends AbstractController
{
    #[Route('/menu/commande', name: 'app_menu_commande')]
    public function index(FirebaseService $firebaseService): Response
    {
        $database = $firebaseService->getDatabase();
        $snapshot = $database->getReference('menus')->getSnapshot();
        $menus = $snapshot->getValue();

        $menusByType = [];
        $featuredItems = [];

        if ($menus) {
            foreach ($menus as $key => $menu) {
                if (isset($menu['type'])) {
                    $type = strtolower($menu['type']);
                    $menuWithSlug = array_merge($menu, [
                        'slug' => $key,
                        'image' => $menu['image'] ?? null
                    ]);
                    $menusByType[$type][] = $menuWithSlug;
                    
                    // Ajoutez les 3 premiers menus comme featured
                    if (count($featuredItems) < 3) {
                        $featuredItems[] = $menuWithSlug;
                    }
                }
            }
        }

        return $this->render('menu_comande/index.html.twig', [
            'menusByType' => $menusByType,
            'featuredItems' => $featuredItems
        ]);
    }
}